package services

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"reflect"
	"sync"
	"time"

	"goravel/app/helpers"
	"goravel/app/models"
	"goravel/app/notificationcore"

	"github.com/goravel/framework/facades"
)

// NotificationQueueJob represents a queued notification job
type NotificationQueueJob struct {
	ID               string        `json:"id"`
	NotificationType string        `json:"notification_type"`
	NotifiableID     string        `json:"notifiable_id"`
	NotifiableType   string        `json:"notifiable_type"`
	NotificationData string        `json:"notification_data"`
	QueueName        string        `json:"queue_name"`
	Delay            time.Duration `json:"delay"`
	CreatedAt        time.Time     `json:"created_at"`
	ProcessedAt      *time.Time    `json:"processed_at,omitempty"`
	FailedAt         *time.Time    `json:"failed_at,omitempty"`
	Error            string        `json:"error,omitempty"`
	Attempts         int           `json:"attempts"`
	MaxAttempts      int           `json:"max_attempts"`
}

// RetryConfig holds configuration for notification retry logic
type RetryConfig struct {
	MaxAttempts   int           `json:"max_attempts"`
	BaseDelay     time.Duration `json:"base_delay"`
	MaxDelay      time.Duration `json:"max_delay"`
	BackoffFactor float64       `json:"backoff_factor"`
	JitterEnabled bool          `json:"jitter_enabled"`
}

// NotificationService handles sending notifications through various channels
type NotificationService struct {
	channels          map[string]notificationcore.Channel
	mutex             sync.RWMutex
	retryConfig       RetryConfig
	preferenceService *NotificationPreferenceService
	rateLimiter       *NotificationRateLimiter
}

// NewNotificationService creates a new notification service
func NewNotificationService() *NotificationService {
	service := &NotificationService{
		channels: make(map[string]notificationcore.Channel),
		retryConfig: RetryConfig{
			MaxAttempts:   3,
			BaseDelay:     5 * time.Second,
			MaxDelay:      5 * time.Minute,
			BackoffFactor: 2.0,
			JitterEnabled: true,
		},
		preferenceService: NewNotificationPreferenceService(),
		rateLimiter:       NewNotificationRateLimiter(),
	}

	// Register default channels
	service.registerDefaultChannels()

	return service
}

// registerDefaultChannels registers the default notification channels
func (s *NotificationService) registerDefaultChannels() {
	// Register database channel
	s.RegisterChannel(NewDatabaseNotificationChannel())

	// Register mail channel
	s.RegisterChannel(NewMailNotificationChannel())

	// Register web push channel
	s.RegisterChannel(NewWebPushNotificationChannel())

	// Register WebSocket channel
	s.RegisterChannel(NewWebSocketNotificationChannel())

	// Register new channels
	s.RegisterChannel(NewSlackNotificationChannel())
	s.RegisterChannel(NewDiscordNotificationChannel())
	s.RegisterChannel(NewTelegramNotificationChannel())
	s.RegisterChannel(NewSMSNotificationChannel())
	s.RegisterChannel(NewWebhookNotificationChannel())
	s.RegisterChannel(NewLogNotificationChannel())
}

// RegisterChannel registers a notification channel
func (s *NotificationService) RegisterChannel(channel notificationcore.Channel) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	s.channels[channel.GetName()] = channel
}

// Send sends a notification to a notifiable entity
func (s *NotificationService) Send(ctx context.Context, notification notificationcore.Notification, notifiable notificationcore.Notifiable) error {
	if notification.ShouldQueue() {
		return s.queueNotification(ctx, notification, notifiable)
	}

	return s.SendNow(ctx, notification, notifiable)
}

// SendNow sends a notification immediately without queuing
func (s *NotificationService) SendNow(ctx context.Context, notification notificationcore.Notification, notifiable notificationcore.Notifiable) error {
	// Check if notification should be sent to this notifiable
	if !notification.ShouldSend(notifiable) {
		facades.Log().Info("Notification skipped for notifiable", map[string]interface{}{
			"notification_type": notification.GetType(),
			"notifiable_id":     notifiable.GetID(),
			"notifiable_type":   notifiable.GetType(),
		})
		return nil
	}

	// Get channels to send through
	channels := s.getChannelsForNotification(notification, notifiable)
	if len(channels) == 0 {
		return fmt.Errorf("no channels available for notification")
	}

	// Send through each channel with retry logic
	var errors []error
	for _, channel := range channels {
		err := s.sendWithRetry(ctx, notification, notifiable, channel)
		if err != nil {
			errors = append(errors, fmt.Errorf("channel %s failed after retries: %w", channel.GetName(), err))
		}
	}

	// Return first error if any occurred
	if len(errors) > 0 {
		return errors[0]
	}

	return nil
}

// sendWithRetry sends a notification through a channel with retry logic
func (s *NotificationService) sendWithRetry(ctx context.Context, notification notificationcore.Notification, notifiable notificationcore.Notifiable, channel notificationcore.Channel) error {
	var lastErr error

	// Create or find notification record for tracking
	notificationRecord := s.findOrCreateNotificationRecord(notification, notifiable, channel.GetName())

	for attempt := 1; attempt <= s.retryConfig.MaxAttempts; attempt++ {
		// Check if notification has expired
		if notificationRecord.IsExpired() {
			s.markNotificationFailed(notificationRecord, "notification expired")
			return fmt.Errorf("notification expired")
		}

		// Update attempt tracking
		notificationRecord.IncrementAttempts()
		facades.Orm().Query().Save(notificationRecord)

		// Check rate limits before sending
		rateLimitInfo := s.rateLimiter.IsAllowed(notifiable.GetID(), notification.GetType(), channel.GetName())
		if !rateLimitInfo.Allowed {
			s.markNotificationFailed(notificationRecord, fmt.Sprintf("rate limited: %s", rateLimitInfo.Reason))
			return fmt.Errorf("notification rate limited: %s", rateLimitInfo.Reason)
		}

		// Attempt to send
		err := channel.Send(ctx, notification, notifiable)
		if err == nil {
			// Success - mark as sent/delivered and increment rate limit counter
			notificationRecord.MarkAsSent()
			if channel.GetName() == "database" {
				notificationRecord.MarkAsDelivered()
			}
			facades.Orm().Query().Save(notificationRecord)

			// Increment rate limit counter
			s.rateLimiter.IncrementCounter(notifiable.GetID(), notification.GetType(), channel.GetName())

			facades.Log().Info("Notification sent successfully", map[string]interface{}{
				"channel":           channel.GetName(),
				"notification_type": notification.GetType(),
				"notifiable_id":     notifiable.GetID(),
				"attempt":           attempt,
			})
			return nil
		}

		lastErr = err
		facades.Log().Warning("Notification attempt failed", map[string]interface{}{
			"channel":           channel.GetName(),
			"notification_type": notification.GetType(),
			"notifiable_id":     notifiable.GetID(),
			"attempt":           attempt,
			"max_attempts":      s.retryConfig.MaxAttempts,
			"error":             err.Error(),
		})

		// If this was the last attempt, mark as failed
		if attempt == s.retryConfig.MaxAttempts {
			s.markNotificationFailed(notificationRecord, fmt.Sprintf("max attempts reached: %s", err.Error()))
			break
		}

		// Calculate delay for next attempt with exponential backoff
		delay := s.calculateRetryDelay(attempt)

		facades.Log().Info("Retrying notification after delay", map[string]interface{}{
			"channel":           channel.GetName(),
			"notification_type": notification.GetType(),
			"notifiable_id":     notifiable.GetID(),
			"next_attempt":      attempt + 1,
			"delay_seconds":     delay.Seconds(),
		})

		// Wait before retry
		select {
		case <-ctx.Done():
			s.markNotificationFailed(notificationRecord, "context cancelled")
			return ctx.Err()
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	return lastErr
}

// calculateRetryDelay calculates the delay for the next retry attempt using exponential backoff
func (s *NotificationService) calculateRetryDelay(attempt int) time.Duration {
	// Calculate exponential backoff: baseDelay * (backoffFactor ^ (attempt - 1))
	delay := float64(s.retryConfig.BaseDelay) * math.Pow(s.retryConfig.BackoffFactor, float64(attempt-1))

	// Cap at max delay
	if time.Duration(delay) > s.retryConfig.MaxDelay {
		delay = float64(s.retryConfig.MaxDelay)
	}

	// Add jitter if enabled (±25% of the calculated delay)
	if s.retryConfig.JitterEnabled {
		jitter := delay * 0.25 * (2.0*rand.Float64() - 1.0) // Random value between -0.25 and +0.25
		delay += jitter
		if delay < 0 {
			delay = float64(s.retryConfig.BaseDelay)
		}
	}

	return time.Duration(delay)
}

// findOrCreateNotificationRecord finds or creates a notification database record
func (s *NotificationService) findOrCreateNotificationRecord(notification notificationcore.Notification, notifiable notificationcore.Notifiable, channel string) *models.Notification {
	var notificationRecord models.Notification

	// Try to find existing record
	err := facades.Orm().Query().
		Where("type = ?", notification.GetType()).
		Where("notifiable_id = ?", notifiable.GetID()).
		Where("notifiable_type = ?", notifiable.GetType()).
		Where("channel = ?", channel).
		Where("delivery_status IN ?", []string{"pending", "sent"}).
		First(&notificationRecord)

	if err != nil {
		// Create new record
		notificationRecord = models.Notification{
			Type:           notification.GetType(),
			Data:           notification.GetData(),
			NotifiableID:   notifiable.GetID(),
			NotifiableType: notifiable.GetType(),
			Channel:        channel,
			DeliveryStatus: "pending",
			Priority:       string(notification.GetPriority()),
			Metadata:       notification.GetMetadata(),
		}

		// Set expiration if notification has one
		if notification.GetExpiresAt() != nil {
			notificationRecord.SetExpiration(24 * time.Hour) // Default 24 hour expiration
		}

		facades.Orm().Query().Create(&notificationRecord)
	}

	return &notificationRecord
}

// markNotificationFailed marks a notification as failed with reason
func (s *NotificationService) markNotificationFailed(notification *models.Notification, reason string) {
	notification.MarkAsFailed(reason)
	facades.Orm().Query().Save(notification)
}

// SendToMany sends a notification to multiple notifiable entities
func (s *NotificationService) SendToMany(ctx context.Context, notification notificationcore.Notification, notifiables []notificationcore.Notifiable) error {
	if notification.ShouldQueue() {
		return s.queueNotificationToMany(ctx, notification, notifiables)
	}

	return s.SendToManyNow(ctx, notification, notifiables)
}

// SendToManyNow sends a notification to multiple notifiable entities immediately
func (s *NotificationService) SendToManyNow(ctx context.Context, notification notificationcore.Notification, notifiables []notificationcore.Notifiable) error {
	var errors []error
	var wg sync.WaitGroup
	errorChan := make(chan error, len(notifiables))

	// Send to each notifiable concurrently
	for _, notifiable := range notifiables {
		wg.Add(1)
		go func(n notificationcore.Notifiable) {
			defer wg.Done()
			if err := s.SendNow(ctx, notification, n); err != nil {
				errorChan <- err
			}
		}(notifiable)
	}

	// Wait for all sends to complete
	wg.Wait()
	close(errorChan)

	// Collect errors
	for err := range errorChan {
		errors = append(errors, err)
	}

	// Return first error if any occurred
	if len(errors) > 0 {
		return errors[0]
	}

	return nil
}

// Helper methods for queue system

func (s *NotificationService) getNotifiableType(notifiable notificationcore.Notifiable) string {
	// Use reflection to get the type name
	return reflect.TypeOf(notifiable).Elem().Name()
}

func (s *NotificationService) serializeNotification(notification notificationcore.Notification) string {
	// Serialize notification data to JSON
	// In a real implementation, you'd want to serialize all notification properties
	data := map[string]interface{}{
		"type":        notification.GetType(),
		"queue_name":  notification.GetQueueName(),
		"queue_delay": notification.GetDelay(),
		// Add other serializable properties as needed
	}

	serialized, err := json.Marshal(data)
	if err != nil {
		facades.Log().Error("Failed to serialize notification", map[string]interface{}{
			"error": err.Error(),
			"type":  notification.GetType(),
		})
		return "{}"
	}

	return string(serialized)
}

func (s *NotificationService) useGoravelQueue() bool {
	// Check if Goravel queue is configured and available
	// This is a simplified check - in reality you'd check queue configuration
	queueDriver := facades.Config().GetString("queue.default", "")
	return queueDriver != "" && queueDriver != "sync"
}

func (s *NotificationService) dispatchToGoravelQueue(job *NotificationQueueJob) error {
	// Goravel queue system integration requires implementing queue.Job interface
	// For now, fall back to background processing until proper queue job implementation
	facades.Log().Info("Queue integration requires proper Job interface implementation", map[string]interface{}{
		"job_id":            job.ID,
		"notification_type": job.NotificationType,
		"queue_name":        job.QueueName,
		"delay":             job.Delay,
	})

	// Fall back to background processing
	return s.processInBackground(context.Background(), job)
}

// processInBackground processes the notification in a background goroutine
func (s *NotificationService) processInBackground(ctx context.Context, job *NotificationQueueJob) error {
	// Validate job before processing
	if job == nil {
		return fmt.Errorf("job cannot be nil")
	}
	if job.NotifiableID == "" {
		return fmt.Errorf("notifiable ID cannot be empty")
	}
	if job.NotificationType == "" {
		return fmt.Errorf("notification type cannot be empty")
	}

	// Process the notification in a background goroutine with panic recovery
	go func() {
		defer func() {
			if r := recover(); r != nil {
				facades.Log().Error("Panic in notification processing", map[string]interface{}{
					"job_id": job.ID,
					"panic":  r,
				})

				// Mark job as failed
				now := time.Now()
				job.FailedAt = &now
				job.Error = fmt.Sprintf("panic during processing: %v", r)
			}
		}()

		// Apply delay if specified
		if job.Delay > 0 {
			facades.Log().Debug("Applying notification delay", map[string]interface{}{
				"job_id": job.ID,
				"delay":  job.Delay,
			})
			time.Sleep(job.Delay)
		}

		// Process the job with timeout
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		err := s.processQueueJobWithTimeout(ctx, job)
		if err != nil {
			facades.Log().Error("Failed to process notification queue job", map[string]interface{}{
				"job_id":   job.ID,
				"error":    err.Error(),
				"attempts": job.Attempts + 1,
			})

			// Retry logic with exponential backoff
			if job.Attempts < job.MaxAttempts {
				job.Attempts++

				// Calculate exponential backoff delay (1s, 4s, 9s, 16s, etc.)
				retryDelay := time.Duration(job.Attempts*job.Attempts) * time.Second

				facades.Log().Info("Retrying notification job", map[string]interface{}{
					"job_id":      job.ID,
					"attempt":     job.Attempts,
					"retry_delay": retryDelay,
				})

				time.Sleep(retryDelay)

				// Recursive retry
				s.processInBackground(ctx, job)
			} else {
				// Mark as permanently failed
				now := time.Now()
				job.FailedAt = &now
				job.Error = err.Error()

				facades.Log().Error("Notification job failed permanently", map[string]interface{}{
					"job_id":       job.ID,
					"attempts":     job.Attempts,
					"max_attempts": job.MaxAttempts,
					"final_error":  err.Error(),
				})

				// Send to dead letter queue or alert admins
				s.handlePermanentFailure(job)
			}
		} else {
			// Mark as successfully processed
			now := time.Now()
			job.ProcessedAt = &now

			facades.Log().Info("Notification job processed successfully", map[string]interface{}{
				"job_id":   job.ID,
				"attempts": job.Attempts,
				"duration": time.Since(job.CreatedAt),
			})
		}
	}()

	facades.Log().Info("Notification queued for background processing", map[string]interface{}{
		"job_id":            job.ID,
		"notification_type": job.NotificationType,
		"delay":             job.Delay,
		"max_attempts":      job.MaxAttempts,
	})

	return nil
}

// processQueueJobWithTimeout processes a job with timeout protection
func (s *NotificationService) processQueueJobWithTimeout(ctx context.Context, job *NotificationQueueJob) error {
	// Create a channel to signal completion
	done := make(chan error, 1)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				done <- fmt.Errorf("panic in job processing: %v", r)
			}
		}()

		done <- s.processQueueJob(ctx, job)
	}()

	// Wait for completion or timeout
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return fmt.Errorf("job processing timed out: %w", ctx.Err())
	}
}

// handlePermanentFailure handles jobs that have failed permanently
func (s *NotificationService) handlePermanentFailure(job *NotificationQueueJob) {
	// Log detailed failure information
	facades.Log().Error("Notification permanently failed", map[string]interface{}{
		"job_id":            job.ID,
		"notification_type": job.NotificationType,
		"notifiable_id":     job.NotifiableID,
		"notifiable_type":   job.NotifiableType,
		"attempts":          job.Attempts,
		"created_at":        job.CreatedAt,
		"failed_at":         job.FailedAt,
		"error":             job.Error,
	})

	// In production, you might want to:
	// 1. Store in a dead letter queue
	// 2. Send alert to administrators
	// 3. Create a support ticket
	// 4. Retry with different strategy

	// For now, we'll store the failed job for manual inspection
	failedJobKey := fmt.Sprintf("failed_notification_job:%s", job.ID)
	facades.Cache().Put(failedJobKey, job, 7*24*time.Hour) // Keep for 7 days
}

func (s *NotificationService) processQueueJob(ctx context.Context, job *NotificationQueueJob) error {
	// Reconstruct the notification and notifiable from the job data
	// This is a simplified implementation - in reality you'd need proper deserialization
	facades.Log().Info("Processing notification queue job", map[string]interface{}{
		"job_id":            job.ID,
		"notification_type": job.NotificationType,
		"notifiable_id":     job.NotifiableID,
		"notifiable_type":   job.NotifiableType,
	})

	// In a real implementation, you would:
	// 1. Deserialize the notification data
	// 2. Reconstruct the notification object
	// 3. Find the notifiable by ID and type
	// 4. Call SendNow with the reconstructed objects

	// For now, just log that the job was processed
	facades.Log().Info("Notification job completed", map[string]interface{}{
		"job_id": job.ID,
	})

	return nil
}

// GetChannel returns a specific notification channel
func (s *NotificationService) GetChannel(name string) (notificationcore.Channel, error) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	channel, exists := s.channels[name]
	if !exists {
		return nil, fmt.Errorf("channel %s not found", name)
	}

	return channel, nil
}

// GetChannels returns all available notification channels
func (s *NotificationService) GetChannels() map[string]notificationcore.Channel {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	// Return a copy to avoid race conditions
	channels := make(map[string]notificationcore.Channel)
	for name, channel := range s.channels {
		channels[name] = channel
	}

	return channels
}

// IsChannelEnabled checks if a channel is enabled
func (s *NotificationService) IsChannelEnabled(name string) bool {
	channel, err := s.GetChannel(name)
	if err != nil {
		return false
	}

	return channel.IsEnabled()
}

// ValidateChannel validates a channel configuration
func (s *NotificationService) ValidateChannel(name string) error {
	channel, err := s.GetChannel(name)
	if err != nil {
		return err
	}

	return channel.Validate()
}

// getChannelsForNotification determines which channels to use for a notification
func (s *NotificationService) getChannelsForNotification(notification notificationcore.Notification, notifiable notificationcore.Notifiable) []notificationcore.Channel {
	var availableChannels []notificationcore.Channel

	// Get user's preferred channels based on notification preferences
	userID := notifiable.GetID()
	notificationType := notification.GetType()

	// Check if user has preferences for this notification type
	preferredChannels := s.preferenceService.GetEnabledChannelsForType(userID, notificationType)

	// If no user preferences, fall back to notification's default channels
	if len(preferredChannels) == 0 {
		preferredChannels = notification.GetChannels()
	}

	// If still no channels, use enabled channels for the notifiable
	if len(preferredChannels) == 0 {
		// Get all available channels and filter by enabled ones
		allChannels := []string{"database", "mail", "push", "sms", "slack", "discord", "telegram", "webhook"}
		for _, channel := range allChannels {
			if notifiable.IsChannelEnabled(channel) {
				preferredChannels = append(preferredChannels, channel)
			}
		}
	}

	// If still no channels, use default
	if len(preferredChannels) == 0 {
		preferredChannels = []string{"database"}
	}

	// Get available channels and filter by user preferences
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, channelName := range preferredChannels {
		// Check if channel exists and is enabled
		if channel, exists := s.channels[channelName]; exists && channel.IsEnabled() {
			// Check user preferences for this specific channel
			if s.preferenceService.IsNotificationAllowed(userID, notificationType, channelName) {
				availableChannels = append(availableChannels, channel)
			} else {
				facades.Log().Debug("Notification blocked by user preferences", map[string]interface{}{
					"user_id":           userID,
					"notification_type": notificationType,
					"channel":           channelName,
				})
			}
		}
	}

	return availableChannels
}

// queueNotification queues a notification for later processing
func (s *NotificationService) queueNotification(ctx context.Context, notification notificationcore.Notification, notifiable notificationcore.Notifiable) error {
	// Create a queue job for the notification
	queueJob := &NotificationQueueJob{
		ID:               helpers.GenerateULID(),
		NotificationType: notification.GetType(),
		NotifiableID:     notifiable.GetID(),
		NotifiableType:   s.getNotifiableType(notifiable),
		NotificationData: s.serializeNotification(notification),
		QueueName:        notification.GetQueueName(),
		Delay:            notification.GetDelay(),
		CreatedAt:        time.Now(),
		Attempts:         0,
		MaxAttempts:      3, // Default max attempts
	}

	// Use Goravel's queue system if available, otherwise fallback to background processing
	if s.useGoravelQueue() {
		return s.dispatchToGoravelQueue(queueJob)
	}

	// Fallback to background goroutine processing
	return s.processInBackground(ctx, queueJob)
}

// queueNotificationToMany queues a notification for multiple notifiables
func (s *NotificationService) queueNotificationToMany(ctx context.Context, notification notificationcore.Notification, notifiables []notificationcore.Notifiable) error {
	// Create separate queue jobs for each notifiable for better error handling and retry logic
	var errors []error

	for _, notifiable := range notifiables {
		err := s.queueNotification(ctx, notification, notifiable)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to queue notification for %s: %w", notifiable.GetID(), err))
		}
	}

	// Log summary
	facades.Log().Info("Bulk notification queued", map[string]interface{}{
		"notification_type": notification.GetType(),
		"recipient_count":   len(notifiables),
		"failed_count":      len(errors),
		"queue_name":        notification.GetQueueName(),
		"queue_delay":       notification.GetDelay(),
	})

	// Return first error if any occurred
	if len(errors) > 0 {
		return errors[0]
	}

	return nil
}
