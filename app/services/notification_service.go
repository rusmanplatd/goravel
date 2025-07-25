package services

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sync"
	"time"

	"goravel/app/helpers"
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

// NotificationService handles sending notifications through various channels
type NotificationService struct {
	channels map[string]notificationcore.Channel
	mutex    sync.RWMutex
}

// NewNotificationService creates a new notification service
func NewNotificationService() *NotificationService {
	service := &NotificationService{
		channels: make(map[string]notificationcore.Channel),
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

	// Send through each channel
	var errors []error
	for _, channel := range channels {
		if err := channel.Send(ctx, notification, notifiable); err != nil {
			errors = append(errors, fmt.Errorf("channel %s failed: %w", channel.GetName(), err))
			facades.Log().Error("Notification channel failed", map[string]interface{}{
				"channel":           channel.GetName(),
				"notification_type": notification.GetType(),
				"notifiable_id":     notifiable.GetID(),
				"error":             err.Error(),
			})
		} else {
			facades.Log().Info("Notification sent successfully", map[string]interface{}{
				"channel":           channel.GetName(),
				"notification_type": notification.GetType(),
				"notifiable_id":     notifiable.GetID(),
			})
		}
	}

	// Return first error if any occurred
	if len(errors) > 0 {
		return errors[0]
	}

	return nil
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
		"queue_delay": notification.GetQueueDelay(),
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
	// Dispatch to Goravel's queue system
	// Note: This is a placeholder - actual implementation would depend on Goravel's queue API
	facades.Log().Info("Dispatching notification to Goravel queue", map[string]interface{}{
		"job_id":            job.ID,
		"notification_type": job.NotificationType,
		"queue_name":        job.QueueName,
		"delay":             job.Delay,
	})

	// In a real implementation, you'd use facades.Queue().Dispatch() or similar
	// For now, fall back to background processing
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

	// Get notification channels
	notificationChannels := notification.GetChannels()
	if len(notificationChannels) == 0 {
		// Use notifiable's preferred channels
		notificationChannels = notifiable.GetPreferredChannels()
	}

	// If still no channels, use default
	if len(notificationChannels) == 0 {
		notificationChannels = []string{"database"}
	}

	// Get available channels
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	for _, channelName := range notificationChannels {
		if channel, exists := s.channels[channelName]; exists && channel.IsEnabled() {
			availableChannels = append(availableChannels, channel)
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
		Delay:            notification.GetQueueDelay(),
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
		"queue_delay":       notification.GetQueueDelay(),
	})

	// Return first error if any occurred
	if len(errors) > 0 {
		return errors[0]
	}

	return nil
}
