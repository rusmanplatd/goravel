package services

import (
	"context"
	"fmt"
	"sync"
	"time"

	"goravel/app/notificationcore"

	"github.com/goravel/framework/facades"
)

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
	// This is a simplified implementation
	// In a real application, you'd use a proper queue system
	facades.Log().Info("Notification queued", map[string]interface{}{
		"notification_type": notification.GetType(),
		"notifiable_id":     notifiable.GetID(),
		"queue_name":        notification.GetQueueName(),
		"queue_delay":       notification.GetQueueDelay(),
	})

	// For now, just send immediately after delay
	if notification.GetQueueDelay() > 0 {
		time.Sleep(notification.GetQueueDelay())
	}

	return s.SendNow(ctx, notification, notifiable)
}

// queueNotificationToMany queues a notification for multiple notifiables
func (s *NotificationService) queueNotificationToMany(ctx context.Context, notification notificationcore.Notification, notifiables []notificationcore.Notifiable) error {
	// This is a simplified implementation
	// In a real application, you'd use a proper queue system
	facades.Log().Info("Notification queued for multiple recipients", map[string]interface{}{
		"notification_type": notification.GetType(),
		"recipient_count":   len(notifiables),
		"queue_name":        notification.GetQueueName(),
		"queue_delay":       notification.GetQueueDelay(),
	})

	// For now, just send immediately after delay
	if notification.GetQueueDelay() > 0 {
		time.Sleep(notification.GetQueueDelay())
	}

	return s.SendToManyNow(ctx, notification, notifiables)
}
