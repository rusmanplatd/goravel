package services

import (
	"fmt"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

// NotificationPreferenceService handles user notification preferences
type NotificationPreferenceService struct{}

// NewNotificationPreferenceService creates a new notification preference service
func NewNotificationPreferenceService() *NotificationPreferenceService {
	return &NotificationPreferenceService{}
}

// GetUserPreferences retrieves all notification preferences for a user
func (s *NotificationPreferenceService) GetUserPreferences(userID string) ([]models.NotificationPreference, error) {
	var preferences []models.NotificationPreference

	err := facades.Orm().Query().
		Where("user_id = ?", userID).
		Find(&preferences)

	if err != nil {
		return nil, fmt.Errorf("failed to retrieve user preferences: %w", err)
	}

	// If no preferences exist, create defaults
	if len(preferences) == 0 {
		return s.CreateDefaultPreferences(userID)
	}

	return preferences, nil
}

// GetPreferenceForType retrieves notification preference for a specific type
func (s *NotificationPreferenceService) GetPreferenceForType(userID, notificationType string) (*models.NotificationPreference, error) {
	var preference models.NotificationPreference

	err := facades.Orm().Query().
		Where("user_id = ?", userID).
		Where("notification_type = ?", notificationType).
		First(&preference)

	if err != nil {
		// Create default preference for this type
		return s.CreateDefaultPreferenceForType(userID, notificationType)
	}

	return &preference, nil
}

// CreateDefaultPreferences creates default notification preferences for a user
func (s *NotificationPreferenceService) CreateDefaultPreferences(userID string) ([]models.NotificationPreference, error) {
	defaultPrefs := models.DefaultNotificationPreferences(userID)
	var createdPrefs []models.NotificationPreference

	for _, pref := range defaultPrefs {
		err := facades.Orm().Query().Create(&pref)
		if err != nil {
			facades.Log().Error("Failed to create default preference", map[string]interface{}{
				"user_id":           userID,
				"notification_type": pref.NotificationType,
				"error":             err.Error(),
			})
			continue
		}
		createdPrefs = append(createdPrefs, pref)
	}

	return createdPrefs, nil
}

// CreateDefaultPreferenceForType creates a default preference for a specific notification type
func (s *NotificationPreferenceService) CreateDefaultPreferenceForType(userID, notificationType string) (*models.NotificationPreference, error) {
	// Get default channels based on notification type
	defaultChannels := s.getDefaultChannelsForType(notificationType)

	preference := models.NotificationPreference{
		UserID:           userID,
		NotificationType: notificationType,
		Channels:         defaultChannels,
		Enabled:          true,
		DigestEnabled:    s.shouldEnableDigestByDefault(notificationType),
		DigestFrequency:  "daily",
	}

	err := facades.Orm().Query().Create(&preference)
	if err != nil {
		return nil, fmt.Errorf("failed to create default preference: %w", err)
	}

	return &preference, nil
}

// UpdatePreference updates a user's notification preference
func (s *NotificationPreferenceService) UpdatePreference(userID string, preference *models.NotificationPreference) error {
	// Ensure the preference belongs to the user
	if preference.UserID != userID {
		return fmt.Errorf("preference does not belong to user")
	}

	err := facades.Orm().Query().Save(preference)
	if err != nil {
		return fmt.Errorf("failed to update preference: %w", err)
	}

	facades.Log().Info("Notification preference updated", map[string]interface{}{
		"user_id":           userID,
		"notification_type": preference.NotificationType,
		"enabled":           preference.Enabled,
		"channels":          preference.Channels,
	})

	return nil
}

// EnableNotificationType enables a notification type for a user
func (s *NotificationPreferenceService) EnableNotificationType(userID, notificationType string) error {
	preference, err := s.GetPreferenceForType(userID, notificationType)
	if err != nil {
		return err
	}

	preference.Enabled = true
	return s.UpdatePreference(userID, preference)
}

// DisableNotificationType disables a notification type for a user
func (s *NotificationPreferenceService) DisableNotificationType(userID, notificationType string) error {
	preference, err := s.GetPreferenceForType(userID, notificationType)
	if err != nil {
		return err
	}

	preference.Enabled = false
	return s.UpdatePreference(userID, preference)
}

// EnableChannelForType enables a specific channel for a notification type
func (s *NotificationPreferenceService) EnableChannelForType(userID, notificationType, channel string) error {
	preference, err := s.GetPreferenceForType(userID, notificationType)
	if err != nil {
		return err
	}

	preference.EnableChannel(channel)
	return s.UpdatePreference(userID, preference)
}

// DisableChannelForType disables a specific channel for a notification type
func (s *NotificationPreferenceService) DisableChannelForType(userID, notificationType, channel string) error {
	preference, err := s.GetPreferenceForType(userID, notificationType)
	if err != nil {
		return err
	}

	preference.DisableChannel(channel)
	return s.UpdatePreference(userID, preference)
}

// SetQuietHours sets quiet hours for a user (applies to all notification types)
func (s *NotificationPreferenceService) SetQuietHours(userID, startTime, endTime, timezone string) error {
	var preferences []models.NotificationPreference

	err := facades.Orm().Query().
		Where("user_id = ?", userID).
		Find(&preferences)

	if err != nil {
		return fmt.Errorf("failed to retrieve preferences: %w", err)
	}

	// Update all preferences with quiet hours
	for _, preference := range preferences {
		preference.QuietHoursStart = &startTime
		preference.QuietHoursEnd = &endTime
		preference.TimeZone = timezone

		err := facades.Orm().Query().Save(&preference)
		if err != nil {
			facades.Log().Error("Failed to update quiet hours for preference", map[string]interface{}{
				"user_id":           userID,
				"notification_type": preference.NotificationType,
				"error":             err.Error(),
			})
		}
	}

	return nil
}

// IsNotificationAllowed checks if a notification should be sent based on user preferences
func (s *NotificationPreferenceService) IsNotificationAllowed(userID, notificationType, channel string) bool {
	preference, err := s.GetPreferenceForType(userID, notificationType)
	if err != nil {
		// If we can't get preferences, allow by default
		facades.Log().Warning("Could not retrieve notification preference, allowing by default", map[string]interface{}{
			"user_id":           userID,
			"notification_type": notificationType,
			"channel":           channel,
			"error":             err.Error(),
		})
		return true
	}

	// Check if notification type is enabled
	if !preference.Enabled {
		return false
	}

	// Check if channel is enabled
	if !preference.IsChannelEnabled(channel) {
		return false
	}

	// Check quiet hours
	if preference.IsInQuietHours() {
		return false
	}

	// Check if should send now (includes rate limiting when implemented)
	return preference.ShouldSendNow()
}

// GetEnabledChannelsForType returns enabled channels for a notification type
func (s *NotificationPreferenceService) GetEnabledChannelsForType(userID, notificationType string) []string {
	preference, err := s.GetPreferenceForType(userID, notificationType)
	if err != nil {
		// Return default channels if preference not found
		return s.getDefaultChannelsForType(notificationType)
	}

	return preference.GetEnabledChannels()
}

// getDefaultChannelsForType returns default channels for a notification type
func (s *NotificationPreferenceService) getDefaultChannelsForType(notificationType string) []string {
	switch notificationType {
	case "WelcomeNotification":
		return []string{"database", "mail"}
	case "PasswordResetNotification":
		return []string{"database", "mail"}
	case "SecurityAlertNotification":
		return []string{"database", "mail", "push"}
	case "CalendarEventNotification":
		return []string{"database", "push"}
	case "ChatMessageNotification":
		return []string{"database", "push", "websocket"}
	case "MeetingInviteNotification":
		return []string{"database", "mail", "push"}
	default:
		return []string{"database"}
	}
}

// shouldEnableDigestByDefault determines if digest should be enabled by default for a notification type
func (s *NotificationPreferenceService) shouldEnableDigestByDefault(notificationType string) bool {
	switch notificationType {
	case "CalendarEventNotification":
		return true
	case "ChatMessageNotification":
		return false // Real-time notifications
	case "SecurityAlertNotification":
		return false // Urgent notifications
	default:
		return false
	}
}

// BulkUpdatePreferences updates multiple preferences at once
func (s *NotificationPreferenceService) BulkUpdatePreferences(userID string, preferences []models.NotificationPreference) error {
	for _, preference := range preferences {
		if preference.UserID != userID {
			return fmt.Errorf("preference %s does not belong to user", preference.NotificationType)
		}

		err := facades.Orm().Query().Save(&preference)
		if err != nil {
			return fmt.Errorf("failed to update preference %s: %w", preference.NotificationType, err)
		}
	}

	return nil
}
