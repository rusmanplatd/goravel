package models

import (
	"encoding/json"
	"time"
)

// NotificationPreference represents a user's notification preferences
type NotificationPreference struct {
	BaseModel
	UserID           string                 `json:"user_id" gorm:"not null;index"`
	NotificationType string                 `json:"notification_type" gorm:"not null"` // e.g., "WelcomeNotification", "PasswordResetNotification"
	Channels         []string               `json:"channels" gorm:"type:json"`         // enabled channels for this notification type
	Enabled          bool                   `json:"enabled" gorm:"default:true"`
	Settings         map[string]interface{} `json:"settings" gorm:"type:json"` // channel-specific settings

	// Timing preferences
	QuietHoursStart *string `json:"quiet_hours_start"` // e.g., "22:00"
	QuietHoursEnd   *string `json:"quiet_hours_end"`   // e.g., "08:00"
	TimeZone        string  `json:"timezone" gorm:"default:UTC"`

	// Frequency control
	MaxPerHour      *int   `json:"max_per_hour"`                          // max notifications per hour for this type
	MaxPerDay       *int   `json:"max_per_day"`                           // max notifications per day for this type
	DigestEnabled   bool   `json:"digest_enabled"`                        // whether to batch notifications into digest
	DigestFrequency string `json:"digest_frequency" gorm:"default:daily"` // hourly, daily, weekly

	// Relationships
	User *User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

// TableName specifies the table name for the NotificationPreference model
func (np *NotificationPreference) TableName() string {
	return "notification_preferences"
}

// IsChannelEnabled checks if a specific channel is enabled for this notification type
func (np *NotificationPreference) IsChannelEnabled(channel string) bool {
	if !np.Enabled {
		return false
	}

	for _, enabledChannel := range np.Channels {
		if enabledChannel == channel {
			return true
		}
	}

	return false
}

// EnableChannel enables a notification channel
func (np *NotificationPreference) EnableChannel(channel string) {
	if !np.IsChannelEnabled(channel) {
		np.Channels = append(np.Channels, channel)
	}
}

// DisableChannel disables a notification channel
func (np *NotificationPreference) DisableChannel(channel string) {
	var newChannels []string
	for _, enabledChannel := range np.Channels {
		if enabledChannel != channel {
			newChannels = append(newChannels, enabledChannel)
		}
	}
	np.Channels = newChannels
}

// IsInQuietHours checks if the current time is within quiet hours
func (np *NotificationPreference) IsInQuietHours() bool {
	if np.QuietHoursStart == nil || np.QuietHoursEnd == nil {
		return false
	}

	// Load timezone
	loc, err := time.LoadLocation(np.TimeZone)
	if err != nil {
		loc = time.UTC
	}

	now := time.Now().In(loc)
	currentTime := now.Format("15:04")

	// Handle same-day quiet hours (e.g., 22:00 to 23:59)
	if *np.QuietHoursStart <= *np.QuietHoursEnd {
		return currentTime >= *np.QuietHoursStart && currentTime <= *np.QuietHoursEnd
	}

	// Handle overnight quiet hours (e.g., 22:00 to 08:00)
	return currentTime >= *np.QuietHoursStart || currentTime <= *np.QuietHoursEnd
}

// GetChannelSetting retrieves a channel-specific setting
func (np *NotificationPreference) GetChannelSetting(channel, key string) interface{} {
	if np.Settings == nil {
		return nil
	}

	channelSettings, exists := np.Settings[channel]
	if !exists {
		return nil
	}

	if settingsMap, ok := channelSettings.(map[string]interface{}); ok {
		return settingsMap[key]
	}

	return nil
}

// SetChannelSetting sets a channel-specific setting
func (np *NotificationPreference) SetChannelSetting(channel, key string, value interface{}) {
	if np.Settings == nil {
		np.Settings = make(map[string]interface{})
	}

	channelSettings, exists := np.Settings[channel]
	if !exists {
		np.Settings[channel] = make(map[string]interface{})
		channelSettings = np.Settings[channel]
	}

	if settingsMap, ok := channelSettings.(map[string]interface{}); ok {
		settingsMap[key] = value
	}
}

// ShouldSendNow checks if a notification should be sent now based on preferences
func (np *NotificationPreference) ShouldSendNow() bool {
	if !np.Enabled {
		return false
	}

	if np.IsInQuietHours() {
		return false
	}

	// TODO: Check rate limits (MaxPerHour, MaxPerDay)
	// This would require additional tracking of sent notifications

	return true
}

// GetEnabledChannels returns all enabled channels for this notification type
func (np *NotificationPreference) GetEnabledChannels() []string {
	if !np.Enabled {
		return []string{}
	}

	return np.Channels
}

// MarshalJSON customizes JSON serialization
func (np *NotificationPreference) MarshalJSON() ([]byte, error) {
	type Alias NotificationPreference
	return json.Marshal(&struct {
		*Alias
		Channels []string `json:"channels"`
	}{
		Alias:    (*Alias)(np),
		Channels: np.Channels,
	})
}

// UnmarshalJSON customizes JSON deserialization
func (np *NotificationPreference) UnmarshalJSON(data []byte) error {
	type Alias NotificationPreference
	aux := &struct {
		*Alias
		Channels []string `json:"channels"`
	}{
		Alias: (*Alias)(np),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	np.Channels = aux.Channels
	return nil
}

// DefaultNotificationPreferences returns default preferences for common notification types
func DefaultNotificationPreferences(userID string) []NotificationPreference {
	return []NotificationPreference{
		{
			UserID:           userID,
			NotificationType: "WelcomeNotification",
			Channels:         []string{"database", "mail"},
			Enabled:          true,
			DigestEnabled:    false,
		},
		{
			UserID:           userID,
			NotificationType: "PasswordResetNotification",
			Channels:         []string{"database", "mail"},
			Enabled:          true,
			DigestEnabled:    false,
		},
		{
			UserID:           userID,
			NotificationType: "SecurityAlertNotification",
			Channels:         []string{"database", "mail", "push"},
			Enabled:          true,
			DigestEnabled:    false,
		},
		{
			UserID:           userID,
			NotificationType: "CalendarEventNotification",
			Channels:         []string{"database", "push"},
			Enabled:          true,
			DigestEnabled:    true,
			DigestFrequency:  "daily",
		},
		{
			UserID:           userID,
			NotificationType: "ChatMessageNotification",
			Channels:         []string{"database", "push", "websocket"},
			Enabled:          true,
			DigestEnabled:    false,
		},
		{
			UserID:           userID,
			NotificationType: "MeetingInviteNotification",
			Channels:         []string{"database", "mail", "push"},
			Enabled:          true,
			DigestEnabled:    false,
		},
	}
}
