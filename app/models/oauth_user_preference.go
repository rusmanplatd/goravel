package models

import (
	"encoding/json"
	"time"
)

// OAuthUserPreference represents user OAuth preferences
// @Description OAuth User Preferences model for managing user OAuth settings
type OAuthUserPreference struct {
	ID                       uint      `gorm:"primaryKey" json:"id"`
	UserID                   string    `gorm:"type:char(26);uniqueIndex;not null" json:"user_id" example:"01HXZ1234567890ABCDEFGHIJK"`
	AutoLinkAccounts         bool      `gorm:"default:true" json:"auto_link_accounts" example:"true"`
	RequireConsentForNewApps bool      `gorm:"default:true" json:"require_consent_for_new_apps" example:"true"`
	ShareProfileInfo         bool      `gorm:"default:true" json:"share_profile_info" example:"true"`
	ShareEmailAddress        bool      `gorm:"default:true" json:"share_email_address" example:"true"`
	EnableSecurityAlerts     bool      `gorm:"default:true" json:"enable_security_alerts" example:"true"`
	TrustedDeviceExpiry      int       `gorm:"default:30" json:"trusted_device_expiry" example:"30"`
	PreferredProviders       *string   `gorm:"type:json" json:"preferred_providers,omitempty"`
	BlockedProviders         *string   `gorm:"type:json" json:"blocked_providers,omitempty"`
	PrivacyLevel             string    `gorm:"default:balanced" json:"privacy_level" example:"balanced"`
	NotificationPreferences  *string   `gorm:"type:json" json:"notification_preferences,omitempty"`
	SecurityPreferences      *string   `gorm:"type:json" json:"security_preferences,omitempty"`
	DataSharingPreferences   *string   `gorm:"type:json" json:"data_sharing_preferences,omitempty"`
	CreatedAt                time.Time `json:"created_at"`
	UpdatedAt                time.Time `json:"updated_at"`

	// Relationships
	User *User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

// TableName returns the table name for the model
func (OAuthUserPreference) TableName() string {
	return "oauth_user_preferences"
}

// GetPreferredProviders returns the preferred providers as a slice
func (p *OAuthUserPreference) GetPreferredProviders() []string {
	if p.PreferredProviders == nil {
		return []string{}
	}
	var providers []string
	json.Unmarshal([]byte(*p.PreferredProviders), &providers)
	return providers
}

// SetPreferredProviders sets the preferred providers from a slice
func (p *OAuthUserPreference) SetPreferredProviders(providers []string) error {
	data, err := json.Marshal(providers)
	if err != nil {
		return err
	}
	str := string(data)
	p.PreferredProviders = &str
	return nil
}

// GetBlockedProviders returns the blocked providers as a slice
func (p *OAuthUserPreference) GetBlockedProviders() []string {
	if p.BlockedProviders == nil {
		return []string{}
	}
	var providers []string
	json.Unmarshal([]byte(*p.BlockedProviders), &providers)
	return providers
}

// SetBlockedProviders sets the blocked providers from a slice
func (p *OAuthUserPreference) SetBlockedProviders(providers []string) error {
	data, err := json.Marshal(providers)
	if err != nil {
		return err
	}
	str := string(data)
	p.BlockedProviders = &str
	return nil
}

// NotificationSettings represents notification preferences
type NotificationSettings struct {
	EmailNotifications       bool `json:"email_notifications"`
	PushNotifications        bool `json:"push_notifications"`
	SMSNotifications         bool `json:"sms_notifications"`
	NewDeviceAlerts          bool `json:"new_device_alerts"`
	SuspiciousActivityAlerts bool `json:"suspicious_activity_alerts"`
	ConsentReminders         bool `json:"consent_reminders"`
}

// GetNotificationPreferences returns the notification preferences
func (p *OAuthUserPreference) GetNotificationPreferences() NotificationSettings {
	if p.NotificationPreferences == nil {
		return NotificationSettings{
			EmailNotifications:       true,
			PushNotifications:        false,
			SMSNotifications:         false,
			NewDeviceAlerts:          true,
			SuspiciousActivityAlerts: true,
			ConsentReminders:         false,
		}
	}
	var settings NotificationSettings
	json.Unmarshal([]byte(*p.NotificationPreferences), &settings)
	return settings
}

// SetNotificationPreferences sets the notification preferences
func (p *OAuthUserPreference) SetNotificationPreferences(settings NotificationSettings) error {
	data, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	str := string(data)
	p.NotificationPreferences = &str
	return nil
}

// SecuritySettings represents security preferences
type SecuritySettings struct {
	RequireMFAForHighRisk     bool `json:"require_mfa_for_high_risk"`
	BlockSuspiciousIPs        bool `json:"block_suspicious_ips"`
	LimitConcurrentSessions   int  `json:"limit_concurrent_sessions"`
	SessionTimeout            int  `json:"session_timeout"`
	RequireDeviceVerification bool `json:"require_device_verification"`
	EnableLocationTracking    bool `json:"enable_location_tracking"`
}

// GetSecurityPreferences returns the security preferences
func (p *OAuthUserPreference) GetSecurityPreferences() SecuritySettings {
	if p.SecurityPreferences == nil {
		return SecuritySettings{
			RequireMFAForHighRisk:     true,
			BlockSuspiciousIPs:        true,
			LimitConcurrentSessions:   5,
			SessionTimeout:            60,
			RequireDeviceVerification: true,
			EnableLocationTracking:    true,
		}
	}
	var settings SecuritySettings
	json.Unmarshal([]byte(*p.SecurityPreferences), &settings)
	return settings
}

// SetSecurityPreferences sets the security preferences
func (p *OAuthUserPreference) SetSecurityPreferences(settings SecuritySettings) error {
	data, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	str := string(data)
	p.SecurityPreferences = &str
	return nil
}

// DataSharingSettings represents data sharing preferences
type DataSharingSettings struct {
	ShareWithTrustedApps  bool     `json:"share_with_trusted_apps"`
	ShareAnalyticsData    bool     `json:"share_analytics_data"`
	AllowDataExport       bool     `json:"allow_data_export"`
	RestrictSensitiveData bool     `json:"restrict_sensitive_data"`
	AllowedDataTypes      []string `json:"allowed_data_types"`
	DataRetentionPeriod   int      `json:"data_retention_period"`
}

// GetDataSharingPreferences returns the data sharing preferences
func (p *OAuthUserPreference) GetDataSharingPreferences() DataSharingSettings {
	if p.DataSharingPreferences == nil {
		return DataSharingSettings{
			ShareWithTrustedApps:  true,
			ShareAnalyticsData:    false,
			AllowDataExport:       true,
			RestrictSensitiveData: true,
			AllowedDataTypes:      []string{"profile", "email"},
			DataRetentionPeriod:   365,
		}
	}
	var settings DataSharingSettings
	json.Unmarshal([]byte(*p.DataSharingPreferences), &settings)
	return settings
}

// SetDataSharingPreferences sets the data sharing preferences
func (p *OAuthUserPreference) SetDataSharingPreferences(settings DataSharingSettings) error {
	data, err := json.Marshal(settings)
	if err != nil {
		return err
	}
	str := string(data)
	p.DataSharingPreferences = &str
	return nil
}
