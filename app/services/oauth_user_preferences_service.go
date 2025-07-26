package services

import (
	"fmt"
	"time"

	"github.com/goravel/framework/facades"
)

type OAuthUserPreferencesService struct{}

type UserPreferences struct {
	UserID                   string               `json:"user_id"`
	AutoLinkAccounts         bool                 `json:"auto_link_accounts"`           // Automatically link accounts with same email
	RequireConsentForNewApps bool                 `json:"require_consent_for_new_apps"` // Always show consent screen for new apps
	ShareProfileInfo         bool                 `json:"share_profile_info"`           // Allow sharing basic profile info
	ShareEmailAddress        bool                 `json:"share_email_address"`          // Allow sharing email address
	EnableSecurityAlerts     bool                 `json:"enable_security_alerts"`       // Receive security alerts
	TrustedDeviceExpiry      int                  `json:"trusted_device_expiry"`        // Days before trusted device expires
	PreferredProviders       []string             `json:"preferred_providers"`          // Preferred OAuth providers in order
	BlockedProviders         []string             `json:"blocked_providers"`            // Blocked OAuth providers
	PrivacyLevel             string               `json:"privacy_level"`                // strict, balanced, permissive
	NotificationPreferences  NotificationSettings `json:"notification_preferences"`
	SecurityPreferences      SecuritySettings     `json:"security_preferences"`
	DataSharingPreferences   DataSharingSettings  `json:"data_sharing_preferences"`
	CreatedAt                time.Time            `json:"created_at"`
	UpdatedAt                time.Time            `json:"updated_at"`
}

type NotificationSettings struct {
	EmailNotifications       bool `json:"email_notifications"`        // Email notifications for security events
	PushNotifications        bool `json:"push_notifications"`         // Push notifications for security events
	SMSNotifications         bool `json:"sms_notifications"`          // SMS notifications for critical events
	NewDeviceAlerts          bool `json:"new_device_alerts"`          // Alerts for new device logins
	SuspiciousActivityAlerts bool `json:"suspicious_activity_alerts"` // Alerts for suspicious activity
	ConsentReminders         bool `json:"consent_reminders"`          // Reminders about app permissions
}

type SecuritySettings struct {
	RequireMFAForHighRisk     bool `json:"require_mfa_for_high_risk"`   // Require MFA for high-risk logins
	BlockSuspiciousIPs        bool `json:"block_suspicious_ips"`        // Block known malicious IPs
	LimitConcurrentSessions   int  `json:"limit_concurrent_sessions"`   // Max concurrent sessions (0 = unlimited)
	SessionTimeout            int  `json:"session_timeout"`             // Session timeout in minutes
	RequireDeviceVerification bool `json:"require_device_verification"` // Require verification for new devices
	EnableLocationTracking    bool `json:"enable_location_tracking"`    // Track login locations
}

type DataSharingSettings struct {
	ShareWithTrustedApps  bool     `json:"share_with_trusted_apps"` // Share data with verified apps
	ShareAnalyticsData    bool     `json:"share_analytics_data"`    // Share anonymized usage data
	AllowDataExport       bool     `json:"allow_data_export"`       // Allow apps to export user data
	RestrictSensitiveData bool     `json:"restrict_sensitive_data"` // Restrict access to sensitive data
	AllowedDataTypes      []string `json:"allowed_data_types"`      // Types of data that can be shared
	DataRetentionPeriod   int      `json:"data_retention_period"`   // Days to retain user data
}

func NewOAuthUserPreferencesService() *OAuthUserPreferencesService {
	return &OAuthUserPreferencesService{}
}

// GetUserPreferences retrieves user OAuth preferences
func (s *OAuthUserPreferencesService) GetUserPreferences(userID string) (*UserPreferences, error) {
	// In a real implementation, this would query the database
	// For now, return default preferences
	return s.getDefaultPreferences(userID), nil
}

// UpdateUserPreferences updates user OAuth preferences
func (s *OAuthUserPreferencesService) UpdateUserPreferences(userID string, preferences *UserPreferences) error {
	// Validate preferences
	if err := s.validatePreferences(preferences); err != nil {
		return fmt.Errorf("invalid preferences: %w", err)
	}

	preferences.UserID = userID
	preferences.UpdatedAt = time.Now()

	// In a real implementation, this would update the database
	facades.Log().Info("User OAuth preferences updated", map[string]interface{}{
		"user_id":       userID,
		"privacy_level": preferences.PrivacyLevel,
		"auto_link":     preferences.AutoLinkAccounts,
	})

	return nil
}

// ApplyPrivacyLevel applies a predefined privacy level
func (s *OAuthUserPreferencesService) ApplyPrivacyLevel(userID, level string) error {
	preferences, err := s.GetUserPreferences(userID)
	if err != nil {
		return err
	}

	switch level {
	case "strict":
		s.applyStrictPrivacy(preferences)
	case "balanced":
		s.applyBalancedPrivacy(preferences)
	case "permissive":
		s.applyPermissivePrivacy(preferences)
	default:
		return fmt.Errorf("unknown privacy level: %s", level)
	}

	preferences.PrivacyLevel = level
	return s.UpdateUserPreferences(userID, preferences)
}

// GetProviderPreferences gets user preferences for a specific provider
func (s *OAuthUserPreferencesService) GetProviderPreferences(userID, provider string) (map[string]interface{}, error) {
	preferences, err := s.GetUserPreferences(userID)
	if err != nil {
		return nil, err
	}

	// Check if provider is blocked
	for _, blocked := range preferences.BlockedProviders {
		if blocked == provider {
			return map[string]interface{}{
				"blocked": true,
				"reason":  "User has blocked this provider",
			}, nil
		}
	}

	// Check if provider is preferred
	isPreferred := false
	for _, preferred := range preferences.PreferredProviders {
		if preferred == provider {
			isPreferred = true
			break
		}
	}

	return map[string]interface{}{
		"blocked":               false,
		"preferred":             isPreferred,
		"auto_link":             preferences.AutoLinkAccounts,
		"require_consent":       preferences.RequireConsentForNewApps,
		"share_profile":         preferences.ShareProfileInfo,
		"share_email":           preferences.ShareEmailAddress,
		"security_alerts":       preferences.EnableSecurityAlerts,
		"trusted_device_expiry": preferences.TrustedDeviceExpiry,
		"privacy_level":         preferences.PrivacyLevel,
	}, nil
}

// UpdateProviderPreference updates preference for a specific provider
func (s *OAuthUserPreferencesService) UpdateProviderPreference(userID, provider, action string) error {
	preferences, err := s.GetUserPreferences(userID)
	if err != nil {
		return err
	}

	switch action {
	case "block":
		// Add to blocked list if not already there
		if !s.contains(preferences.BlockedProviders, provider) {
			preferences.BlockedProviders = append(preferences.BlockedProviders, provider)
		}
		// Remove from preferred list if there
		preferences.PreferredProviders = s.removeFromSlice(preferences.PreferredProviders, provider)

	case "unblock":
		// Remove from blocked list
		preferences.BlockedProviders = s.removeFromSlice(preferences.BlockedProviders, provider)

	case "prefer":
		// Add to preferred list if not already there
		if !s.contains(preferences.PreferredProviders, provider) {
			preferences.PreferredProviders = append(preferences.PreferredProviders, provider)
		}
		// Remove from blocked list if there
		preferences.BlockedProviders = s.removeFromSlice(preferences.BlockedProviders, provider)

	case "unprefer":
		// Remove from preferred list
		preferences.PreferredProviders = s.removeFromSlice(preferences.PreferredProviders, provider)

	default:
		return fmt.Errorf("unknown action: %s", action)
	}

	return s.UpdateUserPreferences(userID, preferences)
}

// CheckConsentRequired checks if consent is required for a provider/app combination
func (s *OAuthUserPreferencesService) CheckConsentRequired(userID, provider, clientID string) (bool, error) {
	preferences, err := s.GetUserPreferences(userID)
	if err != nil {
		return true, err // Default to requiring consent on error
	}

	// Always require consent for new apps if preference is set
	if preferences.RequireConsentForNewApps {
		return true, nil
	}

	// Check privacy level
	if preferences.PrivacyLevel == "strict" {
		return true, nil
	}

	// In a real implementation, check if this app has been consented to before
	// For now, return based on privacy level
	return preferences.PrivacyLevel != "permissive", nil
}

// Helper methods

func (s *OAuthUserPreferencesService) getDefaultPreferences(userID string) *UserPreferences {
	return &UserPreferences{
		UserID:                   userID,
		AutoLinkAccounts:         true,
		RequireConsentForNewApps: true,
		ShareProfileInfo:         true,
		ShareEmailAddress:        true,
		EnableSecurityAlerts:     true,
		TrustedDeviceExpiry:      30, // 30 days
		PreferredProviders:       []string{},
		BlockedProviders:         []string{},
		PrivacyLevel:             "balanced",
		NotificationPreferences: NotificationSettings{
			EmailNotifications:       true,
			PushNotifications:        false,
			SMSNotifications:         false,
			NewDeviceAlerts:          true,
			SuspiciousActivityAlerts: true,
			ConsentReminders:         false,
		},
		SecurityPreferences: SecuritySettings{
			RequireMFAForHighRisk:     true,
			BlockSuspiciousIPs:        true,
			LimitConcurrentSessions:   5,
			SessionTimeout:            60, // 1 hour
			RequireDeviceVerification: true,
			EnableLocationTracking:    true,
		},
		DataSharingPreferences: DataSharingSettings{
			ShareWithTrustedApps:  true,
			ShareAnalyticsData:    false,
			AllowDataExport:       true,
			RestrictSensitiveData: true,
			AllowedDataTypes:      []string{"profile", "email"},
			DataRetentionPeriod:   365, // 1 year
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func (s *OAuthUserPreferencesService) validatePreferences(preferences *UserPreferences) error {
	// Validate privacy level
	validLevels := []string{"strict", "balanced", "permissive"}
	if !s.contains(validLevels, preferences.PrivacyLevel) {
		return fmt.Errorf("invalid privacy level: %s", preferences.PrivacyLevel)
	}

	// Validate trusted device expiry (1-365 days)
	if preferences.TrustedDeviceExpiry < 1 || preferences.TrustedDeviceExpiry > 365 {
		return fmt.Errorf("trusted device expiry must be between 1 and 365 days")
	}

	// Validate session timeout (5-1440 minutes)
	if preferences.SecurityPreferences.SessionTimeout < 5 || preferences.SecurityPreferences.SessionTimeout > 1440 {
		return fmt.Errorf("session timeout must be between 5 and 1440 minutes")
	}

	return nil
}

func (s *OAuthUserPreferencesService) applyStrictPrivacy(preferences *UserPreferences) {
	preferences.AutoLinkAccounts = false
	preferences.RequireConsentForNewApps = true
	preferences.ShareProfileInfo = false
	preferences.ShareEmailAddress = false
	preferences.EnableSecurityAlerts = true

	preferences.SecurityPreferences.RequireMFAForHighRisk = true
	preferences.SecurityPreferences.BlockSuspiciousIPs = true
	preferences.SecurityPreferences.RequireDeviceVerification = true
	preferences.SecurityPreferences.LimitConcurrentSessions = 2

	preferences.DataSharingPreferences.ShareWithTrustedApps = false
	preferences.DataSharingPreferences.ShareAnalyticsData = false
	preferences.DataSharingPreferences.AllowDataExport = false
	preferences.DataSharingPreferences.RestrictSensitiveData = true
}

func (s *OAuthUserPreferencesService) applyBalancedPrivacy(preferences *UserPreferences) {
	preferences.AutoLinkAccounts = true
	preferences.RequireConsentForNewApps = true
	preferences.ShareProfileInfo = true
	preferences.ShareEmailAddress = true
	preferences.EnableSecurityAlerts = true

	preferences.SecurityPreferences.RequireMFAForHighRisk = true
	preferences.SecurityPreferences.BlockSuspiciousIPs = true
	preferences.SecurityPreferences.RequireDeviceVerification = true
	preferences.SecurityPreferences.LimitConcurrentSessions = 5

	preferences.DataSharingPreferences.ShareWithTrustedApps = true
	preferences.DataSharingPreferences.ShareAnalyticsData = false
	preferences.DataSharingPreferences.AllowDataExport = true
	preferences.DataSharingPreferences.RestrictSensitiveData = true
}

func (s *OAuthUserPreferencesService) applyPermissivePrivacy(preferences *UserPreferences) {
	preferences.AutoLinkAccounts = true
	preferences.RequireConsentForNewApps = false
	preferences.ShareProfileInfo = true
	preferences.ShareEmailAddress = true
	preferences.EnableSecurityAlerts = false

	preferences.SecurityPreferences.RequireMFAForHighRisk = false
	preferences.SecurityPreferences.BlockSuspiciousIPs = false
	preferences.SecurityPreferences.RequireDeviceVerification = false
	preferences.SecurityPreferences.LimitConcurrentSessions = 0 // Unlimited

	preferences.DataSharingPreferences.ShareWithTrustedApps = true
	preferences.DataSharingPreferences.ShareAnalyticsData = true
	preferences.DataSharingPreferences.AllowDataExport = true
	preferences.DataSharingPreferences.RestrictSensitiveData = false
}

func (s *OAuthUserPreferencesService) contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func (s *OAuthUserPreferencesService) removeFromSlice(slice []string, item string) []string {
	result := make([]string, 0, len(slice))
	for _, s := range slice {
		if s != item {
			result = append(result, s)
		}
	}
	return result
}
