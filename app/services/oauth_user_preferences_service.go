package services

import (
	"fmt"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type OAuthUserPreferencesService struct{}

// UserPreferences represents user OAuth preferences
type UserPreferences struct {
	UserID                   string                      `json:"user_id"`
	AutoLinkAccounts         bool                        `json:"auto_link_accounts"`           // Automatically link accounts with same email
	RequireConsentForNewApps bool                        `json:"require_consent_for_new_apps"` // Always show consent screen for new apps
	ShareProfileInfo         bool                        `json:"share_profile_info"`           // Allow sharing basic profile info
	ShareEmailAddress        bool                        `json:"share_email_address"`          // Allow sharing email address
	EnableSecurityAlerts     bool                        `json:"enable_security_alerts"`       // Receive security alerts
	TrustedDeviceExpiry      int                         `json:"trusted_device_expiry"`        // Days before trusted device expires
	PreferredProviders       []string                    `json:"preferred_providers"`          // Preferred OAuth providers in order
	BlockedProviders         []string                    `json:"blocked_providers"`            // Blocked OAuth providers
	PrivacyLevel             string                      `json:"privacy_level"`                // strict, balanced, permissive
	NotificationPreferences  models.NotificationSettings `json:"notification_preferences"`
	SecurityPreferences      models.SecuritySettings     `json:"security_preferences"`
	DataSharingPreferences   models.DataSharingSettings  `json:"data_sharing_preferences"`
	CreatedAt                time.Time                   `json:"created_at"`
	UpdatedAt                time.Time                   `json:"updated_at"`
}

func NewOAuthUserPreferencesService() *OAuthUserPreferencesService {
	return &OAuthUserPreferencesService{}
}

// GetUserPreferences retrieves user OAuth preferences
func (s *OAuthUserPreferencesService) GetUserPreferences(userID string) (*UserPreferences, error) {
	var dbPrefs models.OAuthUserPreference

	// Try to find existing preferences
	err := facades.Orm().Query().Where("user_id = ?", userID).First(&dbPrefs)
	if err != nil {
		// If not found, create default preferences
		if err.Error() == "record not found" {
			return s.createDefaultPreferences(userID)
		}
		return nil, fmt.Errorf("failed to get user preferences: %w", err)
	}

	// Convert model to service struct
	return s.modelToPreferences(&dbPrefs), nil
}

// UpdateUserPreferences updates user OAuth preferences
func (s *OAuthUserPreferencesService) UpdateUserPreferences(userID string, preferences *UserPreferences) error {
	// Validate preferences
	if err := s.validatePreferences(preferences); err != nil {
		return fmt.Errorf("invalid preferences: %w", err)
	}

	preferences.UserID = userID
	preferences.UpdatedAt = time.Now()

	var dbPrefs models.OAuthUserPreference

	// Try to find existing preferences
	err := facades.Orm().Query().Where("user_id = ?", userID).First(&dbPrefs)
	if err != nil && err.Error() != "record not found" {
		return fmt.Errorf("failed to find user preferences: %w", err)
	}

	// Convert service struct to model
	if err != nil && err.Error() == "record not found" {
		// Create new record
		dbPrefs = s.preferencesToModel(preferences)
		err = facades.Orm().Query().Create(&dbPrefs)
	} else {
		// Update existing record
		s.updateModelFromPreferences(&dbPrefs, preferences)
		err = facades.Orm().Query().Save(&dbPrefs)
	}

	if err != nil {
		return fmt.Errorf("failed to save user preferences: %w", err)
	}

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

	// Check if this app has been consented to before
	consentCount, err := facades.Orm().Query().Table("oauth_consents").
		Where("user_id = ? AND client_id = ?", userID, clientID).
		Count()
	if err != nil {
		facades.Log().Warning("Failed to check consent history", map[string]interface{}{
			"user_id":   userID,
			"client_id": clientID,
			"error":     err.Error(),
		})
		return true, nil // Default to requiring consent on error
	}

	// If no previous consent and not permissive, require consent
	return consentCount == 0 && preferences.PrivacyLevel != "permissive", nil
}

// createDefaultPreferences creates default preferences for a new user
func (s *OAuthUserPreferencesService) createDefaultPreferences(userID string) (*UserPreferences, error) {
	preferences := s.getDefaultPreferences(userID)

	// Save to database
	err := s.UpdateUserPreferences(userID, preferences)
	if err != nil {
		return nil, fmt.Errorf("failed to create default preferences: %w", err)
	}

	return preferences, nil
}

// modelToPreferences converts database model to service struct
func (s *OAuthUserPreferencesService) modelToPreferences(model *models.OAuthUserPreference) *UserPreferences {
	return &UserPreferences{
		UserID:                   model.UserID,
		AutoLinkAccounts:         model.AutoLinkAccounts,
		RequireConsentForNewApps: model.RequireConsentForNewApps,
		ShareProfileInfo:         model.ShareProfileInfo,
		ShareEmailAddress:        model.ShareEmailAddress,
		EnableSecurityAlerts:     model.EnableSecurityAlerts,
		TrustedDeviceExpiry:      model.TrustedDeviceExpiry,
		PreferredProviders:       model.GetPreferredProviders(),
		BlockedProviders:         model.GetBlockedProviders(),
		PrivacyLevel:             model.PrivacyLevel,
		NotificationPreferences:  model.GetNotificationPreferences(),
		SecurityPreferences:      model.GetSecurityPreferences(),
		DataSharingPreferences:   model.GetDataSharingPreferences(),
		CreatedAt:                model.CreatedAt,
		UpdatedAt:                model.UpdatedAt,
	}
}

// preferencesToModel converts service struct to database model
func (s *OAuthUserPreferencesService) preferencesToModel(prefs *UserPreferences) models.OAuthUserPreference {
	model := models.OAuthUserPreference{
		UserID:                   prefs.UserID,
		AutoLinkAccounts:         prefs.AutoLinkAccounts,
		RequireConsentForNewApps: prefs.RequireConsentForNewApps,
		ShareProfileInfo:         prefs.ShareProfileInfo,
		ShareEmailAddress:        prefs.ShareEmailAddress,
		EnableSecurityAlerts:     prefs.EnableSecurityAlerts,
		TrustedDeviceExpiry:      prefs.TrustedDeviceExpiry,
		PrivacyLevel:             prefs.PrivacyLevel,
		CreatedAt:                prefs.CreatedAt,
		UpdatedAt:                prefs.UpdatedAt,
	}

	model.SetPreferredProviders(prefs.PreferredProviders)
	model.SetBlockedProviders(prefs.BlockedProviders)
	model.SetNotificationPreferences(prefs.NotificationPreferences)
	model.SetSecurityPreferences(prefs.SecurityPreferences)
	model.SetDataSharingPreferences(prefs.DataSharingPreferences)

	return model
}

// updateModelFromPreferences updates existing model from preferences
func (s *OAuthUserPreferencesService) updateModelFromPreferences(model *models.OAuthUserPreference, prefs *UserPreferences) {
	model.AutoLinkAccounts = prefs.AutoLinkAccounts
	model.RequireConsentForNewApps = prefs.RequireConsentForNewApps
	model.ShareProfileInfo = prefs.ShareProfileInfo
	model.ShareEmailAddress = prefs.ShareEmailAddress
	model.EnableSecurityAlerts = prefs.EnableSecurityAlerts
	model.TrustedDeviceExpiry = prefs.TrustedDeviceExpiry
	model.PrivacyLevel = prefs.PrivacyLevel
	model.UpdatedAt = prefs.UpdatedAt

	model.SetPreferredProviders(prefs.PreferredProviders)
	model.SetBlockedProviders(prefs.BlockedProviders)
	model.SetNotificationPreferences(prefs.NotificationPreferences)
	model.SetSecurityPreferences(prefs.SecurityPreferences)
	model.SetDataSharingPreferences(prefs.DataSharingPreferences)
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
		NotificationPreferences: models.NotificationSettings{
			EmailNotifications:       true,
			PushNotifications:        false,
			SMSNotifications:         false,
			NewDeviceAlerts:          true,
			SuspiciousActivityAlerts: true,
			ConsentReminders:         false,
		},
		SecurityPreferences: models.SecuritySettings{
			RequireMFAForHighRisk:     true,
			BlockSuspiciousIPs:        true,
			LimitConcurrentSessions:   5,
			SessionTimeout:            60, // 1 hour
			RequireDeviceVerification: true,
			EnableLocationTracking:    true,
		},
		DataSharingPreferences: models.DataSharingSettings{
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
