package models

import (
	"time"
)

// User represents a user in the system
// @Description User model with multi-organization support and authentication features
type User struct {
	BaseModel
	// User's full name
	// @example John Doe
	Name string `gorm:"not null" json:"name" example:"John Doe"`

	// User's email address
	// @example john.doe@example.com
	Email string `gorm:"unique;not null" json:"email" example:"john.doe@example.com"`

	// Email verification timestamp
	// @example 2024-01-15T10:30:00Z
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// User's password (write-only)
	// @example password123
	Password string `gorm:"not null" json:"password,omitempty" example:"password123"`

	// Remember token for persistent login
	// @example abc123def456
	RememberToken string `json:"remember_token,omitempty" example:"abc123def456"`

	// User's profile picture/avatar URL
	// @example https://example.com/avatar.jpg
	Avatar string `json:"avatar,omitempty" example:"https://example.com/avatar.jpg"`

	// Google OAuth ID for Google sign-in integration
	// @example 123456789012345678901
	GoogleID *string `gorm:"unique" json:"google_id,omitempty" example:"123456789012345678901"`

	// Whether the user is active
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// MFA fields
	// @example false
	MfaEnabled bool `gorm:"default:false" json:"mfa_enabled" example:"false"`
	// @example abc123def456
	MfaSecret string `json:"mfa_secret,omitempty" example:"abc123def456"`
	// @example 2024-01-15T10:30:00Z
	MfaEnabledAt *time.Time `json:"mfa_enabled_at,omitempty" example:"2024-01-15T10:30:00Z"`
	// @example [{"code":"1234-5678","used":false}]
	MfaBackupCodes string `gorm:"type:text" json:"mfa_backup_codes,omitempty" example:"[{\"code\":\"1234-5678\",\"used\":false}]"`

	// Password reset fields
	// @example abc123def456
	PasswordResetToken string `json:"password_reset_token,omitempty" example:"abc123def456"`
	// @example 2024-01-15T10:30:00Z
	PasswordResetExpiresAt *time.Time `json:"password_reset_expires_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// WebAuthn fields
	// @example false
	WebauthnEnabled bool `gorm:"default:false" json:"webauthn_enabled" example:"false"`
	// @example 2024-01-15T10:30:00Z
	WebauthnEnabledAt *time.Time `json:"webauthn_enabled_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Login tracking
	// @example 2024-01-15T10:30:00Z
	LastLoginAt *time.Time `json:"last_login_at,omitempty" example:"2024-01-15T10:30:00Z"`
	// @example 192.168.1.1
	LastLoginIp string `json:"last_login_ip,omitempty" example:"192.168.1.1"`
	// @example Mozilla/5.0...
	LastLoginUserAgent string `json:"last_login_user_agent,omitempty" example:"Mozilla/5.0..."`

	// Account lockout fields
	// @example 0
	FailedLoginAttempts int `gorm:"default:0" json:"failed_login_attempts" example:"0"`
	// @example 2024-01-15T10:30:00Z
	LockedAt *time.Time `json:"locked_at,omitempty" example:"2024-01-15T10:30:00Z"`
	// @example 2024-01-15T10:30:00Z
	LockedUntil *time.Time `json:"locked_until,omitempty" example:"2024-01-15T10:30:00Z"`

	// Relationships
	// @Description User's roles across organizations
	Roles []Role `gorm:"many2many:user_roles;" json:"roles,omitempty"`

	// @Description User's WebAuthn credentials
	WebauthnCredentials []WebauthnCredential `gorm:"foreignKey:UserID" json:"webauthn_credentials,omitempty"`

	// @Description User's push subscriptions
	PushSubscriptions []PushSubscription `gorm:"foreignKey:UserID" json:"push_subscriptions,omitempty"`

	// @Description User's profile information
	Profile *UserProfile `gorm:"foreignKey:UserID" json:"profile,omitempty"`

	// Notification fields
	// @example +1234567890
	Phone string `json:"phone,omitempty" example:"+1234567890"`
	// @example https://hooks.slack.com/services/...
	SlackWebhook string `json:"slack_webhook,omitempty" example:"https://hooks.slack.com/services/..."`
	// @example https://discord.com/api/webhooks/...
	DiscordWebhook string `json:"discord_webhook,omitempty" example:"https://discord.com/api/webhooks/..."`
	// @example 123456789
	TelegramChatID string `json:"telegram_chat_id,omitempty" example:"123456789"`
	// @example https://example.com/webhook
	WebhookURL string `json:"webhook_url,omitempty" example:"https://example.com/webhook"`

	// Notification preferences
	// @Description User's preferred notification channels
	PreferredNotificationChannels []string `gorm:"-" json:"preferred_notification_channels,omitempty"`
}

// Notifiable interface implementation for User

// GetID returns the user's ID
func (u *User) GetID() string {
	return u.ID
}

// GetType returns the user's type
func (u *User) GetType() string {
	return "User"
}

// GetEmail returns the user's email address
func (u *User) GetEmail() string {
	return u.Email
}

// GetPhone returns the user's phone number
func (u *User) GetPhone() string {
	return u.Phone
}

// GetPushTokens returns the user's push notification tokens
func (u *User) GetPushTokens() []string {
	// Return active push subscription endpoints
	var tokens []string
	for _, subscription := range u.PushSubscriptions {
		if subscription.IsValid() {
			tokens = append(tokens, subscription.Endpoint)
		}
	}
	return tokens
}

// GetWebhookURL returns the user's webhook URL
func (u *User) GetWebhookURL() string {
	return u.WebhookURL
}

// GetTimezone returns the user's timezone (from profile or default)
func (u *User) GetTimezone() string {
	if u.Profile != nil && u.Profile.Timezone != "" {
		return u.Profile.Timezone
	}
	return "UTC"
}

// GetLocale returns the user's locale (from profile or default)
func (u *User) GetLocale() string {
	if u.Profile != nil && u.Profile.Language != "" {
		return u.Profile.Language
	}
	return "en"
}

// GetNotificationPreferences returns the user's notification preferences
func (u *User) GetNotificationPreferences() map[string]interface{} {
	preferences := make(map[string]interface{})

	// Add basic preferences
	preferences["email_enabled"] = u.Email != ""
	preferences["push_enabled"] = len(u.GetPushTokens()) > 0
	preferences["sms_enabled"] = u.Phone != ""
	preferences["slack_enabled"] = u.SlackWebhook != ""
	preferences["discord_enabled"] = u.DiscordWebhook != ""
	preferences["telegram_enabled"] = u.TelegramChatID != ""
	preferences["webhook_enabled"] = u.WebhookURL != ""
	preferences["security_notifications"] = true // Enable security notifications by default

	// Add user status
	preferences["is_active"] = u.IsActive
	preferences["email_verified"] = u.EmailVerifiedAt != nil
	preferences["mfa_enabled"] = u.MfaEnabled

	return preferences
}

// GetChannelAddress returns the address for a specific notification channel
func (u *User) GetChannelAddress(channel string) string {
	switch channel {
	case "mail", "email":
		return u.Email
	case "sms":
		return u.Phone
	case "slack":
		return u.SlackWebhook
	case "discord":
		return u.DiscordWebhook
	case "telegram":
		return u.TelegramChatID
	case "webhook":
		return u.WebhookURL
	case "push":
		tokens := u.GetPushTokens()
		if len(tokens) > 0 {
			return tokens[0] // Return first token
		}
		return ""
	default:
		return ""
	}
}

// IsChannelEnabled checks if a specific channel is enabled for the user
func (u *User) IsChannelEnabled(channel string) bool {
	if !u.IsActive {
		return false
	}

	switch channel {
	case "database":
		return true // Database notifications are always enabled for active users
	case "mail", "email":
		return u.Email != "" && u.EmailVerifiedAt != nil
	case "sms":
		return u.Phone != ""
	case "push":
		return len(u.GetPushTokens()) > 0
	case "slack":
		return u.SlackWebhook != ""
	case "discord":
		return u.DiscordWebhook != ""
	case "telegram":
		return u.TelegramChatID != ""
	case "webhook":
		return u.WebhookURL != ""
	case "websocket":
		return true // WebSocket notifications are enabled for active users
	default:
		return false
	}
}

// GetQuietHours returns the user's quiet hours (from profile or defaults)
func (u *User) GetQuietHours() (start, end string) {
	if u.Profile != nil {
		// Assuming profile has quiet hours fields
		return "22:00", "08:00" // Default quiet hours
	}
	return "", "" // No quiet hours
}

// GetRateLimits returns the user's rate limits for different notification types
func (u *User) GetRateLimits() map[string]int {
	limits := make(map[string]int)

	// Default rate limits
	limits["email"] = 50     // 50 emails per hour
	limits["sms"] = 10       // 10 SMS per hour
	limits["push"] = 200     // 200 push notifications per hour
	limits["slack"] = 100    // 100 Slack messages per hour
	limits["discord"] = 100  // 100 Discord messages per hour
	limits["telegram"] = 100 // 100 Telegram messages per hour

	// You could customize these based on user subscription level, etc.
	return limits
}

// UserRole represents the pivot table for user-role relationship
// @Description User-role relationship within an organization context
type UserRole struct {
	// User ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"primaryKey;type:char(26)" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Role ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	RoleID string `gorm:"primaryKey;type:char(26)" json:"role_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Organization ID for role context
	// @example 01HXYZ123456789ABCDEFGHIJK
	OrganizationID *string `gorm:"type:char(26)" json:"organization_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	User         User          `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Role         Role          `gorm:"foreignKey:RoleID" json:"role,omitempty"`
	Organization *Organization `gorm:"foreignKey:OrganizationID" json:"organization,omitempty"`
}
