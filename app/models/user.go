package models

import (
	"goravel/app/notificationcore"
	"time"
)

// User represents a user in the system
// @Description User model with multi-tenant support and authentication features
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
	// @Description User's associated tenants
	Tenants []Tenant `gorm:"many2many:user_tenants;" json:"tenants,omitempty"`

	// @Description User's roles across tenants
	Roles []Role `gorm:"many2many:user_roles;" json:"roles,omitempty"`

	// @Description User's WebAuthn credentials
	WebauthnCredentials []WebauthnCredential `gorm:"foreignKey:UserID" json:"webauthn_credentials,omitempty"`

	// @Description User's push subscriptions
	PushSubscriptions []PushSubscription `gorm:"foreignKey:UserID" json:"push_subscriptions,omitempty"`

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

// GetSlackWebhook returns the user's Slack webhook URL
func (u *User) GetSlackWebhook() string {
	return u.SlackWebhook
}

// GetDiscordWebhook returns the user's Discord webhook URL
func (u *User) GetDiscordWebhook() string {
	return u.DiscordWebhook
}

// GetTelegramChatID returns the user's Telegram chat ID
func (u *User) GetTelegramChatID() string {
	return u.TelegramChatID
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

// GetPreferredChannels returns the user's preferred notification channels
func (u *User) GetPreferredChannels() []string {
	if len(u.PreferredNotificationChannels) > 0 {
		return u.PreferredNotificationChannels
	}
	// Default channels
	return []string{"database", "mail"}
}

// ShouldReceiveNotification checks if the user should receive a specific notification
func (u *User) ShouldReceiveNotification(notification notificationcore.Notification) bool {
	// Check if user is active
	if !u.IsActive {
		return false
	}

	// Check if user is locked
	if u.LockedAt != nil && u.LockedUntil != nil && time.Now().Before(*u.LockedUntil) {
		return false
	}

	// For email notifications, check if email is verified (optional)
	// You can customize this logic based on your requirements
	// if strings.Contains(notification.GetChannels(), "mail") && u.EmailVerifiedAt == nil {
	//     return false
	// }

	return true
}

// UserTenant represents the pivot table for user-tenant relationship
// @Description User-tenant relationship with additional metadata
type UserTenant struct {
	// User ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"primaryKey;type:char(26)" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Tenant ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	TenantID string `gorm:"primaryKey;type:char(26)" json:"tenant_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Whether the user is active in this tenant
	// @example true
	IsActive bool `gorm:"default:true" json:"is_active" example:"true"`

	// When the user joined this tenant
	// @example 2024-01-15T10:30:00Z
	JoinedAt time.Time `json:"joined_at" example:"2024-01-15T10:30:00Z"`

	// Relationships
	User   User   `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Tenant Tenant `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`
}

// UserRole represents the pivot table for user-role relationship
// @Description User-role relationship within a tenant context
type UserRole struct {
	// User ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID string `gorm:"primaryKey;type:char(26)" json:"user_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Role ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	RoleID string `gorm:"primaryKey;type:char(26)" json:"role_id" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Tenant ID for role context
	// @example 01HXYZ123456789ABCDEFGHIJK
	TenantID *string `gorm:"type:char(26)" json:"tenant_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Relationships
	User   User    `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Role   Role    `gorm:"foreignKey:RoleID" json:"role,omitempty"`
	Tenant *Tenant `gorm:"foreignKey:TenantID" json:"tenant,omitempty"`
}
