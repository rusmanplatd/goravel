package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20210101000001CreateUsersTable struct{}

// Signature The unique signature for the migration.
func (r *M20210101000001CreateUsersTable) Signature() string {
	return "20210101000001_create_users_table"
}

// Up Run the migrations.
func (r *M20210101000001CreateUsersTable) Up() error {
	return facades.Schema().Create("users", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique user identifier")
		table.String("name").Comment("User's full name")
		table.String("email").Comment("User's email address")
		table.String("password").Comment("Hashed user password")
		table.TimestampTz("email_verified_at").Nullable().Comment("When email was verified")
		table.String("remember_token").Comment("Remember me token")
		table.Boolean("is_active").Comment("Whether user account is active")
		// MFA fields
		table.String("mfa_secret").Nullable().Comment("TOTP secret for multi-factor authentication")
		table.Boolean("mfa_enabled").Default(false).Comment("Whether MFA is enabled for this user")
		table.TimestampTz("mfa_enabled_at").Nullable().Comment("When MFA was enabled")
		table.Text("mfa_backup_codes").Nullable().Comment("MFA backup codes as JSON")

		// Password reset fields
		table.String("password_reset_token").Nullable().Comment("Password reset token")
		table.TimestampTz("password_reset_expires_at").Nullable().Comment("When password reset token expires")

		// WebAuthn fields
		table.Boolean("webauthn_enabled").Default(false).Comment("Whether WebAuthn is enabled for this user")
		table.TimestampTz("webauthn_enabled_at").Nullable().Comment("When WebAuthn was enabled")

		table.String("avatar").Nullable().Comment("User's profile picture/avatar URL")
		table.String("google_id").Nullable().Comment("Google OAuth ID for Google sign-in integration")

		// Login tracking
		table.TimestampTz("last_login_at").Nullable().Comment("Last login timestamp")
		table.String("last_login_ip").Nullable().Comment("Last login IP address")
		table.String("last_login_user_agent").Nullable().Comment("Last login user agent")

		// Account lockout fields
		table.Integer("failed_login_attempts").Default(0).Comment("Number of consecutive failed login attempts")
		table.TimestampTz("locked_at").Nullable().Comment("When account was locked")
		table.TimestampTz("locked_until").Nullable().Comment("When account lock expires")
		table.String("phone").Nullable().Comment("User's phone number for notifications")
		table.String("slack_webhook").Nullable().Comment("Slack webhook URL for notifications")
		table.String("discord_webhook").Nullable().Comment("Discord webhook URL for notifications")
		table.String("telegram_chat_id").Nullable().Comment("Telegram chat ID for notifications")
		table.String("webhook_url").Nullable().Comment("Custom webhook URL for notifications")

		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Nullable().Comment("User who created data")
		table.Ulid("updated_by").Nullable().Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("email")
		table.Index("is_active")
		table.Index("phone")
		table.Index("password_reset_token")
		table.Index("mfa_enabled")
		table.Index("webauthn_enabled")
		table.Unique("google_id")
		table.Index("locked_at")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add foreign key constraints
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20210101000001CreateUsersTable) Down() error {
	return facades.Schema().DropIfExists("users")
}
