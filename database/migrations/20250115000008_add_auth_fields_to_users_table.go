package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000008AddAuthFieldsToUsersTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000008AddAuthFieldsToUsersTable) Signature() string {
	return "20250115000008_add_auth_fields_to_users_table"
}

// Up Run the migrations.
func (r *M20250115000008AddAuthFieldsToUsersTable) Up() error {
	return facades.Schema().Table("users", func(table schema.Blueprint) {
		// MFA fields
		table.String("mfa_secret").Nullable()
		table.Boolean("mfa_enabled").Default(false)
		table.TimestampTz("mfa_enabled_at").Nullable()

		// Password reset fields
		table.String("password_reset_token").Nullable()
		table.TimestampTz("password_reset_expires_at").Nullable()

		// WebAuthn fields
		table.Boolean("webauthn_enabled").Default(false)
		table.TimestampTz("webauthn_enabled_at").Nullable()

		// Login tracking
		table.TimestampTz("last_login_at").Nullable()
		table.String("last_login_ip").Nullable()
		table.String("last_login_user_agent").Nullable()

		// Account lockout fields
		table.Integer("failed_login_attempts").Default(0)
		table.TimestampTz("locked_at").Nullable()
		table.TimestampTz("locked_until").Nullable()

		// Add indexes
		table.Index("password_reset_token")
		table.Index("mfa_enabled")
		table.Index("webauthn_enabled")
		table.Index("locked_at")
	})
}

// Down Reverse the migrations.
func (r *M20250115000008AddAuthFieldsToUsersTable) Down() error {
	return facades.Schema().Table("users", func(table schema.Blueprint) {
		table.DropColumn("mfa_secret")
		table.DropColumn("mfa_enabled")
		table.DropColumn("mfa_enabled_at")
		table.DropColumn("password_reset_token")
		table.DropColumn("password_reset_expires_at")
		table.DropColumn("webauthn_enabled")
		table.DropColumn("webauthn_enabled_at")
		table.DropColumn("last_login_at")
		table.DropColumn("last_login_ip")
		table.DropColumn("last_login_user_agent")
		table.DropColumn("failed_login_attempts")
		table.DropColumn("locked_at")
		table.DropColumn("locked_until")
	})
}
