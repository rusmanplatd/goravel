package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250117000001CreateOAuthUserPreferencesTable struct{}

// Signature The unique signature for the migration.
func (r *M20250117000001CreateOAuthUserPreferencesTable) Signature() string {
	return "20250117000001_create_oauth_user_preferences_table"
}

// Up runs the migration
func (r *M20250117000001CreateOAuthUserPreferencesTable) Up() error {
	return facades.Schema().Create("oauth_user_preferences", func(table schema.Blueprint) {
		table.ID()
		table.String("user_id", 26).Comment("User ID (ULID)")
		table.Boolean("auto_link_accounts").Default(true).Comment("Automatically link accounts with same email")
		table.Boolean("require_consent_for_new_apps").Default(true).Comment("Always show consent screen for new apps")
		table.Boolean("share_profile_info").Default(true).Comment("Allow sharing basic profile info")
		table.Boolean("share_email_address").Default(true).Comment("Allow sharing email address")
		table.Boolean("enable_security_alerts").Default(true).Comment("Receive security alerts")
		table.Integer("trusted_device_expiry").Default(30).Comment("Days before trusted device expires")
		table.Json("preferred_providers").Nullable().Comment("Preferred OAuth providers in order")
		table.Json("blocked_providers").Nullable().Comment("Blocked OAuth providers")
		table.String("privacy_level", 20).Default("balanced").Comment("Privacy level: strict, balanced, permissive")
		table.Json("notification_preferences").Nullable().Comment("Notification settings")
		table.Json("security_preferences").Nullable().Comment("Security settings")
		table.Json("data_sharing_preferences").Nullable().Comment("Data sharing settings")
		table.Timestamps()

		// Indexes
		table.Unique("user_id")
		table.Index("privacy_level")

		// Foreign key constraints
		table.Foreign("user_id").References("id").On("users")
	})
}

// Down reverses the migration
func (r *M20250117000001CreateOAuthUserPreferencesTable) Down() error {
	return facades.Schema().DropIfExists("oauth_user_preferences")
}
