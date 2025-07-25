package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000060AddGoogleOauthFieldsToUsersTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000060AddGoogleOauthFieldsToUsersTable) Signature() string {
	return "20250115000060_add_google_oauth_fields_to_users_table"
}

// Up Run the migrations.
func (r *M20250115000060AddGoogleOauthFieldsToUsersTable) Up() error {
	return facades.Schema().Table("users", func(table schema.Blueprint) {
		table.String("avatar").Nullable().Comment("User's profile picture/avatar URL")
		table.String("google_id").Nullable().Comment("Google OAuth ID for Google sign-in integration")

		// Add index for google_id
		table.Index("google_id")
	})
}

// Down Reverse the migrations.
func (r *M20250115000060AddGoogleOauthFieldsToUsersTable) Down() error {
	return facades.Schema().Table("users", func(table schema.Blueprint) {
		table.DropColumn("avatar")
		table.DropColumn("google_id")
	})
}
