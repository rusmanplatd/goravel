package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000073CreateOauthUserIdentitiesTable struct{}

// Signature returns the unique identifier for this migration
func (r *M20250115000073CreateOauthUserIdentitiesTable) Signature() string {
	return "20250115000073_create_oauth_user_identities_table"
}

// Up runs the migration
func (r *M20250115000073CreateOauthUserIdentitiesTable) Up() error {
	return facades.Schema().Create("oauth_user_identities", func(table schema.Blueprint) {
		table.ID()
		table.String("user_id").Comment("Reference to users table")
		table.UnsignedBigInteger("provider_id").Comment("Reference to oauth_identity_providers table")
		table.String("provider_user_id").Comment("User ID from the OAuth provider")
		table.String("provider_username").Nullable().Comment("Username from the OAuth provider")
		table.String("provider_email").Comment("Email from the OAuth provider")
		table.String("provider_name").Comment("Display name from the OAuth provider")
		table.String("provider_avatar").Nullable().Comment("Avatar URL from the OAuth provider")
		table.Text("provider_data").Nullable().Comment("Additional provider data as JSON")
		table.Text("access_token").Nullable().Comment("OAuth access token (encrypted)")
		table.Text("refresh_token").Nullable().Comment("OAuth refresh token (encrypted)")
		table.Timestamp("token_expires_at").Nullable().Comment("Access token expiration")
		table.Timestamp("last_login_at").Nullable().Comment("Last login using this provider")
		table.Timestamps()

		// Indexes
		table.Index("user_id")
		table.Index("provider_id")
		table.Index("provider_user_id")
		table.Index("provider_email")
		table.Index("last_login_at")

		// Unique constraint
		table.Unique("provider_id", "provider_user_id")

		// Foreign keys
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("provider_id").References("id").On("oauth_identity_providers")
	})
}

// Down reverses the migration
func (r *M20250115000073CreateOauthUserIdentitiesTable) Down() error {
	return facades.Schema().DropIfExists("oauth_user_identities")
}
