package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000014CreateOauthAuthCodesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000014CreateOauthAuthCodesTable) Signature() string {
	return "20250115000014_create_oauth_auth_codes_table"
}

// Up Run the migrations.
func (r *M20250115000014CreateOauthAuthCodesTable) Up() error {
	return facades.Schema().Create("oauth_auth_codes", func(table schema.Blueprint) {
		table.String("id", 100).Comment("Authorization code identifier")
		table.Ulid("user_id").Comment("User reference")
		table.Ulid("client_id").Comment("OAuth client reference")
		table.Text("scopes").Nullable().Comment("Requested scopes")
		table.Boolean("revoked").Comment("Whether auth code is revoked")
		table.TimestampTz("expires_at").Comment("Code expiration timestamp")
		table.String("code_challenge", 255).Nullable().Comment("PKCE code challenge")
		table.String("code_challenge_method", 10).Nullable().Comment("PKCE challenge method (S256, plain)")
		table.TimestampTz("created_at").Comment("Code creation timestamp")
		table.TimestampTz("updated_at").Comment("Code update timestamp")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("user_id")
		table.Index("client_id")
		table.Index("revoked")
	})
}

// Down Reverse the migrations.
func (r *M20250115000014CreateOauthAuthCodesTable) Down() error {
	return facades.Schema().DropIfExists("oauth_auth_codes")
}
