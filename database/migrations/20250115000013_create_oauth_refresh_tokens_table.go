package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000013CreateOauthRefreshTokensTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000013CreateOauthRefreshTokensTable) Signature() string {
	return "20250115000013_create_oauth_refresh_tokens_table"
}

// Up Run the migrations.
func (r *M20250115000013CreateOauthRefreshTokensTable) Up() error {
	return facades.Schema().Create("oauth_refresh_tokens", func(table schema.Blueprint) {
		table.String("id", 100).Comment("Refresh token identifier")
		table.String("access_token_id", 100).Comment("Associated access token reference")
		table.Boolean("revoked").Comment("Whether refresh token is revoked")
		table.TimestampTz("expires_at").Comment("Token expiration timestamp")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("access_token_id")
		table.Index("revoked")
	})
}

// Down Reverse the migrations.
func (r *M20250115000013CreateOauthRefreshTokensTable) Down() error {
	return facades.Schema().DropIfExists("oauth_refresh_tokens")
}
