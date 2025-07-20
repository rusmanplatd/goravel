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
		table.String("id", 100)
		table.Ulid("user_id")
		table.Ulid("client_id")
		table.Text("scopes").Nullable()
		table.Boolean("revoked")
		table.TimestampTz("expires_at")
		table.String("code_challenge", 255).Nullable()
		table.String("code_challenge_method", 10).Nullable()
		table.TimestampTz("created_at")
		table.TimestampTz("updated_at")

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
