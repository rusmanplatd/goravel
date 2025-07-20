package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000012CreateOauthAccessTokensTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000012CreateOauthAccessTokensTable) Signature() string {
	return "20250115000012_create_oauth_access_tokens_table"
}

// Up Run the migrations.
func (r *M20250115000012CreateOauthAccessTokensTable) Up() error {
	return facades.Schema().Create("oauth_access_tokens", func(table schema.Blueprint) {
		table.String("id", 100)
		table.Ulid("user_id").Nullable()
		table.Ulid("client_id")
		table.String("name", 255).Nullable()
		table.Text("scopes").Nullable()
		table.Boolean("revoked")
		table.TimestampsTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("user_id")
		table.Index("client_id")
		table.Index("revoked")
	})
}

// Down Reverse the migrations.
func (r *M20250115000012CreateOauthAccessTokensTable) Down() error {
	return facades.Schema().DropIfExists("oauth_access_tokens")
}
