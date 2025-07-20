package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000011CreateOauthClientsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000011CreateOauthClientsTable) Signature() string {
	return "20250115000011_create_oauth_clients_table"
}

// Up Run the migrations.
func (r *M20250115000011CreateOauthClientsTable) Up() error {
	return facades.Schema().Create("oauth_clients", func(table schema.Blueprint) {
		table.Ulid("id")
		table.Ulid("user_id").Nullable()
		table.String("name", 255)
		table.String("secret", 100).Nullable()
		table.String("provider", 255).Nullable()
		table.Text("redirect")
		table.Boolean("personal_access_client").Default(false)
		table.Boolean("password_client").Default(false)
		table.Boolean("revoked").Default(false)
		table.Timestamps()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("user_id")
		table.Index("personal_access_client")
		table.Index("password_client")
		table.Index("revoked")
	})
}

// Down Reverse the migrations.
func (r *M20250115000011CreateOauthClientsTable) Down() error {
	return facades.Schema().DropIfExists("oauth_clients")
}
