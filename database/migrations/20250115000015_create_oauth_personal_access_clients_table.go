package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000015CreateOauthPersonalAccessClientsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000015CreateOauthPersonalAccessClientsTable) Signature() string {
	return "20250115000015_create_oauth_personal_access_clients_table"
}

// Up Run the migrations.
func (r *M20250115000015CreateOauthPersonalAccessClientsTable) Up() error {
	return facades.Schema().Create("oauth_personal_access_clients", func(table schema.Blueprint) {
		table.String("id", 26).Comment("Personal access client identifier")
		table.String("client_id", 26).Comment("OAuth client reference")
		table.TimestampsTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("client_id")
	})
}

// Down Reverse the migrations.
func (r *M20250115000015CreateOauthPersonalAccessClientsTable) Down() error {
	return facades.Schema().DropIfExists("oauth_personal_access_clients")
}
