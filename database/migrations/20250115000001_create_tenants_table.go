package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000001CreateTenantsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000001CreateTenantsTable) Signature() string {
	return "20250115000001_create_tenants_table"
}

// Up Run the migrations.
func (r *M20250115000001CreateTenantsTable) Up() error {
	return facades.Schema().Create("tenants", func(table schema.Blueprint) {
		table.Ulid("id")
		table.String("name")
		table.String("slug")
		table.String("domain")
		table.Text("description")
		table.Boolean("is_active")
		table.Json("settings")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("slug")
		table.Index("domain")
	})
}

// Down Reverse the migrations.
func (r *M20250115000001CreateTenantsTable) Down() error {
	return facades.Schema().DropIfExists("tenants")
}
