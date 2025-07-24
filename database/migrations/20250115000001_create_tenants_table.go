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
		table.Ulid("id").Comment("Unique tenant identifier")
		table.String("name").Comment("Tenant name")
		table.String("slug").Nullable().Comment("URL-friendly tenant identifier")
		table.String("domain").Nullable().Comment("Custom domain for tenant")
		table.Text("description").Comment("Tenant description")
		table.Boolean("is_active").Default(false).Comment("Whether tenant is active")
		table.Json("settings").Comment("Tenant-specific settings")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Unique("slug")
		table.Unique("domain")
	})
}

// Down Reverse the migrations.
func (r *M20250115000001CreateTenantsTable) Down() error {
	return facades.Schema().DropIfExists("tenants")
}
