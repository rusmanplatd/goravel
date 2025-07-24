package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000003CreatePermissionsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000003CreatePermissionsTable) Signature() string {
	return "20250115000003_create_permissions_table"
}

// Up Run the migrations.
func (r *M20250115000003CreatePermissionsTable) Up() error {
	return facades.Schema().Create("permissions", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique permission identifier")
		table.String("name").Comment("Permission name")
		table.String("guard").Comment("Authentication guard name")
		table.Ulid("tenant_id").Nullable().Comment("Tenant reference")
		table.Text("description").Comment("Permission description")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("name")
		table.Index("guard")
		table.Index("tenant_id")
		table.Foreign("tenant_id").References("id").On("tenants")
	})
}

// Down Reverse the migrations.
func (r *M20250115000003CreatePermissionsTable) Down() error {
	return facades.Schema().DropIfExists("permissions")
}
