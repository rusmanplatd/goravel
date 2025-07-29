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
		table.Ulid("organization_id").Nullable().Comment("Organization reference")
		table.Text("description").Comment("Permission description")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("name")
		table.Index("guard")
		table.Index("organization_id")
		table.Foreign("organization_id").References("id").On("organizations")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add foreign key constraints
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000003CreatePermissionsTable) Down() error {
	return facades.Schema().DropIfExists("permissions")
}
