package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000006CreateRolePermissionsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000006CreateRolePermissionsTable) Signature() string {
	return "20250115000006_create_role_permissions_table"
}

// Up Run the migrations.
func (r *M20250115000006CreateRolePermissionsTable) Up() error {
	return facades.Schema().Create("role_permissions", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique identifier")
		table.Ulid("role_id").Comment("Role reference")
		table.Ulid("permission_id").Comment("Permission reference")
		table.TimestampsTz()

		// Primary key
		table.Primary("id")

		// Foreign keys
		table.Foreign("role_id").References("id").On("roles")
		table.Foreign("permission_id").References("id").On("permissions")

		// Indexes
		table.Index("role_id")
		table.Index("permission_id")

		// Unique constraint
		table.Unique("role_id", "permission_id")
	})
}

// Down Reverse the migrations.
func (r *M20250115000006CreateRolePermissionsTable) Down() error {
	return facades.Schema().DropIfExists("role_permissions")
}
