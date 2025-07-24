package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000002CreateRolesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000002CreateRolesTable) Signature() string {
	return "20250115000002_create_roles_table"
}

// Up Run the migrations.
func (r *M20250115000002CreateRolesTable) Up() error {
	return facades.Schema().Create("roles", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique role identifier")
		table.String("name").Comment("Role name")
		table.String("guard").Comment("Authentication guard name")
		table.Ulid("tenant_id").Nullable().Comment("Tenant reference")
		table.Text("description").Comment("Role description")
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("name")
		table.Index("guard")
		table.Index("tenant_id")
		table.Foreign("tenant_id").References("id").On("tenants")
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
func (r *M20250115000002CreateRolesTable) Down() error {
	return facades.Schema().DropIfExists("roles")
}
