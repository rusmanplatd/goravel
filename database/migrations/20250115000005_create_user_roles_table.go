package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000005CreateUserRolesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000005CreateUserRolesTable) Signature() string {
	return "20250115000005_create_user_roles_table"
}

// Up Run the migrations.
func (r *M20250115000005CreateUserRolesTable) Up() error {
	return facades.Schema().Create("user_roles", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique identifier")
		table.Ulid("user_id").Comment("User reference")
		table.Ulid("role_id").Comment("Role reference")
		table.Ulid("tenant_id").Nullable().Comment("Tenant reference for tenant-specific roles")
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")
		table.TimestampsTz()

		// Primary key
		table.Primary("id")

		// Foreign keys
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("role_id").References("id").On("roles")
		table.Foreign("tenant_id").References("id").On("tenants")

		// Indexes
		table.Index("user_id")
		table.Index("role_id")
		table.Index("tenant_id")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add foreign key constraints
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")

		// Unique constraint
		table.Unique("user_id", "role_id", "tenant_id")
	})
}

// Down Reverse the migrations.
func (r *M20250115000005CreateUserRolesTable) Down() error {
	return facades.Schema().DropIfExists("user_roles")
}
