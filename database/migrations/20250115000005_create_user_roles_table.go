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
		table.Ulid("user_id")
		table.Ulid("role_id")
		table.Ulid("tenant_id").Nullable()
		table.TimestampsTz()

		// Primary key
		// table.Primary("user_id", "role_id", "tenant_id")
		table.Primary("user_id", "role_id")

		// Foreign keys
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("role_id").References("id").On("roles")
		table.Foreign("tenant_id").References("id").On("tenants")

		// Indexes
		table.Index("user_id")
		table.Index("role_id")
		table.Index("tenant_id")
	})
}

// Down Reverse the migrations.
func (r *M20250115000005CreateUserRolesTable) Down() error {
	return facades.Schema().DropIfExists("user_roles")
}
