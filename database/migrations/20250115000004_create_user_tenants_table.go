package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000004CreateUserTenantsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000004CreateUserTenantsTable) Signature() string {
	return "20250115000004_create_user_tenants_table"
}

// Up Run the migrations.
func (r *M20250115000004CreateUserTenantsTable) Up() error {
	return facades.Schema().Create("user_tenants", func(table schema.Blueprint) {
		table.Ulid("user_id")
		table.Ulid("tenant_id")
		table.Boolean("is_active")
		table.TimestampTz("joined_at")
		table.TimestampsTz()

		// Primary key
		table.Primary("user_id", "tenant_id")

		// Foreign keys
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("tenant_id").References("id").On("tenants")

		// Indexes
		table.Index("user_id")
		table.Index("tenant_id")
		table.Index("is_active")
	})
}

// Down Reverse the migrations.
func (r *M20250115000004CreateUserTenantsTable) Down() error {
	return facades.Schema().DropIfExists("user_tenants")
}
