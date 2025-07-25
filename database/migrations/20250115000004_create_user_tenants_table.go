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
		table.Ulid("id").Comment("Unique identifier")
		table.Ulid("user_id").Comment("User reference")
		table.Ulid("tenant_id").Comment("Tenant reference")
		table.Boolean("is_active").Comment("Whether user is active in this tenant")
		table.TimestampTz("joined_at").Comment("When user joined the tenant")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Foreign keys
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("tenant_id").References("id").On("tenants")

		// Indexes
		table.Index("user_id")
		table.Index("tenant_id")
		table.Index("is_active")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add foreign key constraints
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")

		table.Unique("user_id", "tenant_id")
	})
}

// Down Reverse the migrations.
func (r *M20250115000004CreateUserTenantsTable) Down() error {
	return facades.Schema().DropIfExists("user_tenants")
}
