package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000058AddTenantIdToOrganizationsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000058AddTenantIdToOrganizationsTable) Signature() string {
	return "20250115000058_add_tenant_id_to_organizations_table"
}

// Up Run the migrations.
func (r *M20250115000058AddTenantIdToOrganizationsTable) Up() error {
	return facades.Schema().Table("organizations", func(table schema.Blueprint) {
		table.Ulid("tenant_id").Nullable()
		table.Index("tenant_id")
		table.Foreign("tenant_id").References("id").On("tenants")
	})
}

// Down Reverse the migrations.
func (r *M20250115000058AddTenantIdToOrganizationsTable) Down() error {
	return facades.Schema().Table("organizations", func(table schema.Blueprint) {
		table.DropForeign("tenant_id")
		table.DropIndex("tenant_id")
		table.DropColumn("tenant_id")
	})
}
