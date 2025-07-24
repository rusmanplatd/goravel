package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000039CreateOrganizationsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000039CreateOrganizationsTable) Signature() string {
	return "20250115000039_create_organizations_table"
}

// Up Run the migrations.
func (r *M20250115000039CreateOrganizationsTable) Up() error {
	return facades.Schema().Create("organizations", func(table schema.Blueprint) {
		table.Ulid("id")
		table.String("name")
		table.String("slug").Nullable()
		table.String("domain").Nullable()
		table.Text("description")
		table.String("type").Default("company")
		table.String("industry").Nullable()
		table.String("size").Default("medium")
		table.TimestampTz("founded_at").Nullable()
		table.String("website").Nullable()
		table.String("logo").Nullable()
		table.String("banner").Nullable()
		table.String("contact_email").Nullable()
		table.String("contact_phone").Nullable()
		table.Text("address").Nullable()
		table.Ulid("country_id").Nullable()
		table.Ulid("province_id").Nullable()
		table.Ulid("city_id").Nullable()
		table.Ulid("district_id").Nullable()
		table.String("postal_code").Nullable()
		table.Boolean("is_active").Default(true)
		table.Boolean("is_verified").Default(false)
		table.TimestampTz("verified_at").Nullable()
		table.Json("settings")
		table.Ulid("parent_organization_id").Nullable()
		table.Integer("level").Default(0)
		table.String("path")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("name")
		table.Index("type")
		table.Index("industry")
		table.Index("size")
		table.Index("is_active")
		table.Index("is_verified")
		table.Index("level")
		table.Index("parent_organization_id")

		// Add foreign key constraints
		table.Foreign("country_id").References("id").On("countries")
		table.Foreign("province_id").References("id").On("provinces")
		table.Foreign("city_id").References("id").On("cities")
		table.Foreign("district_id").References("id").On("districts")
		table.Foreign("parent_organization_id").References("id").On("organizations")
	})
}

// Down Reverse the migrations.
func (r *M20250115000039CreateOrganizationsTable) Down() error {
	return facades.Schema().DropIfExists("organizations")
}
