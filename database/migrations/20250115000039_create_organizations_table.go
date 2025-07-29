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
		table.Ulid("id").Comment("Unique organization identifier")

		table.String("name").Comment("Organization name")
		table.String("slug").Nullable().Comment("URL-friendly organization identifier")
		table.String("domain").Nullable().Comment("Organization domain")
		table.Text("description").Comment("Organization description")
		table.String("type").Default("company").Comment("Organization type (company, nonprofit, government, etc.)")
		table.String("industry").Nullable().Comment("Organization industry")
		table.String("size").Default("medium").Comment("Organization size (small, medium, large)")
		table.TimestampTz("founded_at").Nullable().Comment("When organization was founded")
		table.String("website").Nullable().Comment("Organization website URL")
		table.String("logo").Nullable().Comment("Organization logo URL")
		table.String("banner").Nullable().Comment("Organization banner URL")
		table.String("contact_email").Nullable().Comment("Primary contact email")
		table.String("contact_phone").Nullable().Comment("Primary contact phone")
		table.Text("address").Nullable().Comment("Organization address")
		table.Ulid("country_id").Nullable().Comment("Country reference")
		table.Ulid("province_id").Nullable().Comment("Province/state reference")
		table.Ulid("city_id").Nullable().Comment("City reference")
		table.Ulid("district_id").Nullable().Comment("District reference")
		table.String("postal_code").Nullable().Comment("Postal/ZIP code")
		table.Boolean("is_active").Default(true).Comment("Whether organization is active")
		table.Boolean("is_verified").Default(false).Comment("Whether organization is verified")
		table.TimestampTz("verified_at").Nullable().Comment("When organization was verified")
		table.Json("settings").Comment("Organization-specific settings")
		table.Ulid("parent_organization_id").Nullable().Comment("Parent organization reference")
		table.Integer("level").Default(0).Comment("Hierarchy level in organization tree")
		table.String("path").Comment("Hierarchical path in organization tree")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

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
