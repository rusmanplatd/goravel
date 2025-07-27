package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000105CreateProjectTemplatesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000105CreateProjectTemplatesTable) Signature() string {
	return "20250115000105_create_project_templates_table"
}

// Up Run the migrations.
func (r *M20250115000105CreateProjectTemplatesTable) Up() error {
	return facades.Schema().Create("project_templates", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique template identifier")
		table.String("name").Comment("Template name")
		table.Text("description").Comment("Template description")
		table.String("category").Default("general").Comment("Template category (development, marketing, design, general)")
		table.String("icon").Nullable().Comment("Template icon")
		table.String("color").Nullable().Comment("Template color")
		table.Boolean("is_public").Default(false).Comment("Whether template is public")
		table.Boolean("is_featured").Default(false).Comment("Whether template is featured")
		table.Json("configuration").Comment("Template configuration (views, fields, workflows)")
		table.Ulid("organization_id").Nullable().Comment("Organization reference (null for system templates)")
		table.Integer("usage_count").Default(0).Comment("Template usage count")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("name")
		table.Index("category")
		table.Index("is_public")
		table.Index("is_featured")
		table.Index("organization_id")
		table.Index("usage_count")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add foreign key constraints
		table.Foreign("organization_id").References("id").On("organizations")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000105CreateProjectTemplatesTable) Down() error {
	return facades.Schema().DropIfExists("project_templates")
}
