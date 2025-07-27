package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000100CreateProjectViewsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000100CreateProjectViewsTable) Signature() string {
	return "20250115000100_create_project_views_table"
}

// Up Run the migrations.
func (r *M20250115000100CreateProjectViewsTable) Up() error {
	return facades.Schema().Create("project_views", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique view identifier")
		table.String("name").Comment("View name")
		table.Text("description").Comment("View description")
		table.String("type").Comment("View type (table, board, roadmap, timeline)")
		table.Json("layout").Comment("View layout settings")
		table.Json("filters").Comment("View filters")
		table.Json("sorting").Comment("View sorting configuration")
		table.Json("grouping").Comment("View grouping configuration")
		table.Boolean("is_default").Default(false).Comment("Whether view is default")
		table.Boolean("is_public").Default(true).Comment("Whether view is public")
		table.Integer("position").Default(0).Comment("View position/order")
		table.Ulid("project_id").Comment("Project reference")
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
		table.Index("is_default")
		table.Index("is_public")
		table.Index("position")
		table.Index("project_id")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add foreign key constraints
		table.Foreign("project_id").References("id").On("projects")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000100CreateProjectViewsTable) Down() error {
	return facades.Schema().DropIfExists("project_views")
}
