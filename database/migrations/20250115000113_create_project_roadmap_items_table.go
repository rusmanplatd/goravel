package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000113CreateProjectRoadmapItemsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000113CreateProjectRoadmapItemsTable) Signature() string {
	return "20250115000113_create_project_roadmap_items_table"
}

// Up Run the migrations.
func (r *M20250115000113CreateProjectRoadmapItemsTable) Up() error {
	return facades.Schema().Create("project_roadmap_items", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique roadmap item identifier")
		table.String("title").Comment("Roadmap item title")
		table.Text("description").Comment("Roadmap item description")
		table.String("type").Comment("Item type (milestone, epic, feature, release)")
		table.String("status").Default("planned").Comment("Item status (planned, in_progress, completed, cancelled)")
		table.TimestampTz("start_date").Nullable().Comment("Item start date")
		table.TimestampTz("target_date").Nullable().Comment("Item target date")
		table.TimestampTz("completed_at").Nullable().Comment("Item completion date")
		table.Float("progress").Default(0).Comment("Item progress percentage")
		table.String("color").Nullable().Comment("Item color for visualization")
		table.Integer("position").Default(0).Comment("Item position on roadmap")
		table.Ulid("project_id").Comment("Project reference")
		table.Ulid("parent_id").Nullable().Comment("Parent roadmap item reference")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("title")
		table.Index("type")
		table.Index("status")
		table.Index("start_date")
		table.Index("target_date")
		table.Index("completed_at")
		table.Index("position")
		table.Index("project_id")
		table.Index("parent_id")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add foreign key constraints
		table.Foreign("project_id").References("id").On("projects")
		table.Foreign("parent_id").References("id").On("project_roadmap_items")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000113CreateProjectRoadmapItemsTable) Down() error {
	return facades.Schema().DropIfExists("project_roadmap_items")
}
