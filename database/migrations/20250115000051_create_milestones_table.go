package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000051CreateMilestonesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000051CreateMilestonesTable) Signature() string {
	return "20250115000051_create_milestones_table"
}

// Up Run the migrations.
func (r *M20250115000051CreateMilestonesTable) Up() error {
	return facades.Schema().Create("milestones", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique milestone identifier")
		table.String("title").Comment("Milestone title")
		table.Text("description").Comment("Milestone description")
		table.String("status").Default("open").Comment("Milestone status (open, in_progress, completed, cancelled)")
		table.String("color").Nullable().Comment("Milestone color for UI display")
		table.String("icon").Nullable().Comment("Milestone icon for UI display")
		table.Ulid("project_id").Comment("Project reference")
		table.TimestampTz("due_date").Nullable().Comment("Milestone due date")
		table.TimestampTz("completed_at").Nullable().Comment("When milestone was completed")
		table.Float("progress").Default(0).Comment("Milestone completion percentage (0-100)")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("title")
		table.Index("status")
		table.Index("project_id")
		table.Index("due_date")
		table.Index("completed_at")
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
func (r *M20250115000051CreateMilestonesTable) Down() error {
	return facades.Schema().DropIfExists("milestones")
}
