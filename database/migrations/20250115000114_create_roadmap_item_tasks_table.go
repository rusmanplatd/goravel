package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000114CreateRoadmapItemTasksTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000114CreateRoadmapItemTasksTable) Signature() string {
	return "20250115000114_create_roadmap_item_tasks_table"
}

// Up Run the migrations.
func (r *M20250115000114CreateRoadmapItemTasksTable) Up() error {
	return facades.Schema().Create("roadmap_item_tasks", func(table schema.Blueprint) {
		table.Ulid("roadmap_item_id").Comment("Roadmap item reference")
		table.Ulid("task_id").Comment("Task reference")
		table.TimestampTz("added_at").Comment("When task was added to roadmap item")
		table.Ulid("added_by").Comment("User who added the relationship")

		// Primary key
		table.Primary("roadmap_item_id", "task_id")

		// Add indexes
		table.Index("roadmap_item_id")
		table.Index("task_id")
		table.Index("added_at")
		table.Index("added_by")

		// Add foreign key constraints
		table.Foreign("roadmap_item_id").References("id").On("project_roadmap_items")
		table.Foreign("task_id").References("id").On("tasks")
		table.Foreign("added_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000114CreateRoadmapItemTasksTable) Down() error {
	return facades.Schema().DropIfExists("roadmap_item_tasks")
}
