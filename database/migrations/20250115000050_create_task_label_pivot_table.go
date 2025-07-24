package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000050CreateTaskLabelPivotTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000050CreateTaskLabelPivotTable) Signature() string {
	return "20250115000050_create_task_label_pivot_table"
}

// Up Run the migrations.
func (r *M20250115000050CreateTaskLabelPivotTable) Up() error {
	return facades.Schema().Create("task_label_pivot", func(table schema.Blueprint) {
		table.Ulid("task_id").Comment("Task reference")
		table.Ulid("label_id").Comment("Label reference")
		table.TimestampTz("added_at").Comment("When label was added to task")
		table.Ulid("added_by").Comment("User who added the label")

		// Primary key
		table.Primary("task_id", "label_id")

		// Add indexes
		table.Index("task_id")
		table.Index("label_id")
		table.Index("added_at")
		table.Index("added_by")

		// Add foreign key constraints
		table.Foreign("task_id").References("id").On("tasks")
		table.Foreign("label_id").References("id").On("task_labels")
		table.Foreign("added_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000050CreateTaskLabelPivotTable) Down() error {
	return facades.Schema().DropIfExists("task_label_pivot")
}
