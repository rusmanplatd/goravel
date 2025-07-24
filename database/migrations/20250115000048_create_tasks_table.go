package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000048CreateTasksTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000048CreateTasksTable) Signature() string {
	return "20250115000048_create_tasks_table"
}

// Up Run the migrations.
func (r *M20250115000048CreateTasksTable) Up() error {
	return facades.Schema().Create("tasks", func(table schema.Blueprint) {
		table.Ulid("id")
		table.String("title")
		table.Text("description")
		table.Integer("number")
		table.String("status").Default("todo")
		table.String("priority").Default("medium")
		table.String("type").Default("task")
		table.String("color").Nullable()
		table.String("icon").Nullable()
		table.Boolean("is_active").Default(true)
		table.Boolean("is_archived").Default(false)
		table.Ulid("project_id")
		table.Ulid("created_by")
		table.Ulid("assignee_id").Nullable()
		table.Ulid("reviewer_id").Nullable()
		table.Ulid("milestone_id").Nullable()
		table.Ulid("parent_task_id").Nullable()
		table.TimestampTz("start_date").Nullable()
		table.TimestampTz("due_date").Nullable()
		table.Float("estimated_hours").Default(0)
		table.Float("actual_hours").Default(0)
		table.Float("progress").Default(0)
		table.Integer("position").Default(0)
		table.Json("settings")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("title")
		table.Index("number")
		table.Index("status")
		table.Index("priority")
		table.Index("type")
		table.Index("is_active")
		table.Index("is_archived")
		table.Index("project_id")
		table.Index("created_by")
		table.Index("assignee_id")
		table.Index("reviewer_id")
		table.Index("milestone_id")
		table.Index("parent_task_id")
		table.Index("start_date")
		table.Index("due_date")
		table.Index("position")

		// Add foreign key constraints
		table.Foreign("project_id").References("id").On("projects")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("assignee_id").References("id").On("users")
		table.Foreign("reviewer_id").References("id").On("users")
		table.Foreign("parent_task_id").References("id").On("tasks")
	})
}

// Down Reverse the migrations.
func (r *M20250115000048CreateTasksTable) Down() error {
	return facades.Schema().DropIfExists("tasks")
}
