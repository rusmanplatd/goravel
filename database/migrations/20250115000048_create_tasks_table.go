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
		table.Ulid("id").Comment("Unique task identifier")
		table.String("title").Comment("Task title")
		table.Text("description").Comment("Task description")
		table.Integer("number").Comment("Task number within project")
		table.String("status").Default("todo").Comment("Task status (todo, in_progress, review, done, etc.)")
		table.String("priority").Default("medium").Comment("Task priority (low, medium, high, urgent)")
		table.String("type").Default("task").Comment("Task type (task, bug, feature, story, etc.)")
		table.String("color").Nullable().Comment("Task color for UI display")
		table.String("icon").Nullable().Comment("Task icon for UI display")
		table.Boolean("is_active").Default(true).Comment("Whether task is active")
		table.Boolean("is_archived").Default(false).Comment("Whether task is archived")
		table.Ulid("project_id").Comment("Project reference")
		table.Ulid("assignee_id").Nullable().Comment("Task assignee reference")
		table.Ulid("reviewer_id").Nullable().Comment("Task reviewer reference")
		table.Ulid("milestone_id").Nullable().Comment("Milestone reference")
		table.Ulid("parent_task_id").Nullable().Comment("Parent task reference for subtasks")
		table.TimestampTz("start_date").Nullable().Comment("Task start date")
		table.TimestampTz("due_date").Nullable().Comment("Task due date")
		table.Float("estimated_hours").Default(0).Comment("Estimated hours to complete")
		table.Float("actual_hours").Default(0).Comment("Actual hours spent")
		table.Float("progress").Default(0).Comment("Task completion percentage (0-100)")
		table.Integer("position").Default(0).Comment("Task position in list/board")
		table.Json("settings").Comment("Task-specific settings")
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")
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
		table.Index("assignee_id")
		table.Index("reviewer_id")
		table.Index("milestone_id")
		table.Index("parent_task_id")
		table.Index("start_date")
		table.Index("due_date")
		table.Index("position")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add foreign key constraints
		table.Foreign("project_id").References("id").On("projects")
		table.Foreign("assignee_id").References("id").On("users")
		table.Foreign("reviewer_id").References("id").On("users")
		table.Foreign("parent_task_id").References("id").On("tasks")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000048CreateTasksTable) Down() error {
	return facades.Schema().DropIfExists("tasks")
}
