package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000053CreateTaskActivitiesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000053CreateTaskActivitiesTable) Signature() string {
	return "20250115000053_create_task_activities_table"
}

// Up Run the migrations.
func (r *M20250115000053CreateTaskActivitiesTable) Up() error {
	return facades.Schema().Create("task_activities", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique activity identifier")
		table.String("type").Comment("Activity type (created, updated, assigned, commented, etc.)")
		table.Text("description").Comment("Activity description")
		table.Ulid("task_id").Comment("Task reference")
		table.Ulid("user_id").Comment("User who performed the activity")
		table.Json("data").Comment("Additional activity data")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("type")
		table.Index("task_id")
		table.Index("user_id")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add foreign key constraints
		table.Foreign("task_id").References("id").On("tasks")
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000053CreateTaskActivitiesTable) Down() error {
	return facades.Schema().DropIfExists("task_activities")
}
