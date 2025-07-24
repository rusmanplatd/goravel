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
		table.Ulid("id")
		table.String("type")
		table.Text("description")
		table.Ulid("task_id")
		table.Ulid("user_id")
		table.Json("data")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("type")
		table.Index("task_id")
		table.Index("user_id")

		// Add foreign key constraints
		table.Foreign("task_id").References("id").On("tasks")
		table.Foreign("user_id").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000053CreateTaskActivitiesTable) Down() error {
	return facades.Schema().DropIfExists("task_activities")
}
