package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000055CreateTaskTimeEntriesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000055CreateTaskTimeEntriesTable) Signature() string {
	return "20250115000055_create_task_time_entries_table"
}

// Up Run the migrations.
func (r *M20250115000055CreateTaskTimeEntriesTable) Up() error {
	return facades.Schema().Create("task_time_entries", func(table schema.Blueprint) {
		table.Ulid("id")
		table.Text("description")
		table.Ulid("task_id")
		table.Ulid("user_id")
		table.TimestampTz("start_time")
		table.TimestampTz("end_time").Nullable()
		table.Float("duration").Default(0)
		table.Boolean("is_billable").Default(true)
		table.Float("rate").Default(0)
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("task_id")
		table.Index("user_id")
		table.Index("start_time")
		table.Index("end_time")
		table.Index("is_billable")

		// Add foreign key constraints
		table.Foreign("task_id").References("id").On("tasks")
		table.Foreign("user_id").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000055CreateTaskTimeEntriesTable) Down() error {
	return facades.Schema().DropIfExists("task_time_entries")
}
