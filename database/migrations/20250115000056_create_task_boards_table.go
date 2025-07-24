package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000056CreateTaskBoardsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000056CreateTaskBoardsTable) Signature() string {
	return "20250115000056_create_task_boards_table"
}

// Up Run the migrations.
func (r *M20250115000056CreateTaskBoardsTable) Up() error {
	return facades.Schema().Create("task_boards", func(table schema.Blueprint) {
		table.Ulid("id")
		table.String("name")
		table.Text("description")
		table.String("type").Default("kanban")
		table.String("color").Nullable()
		table.String("icon").Nullable()
		table.Boolean("is_active").Default(true)
		table.Boolean("is_default").Default(false)
		table.Ulid("project_id")
		table.Ulid("created_by")
		table.Json("settings")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("name")
		table.Index("type")
		table.Index("is_active")
		table.Index("is_default")
		table.Index("project_id")
		table.Index("created_by")

		// Add foreign key constraints
		table.Foreign("project_id").References("id").On("projects")
		table.Foreign("created_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000056CreateTaskBoardsTable) Down() error {
	return facades.Schema().DropIfExists("task_boards")
}
