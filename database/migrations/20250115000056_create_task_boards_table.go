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
		table.Ulid("id").Comment("Unique board identifier")
		table.String("name").Comment("Board name")
		table.Text("description").Comment("Board description")
		table.String("type").Default("kanban").Comment("Board type (kanban, scrum, list)")
		table.String("color").Nullable().Comment("Board color for UI display")
		table.String("icon").Nullable().Comment("Board icon for UI display")
		table.Boolean("is_active").Default(true).Comment("Whether board is active")
		table.Boolean("is_default").Default(false).Comment("Whether board is the default board")
		table.Ulid("project_id").Comment("Project reference")
		table.Json("settings").Comment("Board-specific settings")
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")
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
func (r *M20250115000056CreateTaskBoardsTable) Down() error {
	return facades.Schema().DropIfExists("task_boards")
}
