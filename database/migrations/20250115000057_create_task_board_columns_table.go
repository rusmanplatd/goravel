package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000057CreateTaskBoardColumnsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000057CreateTaskBoardColumnsTable) Signature() string {
	return "20250115000057_create_task_board_columns_table"
}

// Up Run the migrations.
func (r *M20250115000057CreateTaskBoardColumnsTable) Up() error {
	return facades.Schema().Create("task_board_columns", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique column identifier")
		table.String("name").Comment("Column name")
		table.Text("description").Comment("Column description")
		table.String("color").Nullable().Comment("Column color for UI display")
		table.Integer("position").Comment("Column position in board")
		table.String("status_filter").Nullable().Comment("Status filter for this column")
		table.Integer("task_limit").Default(0).Comment("Maximum number of tasks in column (0 = unlimited)")
		table.Boolean("is_active").Default(true).Comment("Whether column is active")
		table.Ulid("board_id").Comment("Board reference")
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("name")
		table.Index("position")
		table.Index("status_filter")
		table.Index("is_active")
		table.Index("board_id")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add foreign key constraints
		table.Foreign("board_id").References("id").On("task_boards")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000057CreateTaskBoardColumnsTable) Down() error {
	return facades.Schema().DropIfExists("task_board_columns")
}
