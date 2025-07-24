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
		table.Ulid("id")
		table.String("name")
		table.Text("description")
		table.String("color").Nullable()
		table.Integer("position")
		table.String("status_filter").Nullable()
		table.Integer("task_limit").Default(0)
		table.Boolean("is_active").Default(true)
		table.Ulid("board_id")
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

		// Add foreign key constraints
		table.Foreign("board_id").References("id").On("task_boards")
	})
}

// Down Reverse the migrations.
func (r *M20250115000057CreateTaskBoardColumnsTable) Down() error {
	return facades.Schema().DropIfExists("task_board_columns")
}
