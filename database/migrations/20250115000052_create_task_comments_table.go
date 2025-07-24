package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000052CreateTaskCommentsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000052CreateTaskCommentsTable) Signature() string {
	return "20250115000052_create_task_comments_table"
}

// Up Run the migrations.
func (r *M20250115000052CreateTaskCommentsTable) Up() error {
	return facades.Schema().Create("task_comments", func(table schema.Blueprint) {
		table.Ulid("id")
		table.Text("content")
		table.Ulid("task_id")
		table.Ulid("author_id")
		table.Ulid("parent_comment_id").Nullable()
		table.Boolean("is_internal").Default(false)
		table.String("type").Default("comment")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("task_id")
		table.Index("author_id")
		table.Index("parent_comment_id")
		table.Index("is_internal")
		table.Index("type")

		// Add foreign key constraints
		table.Foreign("task_id").References("id").On("tasks")
		table.Foreign("author_id").References("id").On("users")
		table.Foreign("parent_comment_id").References("id").On("task_comments")
	})
}

// Down Reverse the migrations.
func (r *M20250115000052CreateTaskCommentsTable) Down() error {
	return facades.Schema().DropIfExists("task_comments")
}
