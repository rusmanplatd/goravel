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
		table.Ulid("id").Comment("Unique comment identifier")
		table.Text("content").Comment("Comment content")
		table.Ulid("task_id").Comment("Task reference")
		table.Ulid("author_id").Comment("Comment author reference")
		table.Ulid("parent_comment_id").Nullable().Comment("Parent comment reference for replies")
		table.Boolean("is_internal").Default(false).Comment("Whether comment is internal (not visible to external users)")
		table.String("type").Default("comment").Comment("Comment type (comment, review, system)")
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")
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
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add foreign key constraints
		table.Foreign("task_id").References("id").On("tasks")
		table.Foreign("author_id").References("id").On("users")
		table.Foreign("parent_comment_id").References("id").On("task_comments")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000052CreateTaskCommentsTable) Down() error {
	return facades.Schema().DropIfExists("task_comments")
}
