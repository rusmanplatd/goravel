package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000089CreateFileCommentsTable struct{}

// Signature The unique signature for the migration.
func (r *M20250115000089CreateFileCommentsTable) Signature() string {
	return "20250115000089_create_file_comments_table"
}

// Up Run the migrations.
func (r *M20250115000089CreateFileCommentsTable) Up() error {
	return facades.Schema().Create("file_comments", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique comment identifier")

		// Comment content
		table.Text("content").Comment("Comment content")
		table.Boolean("is_resolved").Default(false).Comment("Whether comment is resolved")
		table.TimestampTz("resolved_at").Nullable().Comment("When comment was resolved")
		table.Json("position").Nullable().Comment("Comment position/anchor (for document comments)")

		// Relationships
		table.Ulid("file_id").Comment("File ID the comment belongs to")
		table.Ulid("author_id").Comment("User who created the comment")
		table.Ulid("parent_id").Nullable().Comment("Parent comment ID (for replies)")
		table.Ulid("resolved_by_id").Nullable().Comment("User who resolved the comment")

		// Timestamps
		table.TimestampsTz()

		// Indexes
		table.Index("file_id")
		table.Index("author_id")
		table.Index("parent_id")
		table.Index("resolved_by_id")
		table.Index("is_resolved")
		table.Index("created_at")

		// Foreign key constraints
		table.Foreign("file_id").References("id").On("files")
		table.Foreign("author_id").References("id").On("users")
		table.Foreign("parent_id").References("id").On("file_comments")
		table.Foreign("resolved_by_id").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000089CreateFileCommentsTable) Down() error {
	return facades.Schema().DropIfExists("file_comments")
}
