package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000104CreateTaskAttachmentsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000104CreateTaskAttachmentsTable) Signature() string {
	return "20250115000104_create_task_attachments_table"
}

// Up Run the migrations.
func (r *M20250115000104CreateTaskAttachmentsTable) Up() error {
	return facades.Schema().Create("task_attachments", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique attachment identifier")
		table.String("filename").Comment("Attachment filename")
		table.String("original_filename").Comment("Original filename")
		table.String("file_path").Comment("File path/URL")
		table.BigInteger("file_size").Comment("File size in bytes")
		table.String("mime_type").Comment("MIME type")
		table.Ulid("task_id").Comment("Task reference")
		table.Ulid("uploaded_by").Comment("User who uploaded the attachment")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("filename")
		table.Index("mime_type")
		table.Index("task_id")
		table.Index("uploaded_by")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add foreign key constraints
		table.Foreign("task_id").References("id").On("tasks")
		table.Foreign("uploaded_by").References("id").On("users")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000104CreateTaskAttachmentsTable) Down() error {
	return facades.Schema().DropIfExists("task_attachments")
}
