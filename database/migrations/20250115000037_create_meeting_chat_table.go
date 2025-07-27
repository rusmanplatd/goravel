package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000037CreateMeetingChatTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000037CreateMeetingChatTable) Signature() string {
	return "20250115000037_create_meeting_chat_table"
}

// Up Run the migrations.
func (r *M20250115000037CreateMeetingChatTable) Up() error {
	return facades.Schema().Create("meeting_chat", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique message identifier")
		table.Ulid("meeting_id").Comment("Meeting reference")
		table.Ulid("sender_id").Comment("Message sender reference")
		table.Ulid("recipient_id").Nullable().Comment("Private message recipient (null for public)")
		table.String("message_type").Comment("Message type (text, file, reaction, system)")
		table.Text("content").Comment("Message content")
		table.Text("metadata").Comment("Message metadata as JSON")
		table.String("file_url").Comment("File URL for file messages")
		table.String("file_name").Comment("Original file name")
		table.String("file_type").Comment("File MIME type")
		table.Integer("file_size").Comment("File size in bytes")
		table.Boolean("is_private").Comment("Whether message is private")
		table.Boolean("is_system").Comment("Whether message is system generated")
		table.Boolean("is_edited").Comment("Whether message has been edited")
		table.TimestampTz("edited_at").Nullable().Comment("When message was last edited")
		table.String("status").Comment("Message status (sent, delivered, read)")
		table.TimestampTz("read_at").Nullable().Comment("When message was read")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("Message creator reference")
		table.Ulid("updated_by").Comment("Message updater reference")
		table.Ulid("deleted_by").Nullable().Comment("Message deleter reference")

		// Primary key
		table.Primary("id")

		// Foreign keys
		table.Foreign("meeting_id").References("id").On("meetings")
		table.Foreign("sender_id").References("id").On("users")
		table.Foreign("recipient_id").References("id").On("users")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")

		// Add indexes
		table.Index("meeting_id")
		table.Index("sender_id")
		table.Index("recipient_id")
		table.Index("message_type")
		table.Index("is_private")
		table.Index("is_system")
		table.Index("status")
		table.Index("created_at")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")
	})
}

// Down Reverse the migrations.
func (r *M20250115000037CreateMeetingChatTable) Down() error {
	return facades.Schema().DropIfExists("meeting_chat")
}
