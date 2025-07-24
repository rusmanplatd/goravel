package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000023CreateChatMessagesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000023CreateChatMessagesTable) Signature() string {
	return "20250115000023_create_chat_messages_table"
}

// Up Run the migrations.
func (r *M20250115000023CreateChatMessagesTable) Up() error {
	return facades.Schema().Create("chat_messages", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique message identifier")
		table.Ulid("chat_room_id").Comment("Chat room reference")
		table.Ulid("sender_id").Comment("Message sender reference")
		table.String("type").Comment("Message type (text, image, file, system, etc.)")
		table.Text("encrypted_content").Comment("Encrypted message content")
		table.Json("metadata").Comment("Message metadata (file info, reactions, etc.)")
		table.Ulid("reply_to_id").Comment("Reply to message reference")
		table.Boolean("is_edited").Comment("Whether message was edited")
		table.Text("original_content").Comment("Original message content before edit")
		table.String("status").Comment("Message status (sent, delivered, read, failed)")
		table.Integer("encryption_version").Comment("Encryption algorithm version")
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("chat_room_id")
		table.Index("sender_id")
		table.Index("type")
		table.Index("status")
		table.Index("reply_to_id")
		table.Index("encryption_version")
		table.Index("chat_room_id", "created_at")
		table.Index("chat_room_id", "sender_id")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add foreign key constraints
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000023CreateChatMessagesTable) Down() error {
	return facades.Schema().DropIfExists("chat_messages")
}
