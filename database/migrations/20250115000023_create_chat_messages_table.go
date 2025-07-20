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
		table.Ulid("id")
		table.Ulid("chat_room_id")
		table.Ulid("sender_id")
		table.String("type")
		table.Text("encrypted_content")
		table.Json("metadata")
		table.Ulid("reply_to_id")
		table.Boolean("is_edited")
		table.Text("original_content")
		table.String("status")
		table.Integer("encryption_version")
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
	})
}

// Down Reverse the migrations.
func (r *M20250115000023CreateChatMessagesTable) Down() error {
	return facades.Schema().DropIfExists("chat_messages")
}
