package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000025CreateChatRoomKeysTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000025CreateChatRoomKeysTable) Signature() string {
	return "20250115000025_create_chat_room_keys_table"
}

// Up Run the migrations.
func (r *M20250115000025CreateChatRoomKeysTable) Up() error {
	return facades.Schema().Create("chat_room_keys", func(table schema.Blueprint) {
		table.Ulid("id")
		table.Ulid("chat_room_id")
		table.String("key_type")
		table.Text("encrypted_key")
		table.Integer("version")
		table.Boolean("is_active")
		table.Timestamp("rotated_at")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("chat_room_id")
		table.Index("key_type")
		table.Index("version")
		table.Index("is_active")
		table.Index("chat_room_id", "key_type")
		table.Index("chat_room_id", "is_active")
	})
}

// Down Reverse the migrations.
func (r *M20250115000025CreateChatRoomKeysTable) Down() error {
	return facades.Schema().DropIfExists("chat_room_keys")
}
