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
		table.Ulid("id").Comment("Unique key identifier")
		table.Ulid("chat_room_id").Comment("Chat room reference")
		table.String("key_type").Comment("Key type (message, room, etc.)")
		table.Text("encrypted_key").Comment("Encrypted key data")
		table.Integer("version").Comment("Key version number")
		table.Boolean("is_active").Comment("Whether key is currently active")
		table.Timestamp("rotated_at").Comment("When key was last rotated")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("chat_room_id")
		table.Index("key_type")
		table.Index("version")
		table.Index("is_active")
		table.Index("chat_room_id", "key_type")
		table.Index("chat_room_id", "is_active")
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
func (r *M20250115000025CreateChatRoomKeysTable) Down() error {
	return facades.Schema().DropIfExists("chat_room_keys")
}
