package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000022CreateChatRoomMembersTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000022CreateChatRoomMembersTable) Signature() string {
	return "20250115000022_create_chat_room_members_table"
}

// Up Run the migrations.
func (r *M20250115000022CreateChatRoomMembersTable) Up() error {
	return facades.Schema().Create("chat_room_members", func(table schema.Blueprint) {
		table.Ulid("id")
		table.Ulid("chat_room_id")
		table.Ulid("user_id")
		table.String("role")
		table.Boolean("is_active")
		table.Timestamp("joined_at")
		table.Timestamp("last_read_at")
		table.Text("public_key")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("chat_room_id")
		table.Index("user_id")
		table.Index("role")
		table.Index("last_read_at")
		table.Index("chat_room_id", "user_id")
		table.Index("chat_room_id", "is_active")
	})
}

// Down Reverse the migrations.
func (r *M20250115000022CreateChatRoomMembersTable) Down() error {
	return facades.Schema().DropIfExists("chat_room_members")
}
