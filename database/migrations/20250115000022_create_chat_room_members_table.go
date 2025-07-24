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
		table.Ulid("id").Comment("Unique member identifier")
		table.Ulid("chat_room_id").Comment("Chat room reference")
		table.Ulid("user_id").Comment("User reference")
		table.String("role").Comment("Member role (admin, moderator, member)")
		table.Boolean("is_active").Comment("Whether member is active in the room")
		table.Timestamp("joined_at").Comment("When user joined the room")
		table.Timestamp("last_read_at").Comment("Last message read timestamp")
		table.Text("public_key").Comment("User's public key for encryption")
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
