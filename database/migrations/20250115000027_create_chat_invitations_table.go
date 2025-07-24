package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000027CreateChatInvitationsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000027CreateChatInvitationsTable) Signature() string {
	return "20250115000027_create_chat_invitations_table"
}

// Up Run the migrations.
func (r *M20250115000027CreateChatInvitationsTable) Up() error {
	return facades.Schema().Create("chat_invitations", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique invitation identifier")
		table.Ulid("chat_room_id").Comment("Chat room reference")
		table.Ulid("invited_user_id").Comment("Invited user reference")
		table.Ulid("inviter_id").Comment("User who sent the invitation")
		table.String("status").Comment("Invitation status (pending, accepted, declined, expired)")
		table.Text("message").Comment("Invitation message")
		table.Timestamp("expires_at").Comment("Invitation expiration timestamp")
		table.Timestamp("responded_at").Comment("When invitation was responded to")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("chat_room_id")
		table.Index("invited_user_id")
		table.Index("inviter_id")
		table.Index("status")
		table.Index("expires_at")
		table.Index("chat_room_id", "invited_user_id")
		table.Index("invited_user_id", "status")
	})
}

// Down Reverse the migrations.
func (r *M20250115000027CreateChatInvitationsTable) Down() error {
	return facades.Schema().DropIfExists("chat_invitations")
}
