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
		table.Ulid("id")
		table.Ulid("chat_room_id")
		table.Ulid("invited_user_id")
		table.Ulid("inviter_id")
		table.String("status")
		table.Text("message")
		table.Timestamp("expires_at")
		table.Timestamp("responded_at")
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
