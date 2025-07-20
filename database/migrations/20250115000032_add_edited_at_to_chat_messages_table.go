package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000032AddEditedAtToChatMessagesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000032AddEditedAtToChatMessagesTable) Signature() string {
	return "20250115000032_add_edited_at_to_chat_messages_table"
}

// Up Run the migrations.
func (r *M20250115000032AddEditedAtToChatMessagesTable) Up() error {
	return facades.Schema().Table("chat_messages", func(table schema.Blueprint) {
		table.Timestamp("edited_at").Nullable()
		table.Index("edited_at")
	})
}

// Down Reverse the migrations.
func (r *M20250115000032AddEditedAtToChatMessagesTable) Down() error {
	return facades.Schema().Table("chat_messages", func(table schema.Blueprint) {
		table.DropIndex("edited_at")
		table.DropColumn("edited_at")
	})
}
