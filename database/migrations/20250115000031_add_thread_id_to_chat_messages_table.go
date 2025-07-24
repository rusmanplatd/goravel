package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000031AddThreadIdToChatMessagesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000031AddThreadIdToChatMessagesTable) Signature() string {
	return "20250115000031_add_thread_id_to_chat_messages_table"
}

// Up Run the migrations.
func (r *M20250115000031AddThreadIdToChatMessagesTable) Up() error {
	return facades.Schema().Table("chat_messages", func(table schema.Blueprint) {
		table.Ulid("thread_id").Nullable().Comment("Message thread reference")
		table.Index("thread_id")
		table.Index("thread_id", "created_at")
	})
}

// Down Reverse the migrations.
func (r *M20250115000031AddThreadIdToChatMessagesTable) Down() error {
	return facades.Schema().Table("chat_messages", func(table schema.Blueprint) {
		table.DropIndex("thread_id")
		table.DropIndex("thread_id", "created_at")
		table.DropColumn("thread_id")
	})
}
