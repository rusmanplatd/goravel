package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000030CreateMessageThreadsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000030CreateMessageThreadsTable) Signature() string {
	return "20250115000030_create_message_threads_table"
}

// Up Run the migrations.
func (r *M20250115000030CreateMessageThreadsTable) Up() error {
	return facades.Schema().Create("message_threads", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique thread identifier")
		table.Ulid("chat_room_id").Comment("Chat room reference")
		table.Ulid("root_message_id").Comment("Root message that started the thread")
		table.String("title").Comment("Thread title")
		table.Integer("message_count").Default(0).Comment("Number of messages in thread")
		table.Timestamp("last_activity_at").Comment("Last activity timestamp")
		table.Boolean("is_resolved").Default(false).Comment("Whether thread is resolved")
		table.Ulid("resolved_by").Nullable().Comment("User who resolved the thread")
		table.Timestamp("resolved_at").Nullable().Comment("When thread was resolved")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("chat_room_id")
		table.Index("root_message_id")
		table.Index("is_resolved")
		table.Index("last_activity_at")
		table.Index("chat_room_id", "is_resolved")
	})
}

// Down Reverse the migrations.
func (r *M20250115000030CreateMessageThreadsTable) Down() error {
	return facades.Schema().DropIfExists("message_threads")
}
