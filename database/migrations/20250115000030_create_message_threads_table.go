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
		table.Ulid("id")
		table.Ulid("chat_room_id")
		table.Ulid("root_message_id")
		table.String("title")
		table.Integer("message_count").Default(0)
		table.Timestamp("last_activity_at")
		table.Boolean("is_resolved").Default(false)
		table.Ulid("resolved_by").Nullable()
		table.Timestamp("resolved_at").Nullable()
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
