package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000028CreateMessageReactionsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000028CreateMessageReactionsTable) Signature() string {
	return "20250115000028_create_message_reactions_table"
}

// Up Run the migrations.
func (r *M20250115000028CreateMessageReactionsTable) Up() error {
	return facades.Schema().Create("message_reactions", func(table schema.Blueprint) {
		table.Ulid("id")
		table.Ulid("message_id")
		table.Ulid("user_id")
		table.String("emoji")
		table.Timestamp("reacted_at")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("message_id")
		table.Index("user_id")
		table.Index("emoji")
		table.Index("message_id", "user_id", "emoji")
		table.Index("reacted_at")
	})
}

// Down Reverse the migrations.
func (r *M20250115000028CreateMessageReactionsTable) Down() error {
	return facades.Schema().DropIfExists("message_reactions")
}
