package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000024CreateMessageReadsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000024CreateMessageReadsTable) Signature() string {
	return "20250115000024_create_message_reads_table"
}

// Up Run the migrations.
func (r *M20250115000024CreateMessageReadsTable) Up() error {
	return facades.Schema().Create("message_reads", func(table schema.Blueprint) {
		table.Ulid("id")
		table.Ulid("message_id")
		table.Ulid("user_id")
		table.Timestamp("read_at")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("message_id")
		table.Index("user_id")
		table.Index("read_at")
		table.Index("message_id", "user_id")
	})
}

// Down Reverse the migrations.
func (r *M20250115000024CreateMessageReadsTable) Down() error {
	return facades.Schema().DropIfExists("message_reads")
}
