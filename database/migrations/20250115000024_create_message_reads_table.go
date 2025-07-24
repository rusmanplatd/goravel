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
		table.Ulid("id").Comment("Unique read record identifier")
		table.Ulid("message_id").Comment("Message reference")
		table.Ulid("user_id").Comment("User reference")
		table.Timestamp("read_at").Comment("When message was read")
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("message_id")
		table.Index("user_id")
		table.Index("read_at")
		table.Index("message_id", "user_id")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add foreign key constraints
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000024CreateMessageReadsTable) Down() error {
	return facades.Schema().DropIfExists("message_reads")
}
