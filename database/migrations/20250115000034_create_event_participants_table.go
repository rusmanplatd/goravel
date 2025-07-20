package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000034CreateEventParticipantsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000034CreateEventParticipantsTable) Signature() string {
	return "20250115000034_create_event_participants_table"
}

// Up Run the migrations.
func (r *M20250115000034CreateEventParticipantsTable) Up() error {
	return facades.Schema().Create("event_participants", func(table schema.Blueprint) {
		table.Ulid("id")
		table.Ulid("event_id")
		table.Ulid("user_id")
		table.String("role")
		table.String("response_status")
		table.TimestampTz("responded_at")
		table.Text("response_comment")
		table.Boolean("is_required")
		table.Boolean("send_reminder")
		table.TimestampTz("reminder_sent_at")
		table.TimestampsTz()

		// Primary key
		table.Primary("id")

		// Unique constraint
		table.Unique("event_id", "user_id")

		// Add indexes
		table.Index("event_id")
		table.Index("user_id")
		table.Index("response_status")
		table.Index("role")
		table.Index("event_id", "response_status")
		table.Index("user_id", "response_status")
	})
}

// Down Reverse the migrations.
func (r *M20250115000034CreateEventParticipantsTable) Down() error {
	return facades.Schema().DropIfExists("event_participants")
}
