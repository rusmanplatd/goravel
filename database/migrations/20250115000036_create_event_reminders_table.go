package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000036CreateEventRemindersTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000036CreateEventRemindersTable) Signature() string {
	return "20250115000036_create_event_reminders_table"
}

// Up Run the migrations.
func (r *M20250115000036CreateEventRemindersTable) Up() error {
	return facades.Schema().Create("event_reminders", func(table schema.Blueprint) {
		table.Ulid("id")
		table.Ulid("event_id")
		table.Ulid("user_id")
		table.String("type")
		table.Integer("minutes_before")
		table.TimestampTz("scheduled_at")
		table.Boolean("sent")
		table.TimestampTz("sent_at")
		table.String("status")
		table.String("error_message")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Foreign keys
		table.Foreign("event_id").References("id").On("calendar_events")
		table.Foreign("user_id").References("id").On("users")

		// Add indexes
		table.Index("event_id")
		table.Index("user_id")
		table.Index("type")
		table.Index("status")
		table.Index("scheduled_at")
		table.Index("sent")
		table.Index("event_id", "user_id")
		table.Index("scheduled_at", "sent")
	})
}

// Down Reverse the migrations.
func (r *M20250115000036CreateEventRemindersTable) Down() error {
	return facades.Schema().DropIfExists("event_reminders")
}
