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
		table.Ulid("id").Comment("Unique reminder identifier")
		table.Ulid("event_id").Comment("Calendar event reference")
		table.Ulid("user_id").Comment("User reference")
		table.String("type").Comment("Reminder type (email, push, sms, etc.)")
		table.Integer("minutes_before").Comment("Minutes before event to send reminder")
		table.TimestampTz("scheduled_at").Comment("When reminder is scheduled to be sent")
		table.Boolean("sent").Comment("Whether reminder was sent")
		table.TimestampTz("sent_at").Nullable().Comment("When reminder was actually sent")
		table.String("status").Comment("Reminder status (pending, sent, failed)")
		table.String("error_message").Comment("Error message if reminder failed")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Foreign keys
		table.Foreign("event_id").References("id").On("calendar_events")
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")

		// Add indexes
		table.Index("event_id")
		table.Index("user_id")
		table.Index("type")
		table.Index("status")
		table.Index("scheduled_at")
		table.Index("sent")
		table.Index("event_id", "user_id")
		table.Index("scheduled_at", "sent")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")
	})
}

// Down Reverse the migrations.
func (r *M20250115000036CreateEventRemindersTable) Down() error {
	return facades.Schema().DropIfExists("event_reminders")
}
