package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000033CreateCalendarEventsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000033CreateCalendarEventsTable) Signature() string {
	return "20250115000033_create_calendar_events_table"
}

// Up Run the migrations.
func (r *M20250115000033CreateCalendarEventsTable) Up() error {
	return facades.Schema().Create("calendar_events", func(table schema.Blueprint) {
		table.Ulid("id")
		table.String("title")
		table.Text("description")
		table.TimestampTz("start_time")
		table.TimestampTz("end_time")
		table.String("location")
		table.String("color")
		table.String("type")
		table.Boolean("is_all_day")
		table.Boolean("is_recurring")
		table.String("recurrence_rule")
		table.TimestampTz("recurrence_until")
		table.String("timezone")
		table.String("status")
		table.String("reminder_settings")
		table.Boolean("reminders_sent")
		table.TimestampTz("reminders_sent_at")
		table.Ulid("tenant_id")
		table.Ulid("created_by")
		table.Ulid("parent_event_id")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("tenant_id")
		table.Index("created_by")
		table.Index("parent_event_id")
		table.Index("start_time")
		table.Index("end_time")
		table.Index("type")
		table.Index("status")
		table.Index("is_recurring")
		table.Index("tenant_id", "start_time")
		table.Index("tenant_id", "created_by")
	})
}

// Down Reverse the migrations.
func (r *M20250115000033CreateCalendarEventsTable) Down() error {
	return facades.Schema().DropIfExists("calendar_events")
}
