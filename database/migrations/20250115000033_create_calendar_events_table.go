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
		table.Ulid("id").Comment("Unique event identifier")
		table.String("title").Comment("Event title")
		table.Text("description").Comment("Event description")
		table.TimestampTz("start_time").Comment("Event start time")
		table.TimestampTz("end_time").Comment("Event end time")
		table.String("location").Comment("Event location")
		table.String("color").Comment("Event color for calendar display")
		table.String("type").Comment("Event type (meeting, appointment, reminder, etc.)")
		table.Boolean("is_all_day").Comment("Whether event is all-day")
		table.Boolean("is_recurring").Comment("Whether event is recurring")
		table.String("recurrence_rule").Comment("Recurrence rule (RRULE format)")
		table.TimestampTz("recurrence_until").Nullable().Comment("Recurrence end date")
		table.String("timezone").Comment("Event timezone")
		table.String("status").Comment("Event status (confirmed, tentative, cancelled)")
		table.String("reminder_settings").Comment("Reminder settings as JSON")
		table.Boolean("reminders_sent").Comment("Whether reminders were sent")
		table.TimestampTz("reminders_sent_at").Nullable().Comment("When reminders were sent")
		table.Ulid("tenant_id").Comment("Tenant reference")
		table.Ulid("parent_event_id").Nullable().Comment("Parent recurring event reference")
		table.Ulid("created_by").Comment("Event creator reference")
		table.Ulid("updated_by").Comment("Event updater reference")
		table.Ulid("deleted_by").Nullable().Comment("Event deleter reference")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("tenant_id")
		table.Index("parent_event_id")
		table.Index("start_time")
		table.Index("end_time")
		table.Index("type")
		table.Index("status")
		table.Index("is_recurring")
		table.Index("tenant_id", "start_time")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add Foreign
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
		table.Foreign("tenant_id").References("id").On("tenants")
		table.Foreign("parent_event_id").References("id").On("calendar_events")
	})
}

// Down Reverse the migrations.
func (r *M20250115000033CreateCalendarEventsTable) Down() error {
	return facades.Schema().DropIfExists("calendar_events")
}
