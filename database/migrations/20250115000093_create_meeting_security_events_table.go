package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000093CreateMeetingSecurityEventsTable struct{}

// Signature The name and signature of the migration.
func (receiver *M20250115000093CreateMeetingSecurityEventsTable) Signature() string {
	return "20250115000093_create_meeting_security_events_table"
}

// Up Run the migrations.
func (receiver *M20250115000093CreateMeetingSecurityEventsTable) Up() error {
	return facades.Schema().Create("meeting_security_events", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique security event identifier")
		table.Ulid("meeting_id").Comment("Meeting reference")
		table.Ulid("user_id").Nullable().Comment("User who triggered the event")
		table.String("event_type").Comment("Type of security event")
		table.String("severity").Comment("Event severity (info, warning, error, critical)")
		table.String("description").Comment("Human-readable description")
		table.Text("details").Nullable().Comment("Additional event details as JSON")
		table.String("ip_address").Nullable().Comment("IP address of the user")
		table.String("user_agent").Nullable().Comment("User agent string")
		table.Text("device_info").Nullable().Comment("Device information as JSON")
		table.String("action_taken").Nullable().Comment("Action taken in response to event")
		table.Boolean("requires_attention").Comment("Whether event requires admin attention")
		table.Ulid("resolved_by").Nullable().Comment("Admin who resolved the event")
		table.TimestampTz("resolved_at").Nullable().Comment("When event was resolved")
		table.Text("resolution_notes").Nullable().Comment("Notes about resolution")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Indexes
		table.Index("meeting_id")
		table.Index("user_id")
		table.Index("event_type")
		table.Index("severity")
		table.Index("requires_attention")
		table.Index("created_at")

		// Foreign keys
		table.Foreign("meeting_id").References("id").On("calendar_events")
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("resolved_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (receiver *M20250115000093CreateMeetingSecurityEventsTable) Down() error {
	return facades.Schema().DropIfExists("meeting_security_events")
}
