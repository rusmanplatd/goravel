package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000035CreateMeetingsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000035CreateMeetingsTable) Signature() string {
	return "20250115000035_create_meetings_table"
}

// Up Run the migrations.
func (r *M20250115000035CreateMeetingsTable) Up() error {
	return facades.Schema().Create("meetings", func(table schema.Blueprint) {
		table.Ulid("id")
		table.Ulid("event_id")
		table.String("meeting_type")
		table.String("platform")
		table.String("meeting_url")
		table.String("meeting_id")
		table.String("passcode")
		table.Text("meeting_notes")
		table.Boolean("record_meeting")
		table.Boolean("allow_join_before_host")
		table.Boolean("mute_participants_on_entry")
		table.String("waiting_room")
		table.TimestampTz("started_at").Nullable()
		table.TimestampTz("ended_at").Nullable()
		table.String("recording_url")
		table.String("status")
		table.Boolean("has_conflicts")
		table.String("conflict_details")
		table.Integer("attendance_count")
		table.Text("meeting_minutes")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Foreign key
		table.Foreign("event_id").References("id").On("calendar_events")

		// Add indexes
		table.Index("event_id")
		table.Index("meeting_type")
		table.Index("platform")
		table.Index("started_at")
		table.Index("ended_at")
	})
}

// Down Reverse the migrations.
func (r *M20250115000035CreateMeetingsTable) Down() error {
	return facades.Schema().DropIfExists("meetings")
}
