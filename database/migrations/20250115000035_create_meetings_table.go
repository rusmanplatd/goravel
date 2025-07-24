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
		table.Ulid("id").Comment("Unique meeting identifier")
		table.Ulid("event_id").Comment("Calendar event reference")
		table.String("meeting_type").Comment("Meeting type (video, audio, hybrid)")
		table.String("platform").Comment("Meeting platform (zoom, teams, meet, etc.)")
		table.String("meeting_url").Comment("Meeting URL")
		table.String("meeting_id").Comment("Platform-specific meeting ID")
		table.String("passcode").Comment("Meeting passcode")
		table.Text("meeting_notes").Comment("Pre-meeting notes")
		table.Boolean("record_meeting").Comment("Whether meeting should be recorded")
		table.Boolean("allow_join_before_host").Comment("Whether participants can join before host")
		table.Boolean("mute_participants_on_entry").Comment("Whether participants are muted on entry")
		table.String("waiting_room").Comment("Waiting room settings")
		table.TimestampTz("started_at").Nullable().Comment("When meeting actually started")
		table.TimestampTz("ended_at").Nullable().Comment("When meeting actually ended")
		table.String("recording_url").Comment("Recording URL")
		table.String("status").Comment("Meeting status (scheduled, in_progress, completed, cancelled)")
		table.Boolean("has_conflicts").Comment("Whether meeting has scheduling conflicts")
		table.String("conflict_details").Comment("Conflict details")
		table.Integer("attendance_count").Comment("Number of attendees")
		table.Text("meeting_minutes").Comment("Meeting minutes/notes")
		table.Ulid("created_by").Comment("Meeting creator reference")
		table.Ulid("updated_by").Comment("Meeting updater reference")
		table.Ulid("deleted_by").Nullable().Comment("Meeting deleter reference")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Foreign key
		table.Foreign("event_id").References("id").On("calendar_events")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")

		// Add indexes
		table.Index("event_id")
		table.Index("meeting_type")
		table.Index("platform")
		table.Index("started_at")
		table.Index("ended_at")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")
	})
}

// Down Reverse the migrations.
func (r *M20250115000035CreateMeetingsTable) Down() error {
	return facades.Schema().DropIfExists("meetings")
}
