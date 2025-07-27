package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000036CreateMeetingParticipantsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000036CreateMeetingParticipantsTable) Signature() string {
	return "20250115000036_create_meeting_participants_table"
}

// Up Run the migrations.
func (r *M20250115000036CreateMeetingParticipantsTable) Up() error {
	return facades.Schema().Create("meeting_participants", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique participant identifier")
		table.Ulid("meeting_id").Comment("Meeting reference")
		table.Ulid("user_id").Comment("User reference")
		table.String("role").Comment("Participant role (host, co-host, presenter, attendee)")
		table.String("status").Comment("Participant status (invited, joined, left, removed)")
		table.Boolean("is_muted").Comment("Whether participant is muted")
		table.Boolean("is_video_enabled").Comment("Whether participant has video enabled")
		table.Boolean("is_screen_sharing").Comment("Whether participant is screen sharing")
		table.Boolean("is_hand_raised").Comment("Whether participant has hand raised")
		table.Boolean("is_in_waiting_room").Comment("Whether participant is in waiting room")
		table.Boolean("is_recording_consent_given").Comment("Whether participant consented to recording")
		table.String("connection_id").Comment("WebSocket connection ID")
		table.String("device_type").Comment("Device type (desktop, mobile, tablet)")
		table.String("browser_info").Comment("Browser information")
		table.String("ip_address").Comment("IP address")
		table.TimestampTz("joined_at").Nullable().Comment("When participant joined")
		table.TimestampTz("left_at").Nullable().Comment("When participant left")
		table.Integer("duration_seconds").Comment("Total time spent in meeting")
		table.Text("connection_quality").Comment("Connection quality metrics as JSON")
		table.Text("permissions").Comment("Participant permissions as JSON")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("Participant creator reference")
		table.Ulid("updated_by").Comment("Participant updater reference")
		table.Ulid("deleted_by").Nullable().Comment("Participant deleter reference")

		// Primary key
		table.Primary("id")

		// Foreign keys
		table.Foreign("meeting_id").References("id").On("meetings")
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")

		// Add indexes
		table.Index("meeting_id")
		table.Index("user_id")
		table.Index("status")
		table.Index("role")
		table.Index("joined_at")
		table.Index("left_at")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Unique constraint for user per meeting
		table.Unique("meeting_id", "user_id")
	})
}

// Down Reverse the migrations.
func (r *M20250115000036CreateMeetingParticipantsTable) Down() error {
	return facades.Schema().DropIfExists("meeting_participants")
}
