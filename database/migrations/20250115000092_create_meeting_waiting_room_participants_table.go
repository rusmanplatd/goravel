package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000092CreateMeetingWaitingRoomParticipantsTable struct{}

// Signature The name and signature of the migration.
func (receiver *M20250115000092CreateMeetingWaitingRoomParticipantsTable) Signature() string {
	return "20250115000092_create_meeting_waiting_room_participants_table"
}

// Up Run the migrations.
func (receiver *M20250115000092CreateMeetingWaitingRoomParticipantsTable) Up() error {
	return facades.Schema().Create("meeting_waiting_room_participants", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique waiting room participant identifier")
		table.Ulid("meeting_id").Comment("Meeting reference")
		table.Ulid("user_id").Comment("User reference")
		table.String("name").Comment("Participant name")
		table.String("email").Comment("Participant email")
		table.TimestampTz("join_time").Comment("Time when user joined waiting room")
		table.Text("device_info").Nullable().Comment("Device information JSON")
		table.Text("request_reason").Nullable().Comment("Reason for joining meeting")
		table.String("status").Comment("Waiting room status (waiting, approved, denied, removed)")
		table.Ulid("approved_by").Nullable().Comment("Host who approved/denied")
		table.TimestampTz("status_changed_at").Nullable().Comment("When status was last changed")
		table.Text("denial_reason").Nullable().Comment("Reason for denial if applicable")
		table.Text("metadata").Nullable().Comment("Additional metadata JSON")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Indexes
		table.Index("meeting_id")
		table.Index("user_id")
		table.Index("status")
		table.Index("join_time")

		// Foreign keys
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("approved_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (receiver *M20250115000092CreateMeetingWaitingRoomParticipantsTable) Down() error {
	return facades.Schema().DropIfExists("meeting_waiting_room_participants")
}
