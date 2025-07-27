package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000039CreateBreakoutRoomParticipantsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000039CreateBreakoutRoomParticipantsTable) Signature() string {
	return "20250115000039_create_breakout_room_participants_table"
}

// Up Run the migrations.
func (r *M20250115000039CreateBreakoutRoomParticipantsTable) Up() error {
	return facades.Schema().Create("breakout_room_participants", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique participant identifier")
		table.Ulid("breakout_room_id").Comment("Breakout room reference")
		table.Ulid("meeting_participant_id").Comment("Meeting participant reference")
		table.String("assignment_type").Comment("Assignment type (manual, auto, self-selected)")
		table.String("status").Comment("Participant status (assigned, joined, left)")
		table.TimestampTz("joined_at").Nullable().Comment("When participant joined breakout room")
		table.TimestampTz("left_at").Nullable().Comment("When participant left breakout room")
		table.Integer("duration_seconds").Comment("Time spent in breakout room")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("Assignment creator reference")
		table.Ulid("updated_by").Comment("Assignment updater reference")
		table.Ulid("deleted_by").Nullable().Comment("Assignment deleter reference")

		// Primary key
		table.Primary("id")

		// Foreign keys
		table.Foreign("breakout_room_id").References("id").On("meeting_breakout_rooms")
		table.Foreign("meeting_participant_id").References("id").On("meeting_participants")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")

		// Add indexes
		table.Index("breakout_room_id")
		table.Index("meeting_participant_id")
		table.Index("assignment_type")
		table.Index("status")
		table.Index("joined_at")
		table.Index("left_at")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Unique constraint for participant per breakout room
		table.Unique("breakout_room_id", "meeting_participant_id")
	})
}

// Down Reverse the migrations.
func (r *M20250115000039CreateBreakoutRoomParticipantsTable) Down() error {
	return facades.Schema().DropIfExists("breakout_room_participants")
}
