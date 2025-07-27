package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000038CreateMeetingBreakoutRoomsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000038CreateMeetingBreakoutRoomsTable) Signature() string {
	return "20250115000038_create_meeting_breakout_rooms_table"
}

// Up Run the migrations.
func (r *M20250115000038CreateMeetingBreakoutRoomsTable) Up() error {
	return facades.Schema().Create("meeting_breakout_rooms", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique breakout room identifier")
		table.Ulid("meeting_id").Comment("Parent meeting reference")
		table.String("name").Comment("Breakout room name")
		table.Text("description").Comment("Breakout room description")
		table.Integer("capacity").Comment("Maximum participants allowed")
		table.String("status").Comment("Room status (active, closed, paused)")
		table.Boolean("auto_assign").Comment("Whether to auto-assign participants")
		table.Boolean("allow_participants_to_choose").Comment("Whether participants can choose rooms")
		table.Boolean("allow_participants_to_return").Comment("Whether participants can return to main room")
		table.Integer("time_limit_minutes").Comment("Time limit in minutes (0 for unlimited)")
		table.TimestampTz("started_at").Nullable().Comment("When breakout room started")
		table.TimestampTz("ended_at").Nullable().Comment("When breakout room ended")
		table.Text("settings").Comment("Room settings as JSON")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("Room creator reference")
		table.Ulid("updated_by").Comment("Room updater reference")
		table.Ulid("deleted_by").Nullable().Comment("Room deleter reference")

		// Primary key
		table.Primary("id")

		// Foreign keys
		table.Foreign("meeting_id").References("id").On("meetings")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")

		// Add indexes
		table.Index("meeting_id")
		table.Index("status")
		table.Index("started_at")
		table.Index("ended_at")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")
	})
}

// Down Reverse the migrations.
func (r *M20250115000038CreateMeetingBreakoutRoomsTable) Down() error {
	return facades.Schema().DropIfExists("meeting_breakout_rooms")
}
