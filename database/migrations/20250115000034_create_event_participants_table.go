package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000034CreateEventParticipantsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000034CreateEventParticipantsTable) Signature() string {
	return "20250115000034_create_event_participants_table"
}

// Up Run the migrations.
func (r *M20250115000034CreateEventParticipantsTable) Up() error {
	return facades.Schema().Create("event_participants", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique participant identifier")
		table.Ulid("event_id").Comment("Calendar event reference")
		table.Ulid("user_id").Comment("User reference")
		table.String("role").Comment("Participant role (organizer, attendee, optional)")
		table.String("response_status").Comment("Response status (accepted, declined, tentative, pending)")
		table.TimestampTz("responded_at").Nullable().Comment("When participant responded")
		table.Text("response_comment").Comment("Participant's response comment")
		table.Boolean("is_required").Comment("Whether participant is required")
		table.Boolean("send_reminder").Comment("Whether to send reminders to this participant")
		table.TimestampTz("reminder_sent_at").Nullable().Comment("When reminder was last sent")
		table.Ulid("created_by").Comment("Participant creator reference")
		table.Ulid("updated_by").Comment("Participant updater reference")
		table.Ulid("deleted_by").Nullable().Comment("Participant deleter reference")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Unique constraint
		table.Unique("event_id", "user_id")

		// Add indexes
		table.Index("event_id")
		table.Index("user_id")
		table.Index("response_status")
		table.Index("role")
		table.Index("event_id", "response_status")
		table.Index("user_id", "response_status")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add Foreign
		table.Foreign("event_id").References("id").On("calendar_events")
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000034CreateEventParticipantsTable) Down() error {
	return facades.Schema().DropIfExists("event_participants")
}
