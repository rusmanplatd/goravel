package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000040CreateMeetingPollsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000040CreateMeetingPollsTable) Signature() string {
	return "20250115000040_create_meeting_polls_table"
}

// Up Run the migrations.
func (r *M20250115000040CreateMeetingPollsTable) Up() error {
	return facades.Schema().Create("meeting_polls", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique poll identifier")
		table.Ulid("meeting_id").Comment("Meeting reference")
		table.Ulid("creator_id").Comment("Poll creator reference")
		table.String("title").Comment("Poll title/question")
		table.Text("description").Comment("Poll description")
		table.String("poll_type").Comment("Poll type (single_choice, multiple_choice, rating, text)")
		table.Boolean("is_anonymous").Comment("Whether poll responses are anonymous")
		table.Boolean("allow_multiple_votes").Comment("Whether participants can vote multiple times")
		table.Boolean("is_active").Comment("Whether poll is currently active")
		table.TimestampTz("starts_at").Nullable().Comment("When poll becomes active")
		table.TimestampTz("ends_at").Nullable().Comment("When poll closes")
		table.Integer("total_votes").Comment("Total number of votes")
		table.Text("settings").Comment("Additional poll settings as JSON")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("Poll creator reference")
		table.Ulid("updated_by").Comment("Poll updater reference")
		table.Ulid("deleted_by").Nullable().Comment("Poll deleter reference")

		// Primary key
		table.Primary("id")

		// Foreign keys
		table.Foreign("meeting_id").References("id").On("meetings")
		table.Foreign("creator_id").References("id").On("users")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")

		// Indexes
		table.Index("meeting_id")
		table.Index("creator_id")
		table.Index("is_active")
		table.Index("starts_at")
		table.Index("ends_at")
	})
}

// Down Reverse the migrations.
func (r *M20250115000040CreateMeetingPollsTable) Down() error {
	return facades.Schema().DropIfExists("meeting_polls")
}
