package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000041CreateMeetingPollOptionsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000041CreateMeetingPollOptionsTable) Signature() string {
	return "20250115000041_create_meeting_poll_options_table"
}

// Up Run the migrations.
func (r *M20250115000041CreateMeetingPollOptionsTable) Up() error {
	return facades.Schema().Create("meeting_poll_options", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique option identifier")
		table.Ulid("poll_id").Comment("Poll reference")
		table.String("option_text").Comment("Option text/description")
		table.Integer("vote_count").Comment("Number of votes for this option")
		table.Integer("order_index").Comment("Display order of option")
		table.TimestampsTz()
		table.Ulid("created_by").Comment("Option creator reference")
		table.Ulid("updated_by").Comment("Option updater reference")

		// Primary key
		table.Primary("id")

		// Foreign keys
		table.Foreign("poll_id").References("id").On("meeting_polls")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")

		// Indexes
		table.Index("poll_id")
		table.Index("order_index")
	})
}

// Down Reverse the migrations.
func (r *M20250115000041CreateMeetingPollOptionsTable) Down() error {
	return facades.Schema().DropIfExists("meeting_poll_options")
}
