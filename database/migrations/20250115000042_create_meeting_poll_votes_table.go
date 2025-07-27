package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000042CreateMeetingPollVotesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000042CreateMeetingPollVotesTable) Signature() string {
	return "20250115000042_create_meeting_poll_votes_table"
}

// Up Run the migrations.
func (r *M20250115000042CreateMeetingPollVotesTable) Up() error {
	return facades.Schema().Create("meeting_poll_votes", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique vote identifier")
		table.Ulid("poll_id").Comment("Poll reference")
		table.Ulid("option_id").Nullable().Comment("Selected option reference (null for text responses)")
		table.Ulid("voter_id").Comment("Voter reference")
		table.Text("text_response").Comment("Text response for open-ended polls")
		table.Integer("rating_value").Nullable().Comment("Rating value for rating polls")
		table.TimestampTz("voted_at").Comment("When vote was cast")
		table.TimestampsTz()
		table.Ulid("created_by").Comment("Vote creator reference")

		// Primary key
		table.Primary("id")

		// Foreign keys
		table.Foreign("poll_id").References("id").On("meeting_polls")
		table.Foreign("option_id").References("id").On("meeting_poll_options")
		table.Foreign("voter_id").References("id").On("users")
		table.Foreign("created_by").References("id").On("users")

		// Indexes
		table.Index("poll_id")
		table.Index("option_id")
		table.Index("voter_id")
		table.Index("voted_at")

		// Unique constraint to prevent duplicate votes (unless poll allows multiple votes)
		table.Unique("poll_id", "voter_id")
	})
}

// Down Reverse the migrations.
func (r *M20250115000042CreateMeetingPollVotesTable) Down() error {
	return facades.Schema().DropIfExists("meeting_poll_votes")
}
