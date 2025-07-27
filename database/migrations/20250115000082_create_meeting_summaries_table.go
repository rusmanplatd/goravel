package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000082CreateMeetingSummariesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000082CreateMeetingSummariesTable) Signature() string {
	return "20250115000082_create_meeting_summaries_table"
}

// Up Run the migrations.
func (r *M20250115000082CreateMeetingSummariesTable) Up() error {
	return facades.Schema().Create("meeting_summaries", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique summary identifier")
		table.Ulid("recording_id").Comment("Recording reference")
		table.Ulid("meeting_id").Comment("Meeting reference")
		table.String("title").Comment("Summary title")
		table.Text("summary").Comment("Brief summary text")
		table.Text("content").Comment("Full AI-generated content (JSON)")
		table.String("language").Comment("Language of the summary")
		table.String("ai_model").Comment("AI model used for generation")
		table.Float("confidence_score").Comment("Confidence score (0-1)")
		table.String("summary_type").Comment("Summary type (automatic, manual, hybrid)")
		table.String("status").Comment("Summary status (processing, completed, failed)")
		table.Text("error_message").Comment("Error message if processing failed")
		table.Integer("action_items_count").Comment("Number of action items identified")
		table.Integer("decisions_count").Comment("Number of decisions identified")
		table.Integer("key_points_count").Comment("Number of key points identified")
		table.String("sentiment").Comment("Overall sentiment")
		table.Float("sentiment_score").Comment("Sentiment score (-1 to 1)")
		table.Boolean("is_approved").Comment("Whether summary is approved")
		table.Ulid("approved_by").Nullable().Comment("Who approved the summary")
		table.TimestampTz("approved_at").Nullable().Comment("When summary was approved")
		table.Boolean("is_public").Comment("Whether summary is public")
		table.TimestampTz("generated_at").Comment("When summary was generated")
		table.TimestampTz("completed_at").Nullable().Comment("When processing completed")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("Summary creator reference")
		table.Ulid("updated_by").Comment("Summary updater reference")
		table.Ulid("deleted_by").Nullable().Comment("Summary deleter reference")

		// Primary key
		table.Primary("id")

		// Foreign keys
		table.Foreign("recording_id").References("id").On("meeting_recordings")
		table.Foreign("meeting_id").References("id").On("meetings")
		table.Foreign("approved_by").References("id").On("users")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")

		// Indexes
		table.Index("recording_id")
		table.Index("meeting_id")
		table.Index("status")
		table.Index("summary_type")
		table.Index("sentiment")
		table.Index("is_approved")
		table.Index("is_public")
		table.Index("generated_at")
		table.Index("completed_at")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")
	})
}

// Down Reverse the migrations.
func (r *M20250115000082CreateMeetingSummariesTable) Down() error {
	return facades.Schema().DropIfExists("meeting_summaries")
}
