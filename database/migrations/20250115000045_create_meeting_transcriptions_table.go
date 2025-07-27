package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000045CreateMeetingTranscriptionsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000045CreateMeetingTranscriptionsTable) Signature() string {
	return "20250115000045_create_meeting_transcriptions_table"
}

// Up Run the migrations.
func (r *M20250115000045CreateMeetingTranscriptionsTable) Up() error {
	return facades.Schema().Create("meeting_transcriptions", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique transcription identifier")
		table.Ulid("meeting_id").Comment("Meeting reference")
		table.Ulid("recording_id").Nullable().Comment("Associated recording reference")
		table.Ulid("speaker_id").Nullable().Comment("Speaker user reference")
		table.String("speaker_name").Comment("Speaker display name")
		table.Text("content").Comment("Transcribed text content")
		table.String("language").Comment("Transcription language code")
		table.Float("confidence_score").Comment("Transcription confidence score (0-1)")
		table.Integer("start_time").Comment("Start time in milliseconds")
		table.Integer("end_time").Comment("End time in milliseconds")
		table.Integer("duration").Comment("Duration in milliseconds")
		table.String("transcript_type").Comment("Type (live, final, correction)")
		table.Boolean("is_final").Comment("Whether this is the final transcription")
		table.Text("metadata").Comment("Additional transcription metadata as JSON")
		table.TimestampsTz()
		table.Ulid("created_by").Comment("Transcription creator reference")
		table.Ulid("updated_by").Comment("Transcription updater reference")

		// Primary key
		table.Primary("id")

		// Foreign keys
		table.Foreign("meeting_id").References("id").On("meetings")
		table.Foreign("recording_id").References("id").On("meeting_recordings")
		table.Foreign("speaker_id").References("id").On("users")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")

		// Indexes
		table.Index("meeting_id")
		table.Index("recording_id")
		table.Index("speaker_id")
		table.Index("start_time")
		table.Index("end_time")
		table.Index("is_final")
		table.Index("transcript_type")
	})
}

// Down Reverse the migrations.
func (r *M20250115000045CreateMeetingTranscriptionsTable) Down() error {
	return facades.Schema().DropIfExists("meeting_transcriptions")
}
