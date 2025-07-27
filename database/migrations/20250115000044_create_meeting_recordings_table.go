package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000044CreateMeetingRecordingsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000044CreateMeetingRecordingsTable) Signature() string {
	return "20250115000044_create_meeting_recordings_table"
}

// Up Run the migrations.
func (r *M20250115000044CreateMeetingRecordingsTable) Up() error {
	return facades.Schema().Create("meeting_recordings", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique recording identifier")
		table.Ulid("meeting_id").Comment("Meeting reference")
		table.String("recording_type").Comment("Recording type (video, audio, screen)")
		table.String("file_name").Comment("Recording file name")
		table.String("file_path").Comment("Recording file path/URL")
		table.String("file_size").Comment("Recording file size in bytes")
		table.String("duration").Comment("Recording duration in seconds")
		table.String("format").Comment("Recording format (mp4, mp3, webm)")
		table.String("quality").Comment("Recording quality (low, medium, high, ultra)")
		table.String("status").Comment("Recording status (processing, completed, failed, deleted)")
		table.Boolean("is_transcribed").Comment("Whether recording has been transcribed")
		table.String("transcription_url").Comment("Transcription file URL")
		table.String("thumbnail_url").Comment("Recording thumbnail URL")
		table.Text("metadata").Comment("Additional recording metadata as JSON")
		table.Boolean("is_public").Comment("Whether recording is publicly accessible")
		table.String("access_key").Comment("Access key for protected recordings")
		table.TimestampTz("expires_at").Nullable().Comment("When recording expires and gets deleted")
		table.TimestampTz("started_at").Comment("When recording started")
		table.TimestampTz("completed_at").Nullable().Comment("When recording completed")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("Recording creator reference")
		table.Ulid("updated_by").Comment("Recording updater reference")
		table.Ulid("deleted_by").Nullable().Comment("Recording deleter reference")

		// Primary key
		table.Primary("id")

		// Foreign keys
		table.Foreign("meeting_id").References("id").On("meetings")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")

		// Indexes
		table.Index("meeting_id")
		table.Index("recording_type")
		table.Index("status")
		table.Index("is_transcribed")
		table.Index("is_public")
		table.Index("expires_at")
		table.Index("started_at")
		table.Index("completed_at")
	})
}

// Down Reverse the migrations.
func (r *M20250115000044CreateMeetingRecordingsTable) Down() error {
	return facades.Schema().DropIfExists("meeting_recordings")
}
