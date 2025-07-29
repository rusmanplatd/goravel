package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000037CreateMeetingTranscriptsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000037CreateMeetingTranscriptsTable) Signature() string {
	return "20250115000037_create_meeting_transcripts_table"
}

// Up Run the migrations.
func (r *M20250115000037CreateMeetingTranscriptsTable) Up() error {
	return facades.Schema().Create("meeting_transcripts", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique transcript identifier")
		table.Ulid("meeting_id").Comment("Associated meeting ID")
		table.String("content_type").Default("text").Comment("Transcript content type")
		table.Text("content").Comment("Transcript content")
		table.String("language").Default("en-US").Comment("Transcript language")
		table.String("status").Default("processing").Comment("Transcript status")
		table.String("download_url").Comment("Download URL for transcript")
		table.BigInteger("file_size").Default(0).Comment("File size in bytes")
		table.Integer("duration").Default(0).Comment("Duration in seconds")
		table.TimestampsTz()

		// Indexes
		table.Index("meeting_id")
		table.Index("status")
		table.Index("language")

		// Foreign key constraints
		table.Foreign("meeting_id").References("id").On("meetings")
	})
}

// Down Reverse the migrations.
func (r *M20250115000037CreateMeetingTranscriptsTable) Down() error {
	return facades.Schema().DropIfExists("meeting_transcripts")
}
