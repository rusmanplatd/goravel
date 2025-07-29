package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000038CreateMeetingAttendanceReportsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000038CreateMeetingAttendanceReportsTable) Signature() string {
	return "20250115000038_create_meeting_attendance_reports_table"
}

// Up Run the migrations.
func (r *M20250115000038CreateMeetingAttendanceReportsTable) Up() error {
	return facades.Schema().Create("meeting_attendance_reports", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique report identifier")
		table.Ulid("meeting_id").Comment("Associated meeting ID")
		table.String("title").Comment("Report title")
		table.Integer("total_participants").Default(0).Comment("Total participants count")
		table.Integer("unique_participants").Default(0).Comment("Unique participants count")
		table.String("status").Default("processing").Comment("Report generation status")
		table.String("download_url").Comment("Download URL for report")
		table.String("format").Default("csv").Comment("Report format")
		table.BigInteger("file_size").Default(0).Comment("File size in bytes")
		table.Text("report_data").Comment("Report data as JSON")
		table.TimestampsTz()

		// Indexes
		table.Index("meeting_id")
		table.Index("status")
		table.Index("format")

		// Foreign key constraints
		table.Foreign("meeting_id").References("id").On("meetings")
	})
}

// Down Reverse the migrations.
func (r *M20250115000038CreateMeetingAttendanceReportsTable) Down() error {
	return facades.Schema().DropIfExists("meeting_attendance_reports")
}
