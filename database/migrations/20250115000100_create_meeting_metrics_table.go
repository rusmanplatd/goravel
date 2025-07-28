package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000100CreateMeetingMetricsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000100CreateMeetingMetricsTable) Signature() string {
	return "20250115000100_create_meeting_metrics_table"
}

// Up Run the migrations.
func (r *M20250115000100CreateMeetingMetricsTable) Up() error {
	return facades.Schema().Create("meeting_metrics", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique metrics identifier")
		table.Ulid("meeting_id").Comment("Meeting reference")

		// Connection metrics
		table.Integer("total_connections").Comment("Total connection attempts")
		table.Integer("active_connections").Comment("Currently active connections")
		table.Integer("failed_connections").Comment("Failed connection attempts")
		table.Float("connection_latency").Comment("Average connection latency in ms")
		table.Integer("reconnection_count").Comment("Number of reconnections")

		// Audio/Video metrics
		table.Float("audio_quality").Comment("Audio quality score (0-1)")
		table.Float("video_quality").Comment("Video quality score (0-1)")
		table.Float("packet_loss_rate").Comment("Packet loss rate percentage")
		table.Float("jitter").Comment("Network jitter in ms")
		table.BigInteger("bitrate").Comment("Average bitrate in kbps")
		table.Float("frame_rate").Comment("Average frame rate in fps")

		// Participant metrics
		table.Integer("participant_count").Comment("Number of participants")
		table.Json("speaking_time").Comment("Speaking time per participant in seconds")
		table.Integer("muted_participants").Comment("Number of muted participants")
		table.Integer("video_off_participants").Comment("Number of participants with video off")

		// Meeting flow metrics
		table.Float("duration").Comment("Meeting duration in seconds")
		table.Integer("silence_periods").Comment("Number of silence periods")
		table.Integer("interruption_count").Comment("Number of interruptions")
		table.Integer("hand_raised_count").Comment("Number of hand raises")
		table.Integer("chat_message_count").Comment("Number of chat messages")

		// Technical metrics
		table.Float("cpu_usage").Comment("CPU usage percentage")
		table.Float("memory_usage").Comment("Memory usage in MB")
		table.Float("network_bandwidth").Comment("Network bandwidth usage in Mbps")
		table.Float("server_load").Comment("Server load average")

		// Engagement metrics
		table.Float("engagement_score").Comment("Overall engagement score (0-1)")
		table.Float("attention_score").Comment("Attention score (0-1)")
		table.Float("participation_rate").Comment("Participation rate percentage")

		// Error metrics
		table.Integer("error_count").Comment("Number of errors")
		table.Integer("warning_count").Comment("Number of warnings")
		table.Integer("critical_issues").Comment("Number of critical issues")

		table.TimestampsTz()

		// Indexes
		table.Index("meeting_id")
		table.Index("created_at")
		table.Index("meeting_id", "created_at")
	})
}

// Down Reverse the migrations.
func (r *M20250115000100CreateMeetingMetricsTable) Down() error {
	return facades.Schema().DropIfExists("meeting_metrics")
}
