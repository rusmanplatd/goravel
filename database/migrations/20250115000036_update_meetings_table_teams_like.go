package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000036UpdateMeetingsTableTeamsLike struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000036UpdateMeetingsTableTeamsLike) Signature() string {
	return "20250115000036_update_meetings_table_teams_like"
}

// Up Run the migrations.
func (r *M20250115000036UpdateMeetingsTableTeamsLike) Up() error {
	return facades.Schema().Table("meetings", func(table schema.Blueprint) {
		// Add new Teams-like fields
		table.String("subject").Comment("Meeting subject/title")
		table.String("join_web_url").Comment("Meeting join URL")
		table.String("video_teleconference_id").Comment("Video teleconference ID")
		table.TimestampTz("start_date_time").Nullable().Comment("Meeting start time")
		table.TimestampTz("end_date_time").Nullable().Comment("Meeting end time")

		// Teams meeting settings
		table.Boolean("allow_attendee_to_enable_camera").Default(true).Comment("Whether attendees can enable camera")
		table.Boolean("allow_attendee_to_enable_mic").Default(true).Comment("Whether attendees can enable microphone")
		table.Boolean("allow_breakout_rooms").Default(false).Comment("Whether breakout rooms are enabled")
		table.String("allowed_presenters").Default("everyone").Comment("Who can be a presenter")
		table.String("allow_meeting_chat").Default("enabled").Comment("Meeting chat mode")
		table.Boolean("allow_participants_to_change_name").Default(true).Comment("Whether participants can change name")
		table.Boolean("allow_power_point_sharing").Default(true).Comment("Whether PowerPoint sharing is allowed")
		table.Boolean("allow_recording").Default(false).Comment("Whether recording is enabled")
		table.Boolean("allow_teamwork_reactions").Default(true).Comment("Whether Teams reactions are enabled")
		table.Boolean("allow_transcription").Default(false).Comment("Whether transcription is enabled")
		table.Boolean("allow_whiteboard").Default(true).Comment("Whether whiteboard is enabled")
		table.Boolean("is_entry_exit_announced").Default(true).Comment("Whether to announce entry/exit")
		table.Boolean("record_automatically").Default(false).Comment("Whether to record automatically")

		// Lobby and security settings
		table.String("lobby_bypass_scope").Default("organization").Comment("Lobby bypass scope")
		table.Boolean("is_dial_in_bypass_enabled").Default(false).Comment("Whether dial-in bypass is enabled")
		table.String("join_meeting_id").Comment("Join meeting ID for dial-in")
		table.Boolean("is_passcode_required").Default(false).Comment("Whether passcode is required")
		table.String("share_meeting_chat_history_default").Default("all").Comment("Chat history sharing mode")
		table.String("watermark_protection").Default("disabled").Comment("Watermark protection settings")
	})
}

// Down Reverse the migrations.
func (r *M20250115000036UpdateMeetingsTableTeamsLike) Down() error {
	return facades.Schema().Table("meetings", func(table schema.Blueprint) {
		// Drop the added columns
		table.DropColumn("subject")
		table.DropColumn("join_web_url")
		table.DropColumn("video_teleconference_id")
		table.DropColumn("start_date_time")
		table.DropColumn("end_date_time")
		table.DropColumn("allow_attendee_to_enable_camera")
		table.DropColumn("allow_attendee_to_enable_mic")
		table.DropColumn("allow_breakout_rooms")
		table.DropColumn("allowed_presenters")
		table.DropColumn("allow_meeting_chat")
		table.DropColumn("allow_participants_to_change_name")
		table.DropColumn("allow_power_point_sharing")
		table.DropColumn("allow_recording")
		table.DropColumn("allow_teamwork_reactions")
		table.DropColumn("allow_transcription")
		table.DropColumn("allow_whiteboard")
		table.DropColumn("is_entry_exit_announced")
		table.DropColumn("record_automatically")
		table.DropColumn("lobby_bypass_scope")
		table.DropColumn("is_dial_in_bypass_enabled")
		table.DropColumn("join_meeting_id")
		table.DropColumn("is_passcode_required")
		table.DropColumn("share_meeting_chat_history_default")
		table.DropColumn("watermark_protection")
	})
}
