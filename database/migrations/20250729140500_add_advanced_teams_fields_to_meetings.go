package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250729140500AddAdvancedTeamsFieldsToMeetings struct {
}

// Signature The unique signature for the migration.
func (r *M20250729140500AddAdvancedTeamsFieldsToMeetings) Signature() string {
	return "20250729140500_add_advanced_teams_fields_to_meetings"
}

// Up Run the migrations.
func (r *M20250729140500AddAdvancedTeamsFieldsToMeetings) Up() error {
	return facades.Schema().Table("meetings", func(table schema.Blueprint) {
		// Add missing Teams-compatible fields
		table.TimestampTz("creation_date_time").Nullable().Comment("Meeting creation time in UTC")
		table.String("external_id").Nullable().Comment("External ID for custom identification")
		table.String("meeting_template_id").Nullable().Comment("Meeting template ID for consistent setups")

		// Additional Teams-specific permissions
		table.Boolean("allow_copying_and_sharing_meeting_content").Default(true).Comment("Whether copying and sharing meeting content is enabled")
		table.String("allow_live_share").Default("enabled").Comment("Whether live share is enabled")
		table.String("allowed_lobby_admitters").Default("organizerAndCoOrganizers").Comment("Users who can admit from lobby")
		table.String("anonymize_identity_for_roles").Nullable().Comment("Roles whose identity is anonymized")
		table.Boolean("is_end_to_end_encryption_enabled").Default(false).Comment("Whether end-to-end encryption is enabled")

		// JSON fields for structured data
		table.Json("audio_conferencing_json").Nullable().Comment("Audio conferencing settings")
		table.Json("chat_info_json").Nullable().Comment("Chat information")
		table.Json("chat_restrictions_json").Nullable().Comment("Chat restrictions configuration")

		// Join information
		table.Text("join_information").Nullable().Comment("Join information in localized format")
		table.String("passcode").Nullable().Comment("Meeting passcode")

		// Add indexes for better performance
		table.Index("external_id")
		table.Index("video_teleconference_id")
		table.Index("join_meeting_id")
		table.Index("creation_date_time")
	})
}

// Down Reverse the migrations.
func (r *M20250729140500AddAdvancedTeamsFieldsToMeetings) Down() error {
	return facades.Schema().Table("meetings", func(table schema.Blueprint) {
		// Drop the added columns
		table.DropColumn("creation_date_time")
		table.DropColumn("external_id")
		table.DropColumn("meeting_template_id")
		table.DropColumn("allow_copying_and_sharing_meeting_content")
		table.DropColumn("allow_live_share")
		table.DropColumn("allowed_lobby_admitters")
		table.DropColumn("anonymize_identity_for_roles")
		table.DropColumn("is_end_to_end_encryption_enabled")
		table.DropColumn("audio_conferencing_json")
		table.DropColumn("chat_info_json")
		table.DropColumn("chat_restrictions_json")
		table.DropColumn("join_information")
		table.DropColumn("passcode")

		// Drop indexes
		table.DropIndex("meetings_external_id_index")
		table.DropIndex("meetings_video_teleconference_id_index")
		table.DropIndex("meetings_join_meeting_id_index")
		table.DropIndex("meetings_creation_date_time_index")
	})
}
