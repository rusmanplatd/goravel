package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000081CreateMeetingSecurityPoliciesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000081CreateMeetingSecurityPoliciesTable) Signature() string {
	return "20250115000081_create_meeting_security_policies_table"
}

// Up Run the migrations.
func (r *M20250115000081CreateMeetingSecurityPoliciesTable) Up() error {
	return facades.Schema().Create("meeting_security_policies", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique policy identifier")
		table.Ulid("meeting_id").Comment("Meeting reference")
		table.Boolean("require_waiting_room").Default(false).Comment("Whether waiting room is required")
		table.Boolean("require_password").Default(false).Comment("Whether password is required")
		table.Boolean("allow_anonymous_join").Default(true).Comment("Whether anonymous users can join")
		table.Integer("max_participants").Default(100).Comment("Maximum number of participants")
		table.Json("allowed_domains").Comment("List of allowed email domains")
		table.Json("blocked_users").Comment("List of blocked user IDs")
		table.Boolean("require_registration").Default(false).Comment("Whether registration is required")
		table.Boolean("enable_e2e_encryption").Default(false).Comment("Whether end-to-end encryption is enabled")
		table.String("recording_permissions").Default("host").Comment("Who can record (host, all, none)")
		table.String("screen_share_permissions").Default("all").Comment("Who can screen share (host, all, none)")
		table.String("chat_permissions").Default("all").Comment("Who can chat (host, all, none)")
		table.Boolean("mute_on_entry").Default(false).Comment("Whether to mute participants on entry")
		table.Boolean("disable_camera").Default(false).Comment("Whether to disable camera on entry")
		table.Boolean("lock_meeting").Default(false).Comment("Whether meeting is locked")
		table.Boolean("enable_breakout_rooms").Default(true).Comment("Whether breakout rooms are allowed")
		table.Boolean("enable_polls").Default(true).Comment("Whether polls are allowed")
		table.Boolean("enable_whiteboard").Default(true).Comment("Whether whiteboard is allowed")
		table.Boolean("enable_file_sharing").Default(true).Comment("Whether file sharing is allowed")
		table.Boolean("enable_reactions").Default(true).Comment("Whether reactions are allowed")
		table.Boolean("enable_hand_raise").Default(true).Comment("Whether hand raising is allowed")
		table.Integer("idle_timeout_minutes").Default(0).Comment("Idle timeout in minutes (0 for no timeout)")
		table.Integer("meeting_duration_minutes").Default(0).Comment("Meeting duration limit in minutes (0 for unlimited)")
		table.String("join_approval_mode").Default("automatic").Comment("Join approval mode (automatic, manual, domain_restricted)")
		table.Json("custom_settings").Comment("Additional custom security settings as JSON")
		table.TimestampsTz()

		// Indexes
		table.Index("meeting_id")
		table.Unique("meeting_id") // One policy per meeting
	})
}

// Down Reverse the migrations.
func (r *M20250115000081CreateMeetingSecurityPoliciesTable) Down() error {
	return facades.Schema().DropIfExists("meeting_security_policies")
}
