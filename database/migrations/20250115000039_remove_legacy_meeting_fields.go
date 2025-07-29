package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000039RemoveLegacyMeetingFields struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000039RemoveLegacyMeetingFields) Signature() string {
	return "20250115000039_remove_legacy_meeting_fields"
}

// Up Run the migrations.
func (r *M20250115000039RemoveLegacyMeetingFields) Up() error {
	return facades.Schema().Table("meetings", func(table schema.Blueprint) {
		// Remove legacy fields that are no longer needed
		table.DropColumn("allow_join_before_host")
		table.DropColumn("mute_participants_on_entry")
		table.DropColumn("waiting_room")
	})
}

// Down Reverse the migrations.
func (r *M20250115000039RemoveLegacyMeetingFields) Down() error {
	return facades.Schema().Table("meetings", func(table schema.Blueprint) {
		// Re-add legacy fields if needed
		table.Boolean("allow_join_before_host").Default(true).Comment("Whether participants can join before host")
		table.Boolean("mute_participants_on_entry").Default(false).Comment("Whether to mute participants on entry")
		table.String("waiting_room").Default("disabled").Comment("Waiting room setting")
	})
}
