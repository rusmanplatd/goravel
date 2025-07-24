package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000029CreateChatNotificationSettingsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000029CreateChatNotificationSettingsTable) Signature() string {
	return "20250115000029_create_chat_notification_settings_table"
}

// Up Run the migrations.
func (r *M20250115000029CreateChatNotificationSettingsTable) Up() error {
	return facades.Schema().Create("chat_notification_settings", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique settings identifier")
		table.Ulid("user_id").Comment("User reference")
		table.Ulid("chat_room_id").Comment("Chat room reference")
		table.Boolean("email_notifications").Default(true).Comment("Whether email notifications are enabled")
		table.Boolean("push_notifications").Default(true).Comment("Whether push notifications are enabled")
		table.Boolean("desktop_notifications").Default(true).Comment("Whether desktop notifications are enabled")
		table.Boolean("mention_notifications").Default(true).Comment("Whether mention notifications are enabled")
		table.Boolean("reaction_notifications").Default(true).Comment("Whether reaction notifications are enabled")
		table.Boolean("thread_notifications").Default(true).Comment("Whether thread notifications are enabled")
		table.String("mute_until").Nullable().Comment("Mute until timestamp")
		table.Boolean("is_muted").Default(false).Comment("Whether chat room is muted")
		table.Json("custom_settings").Comment("Custom notification settings")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("user_id")
		table.Index("chat_room_id")
		table.Index("user_id", "chat_room_id")
		table.Index("is_muted")
	})
}

// Down Reverse the migrations.
func (r *M20250115000029CreateChatNotificationSettingsTable) Down() error {
	return facades.Schema().DropIfExists("chat_notification_settings")
}
