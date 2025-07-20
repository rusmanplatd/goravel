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
		table.Ulid("id")
		table.Ulid("user_id")
		table.Ulid("chat_room_id")
		table.Boolean("email_notifications").Default(true)
		table.Boolean("push_notifications").Default(true)
		table.Boolean("desktop_notifications").Default(true)
		table.Boolean("mention_notifications").Default(true)
		table.Boolean("reaction_notifications").Default(true)
		table.Boolean("thread_notifications").Default(true)
		table.String("mute_until").Nullable()
		table.Boolean("is_muted").Default(false)
		table.Json("custom_settings")
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
