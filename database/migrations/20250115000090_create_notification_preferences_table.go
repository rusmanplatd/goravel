package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000090CreateNotificationPreferencesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000090CreateNotificationPreferencesTable) Signature() string {
	return "20250115000090_create_notification_preferences_table"
}

// Up Run the migrations.
func (r *M20250115000090CreateNotificationPreferencesTable) Up() error {
	return facades.Schema().Create("notification_preferences", func(table schema.Blueprint) {
		table.Ulid("id")
		table.Ulid("user_id").Comment("ID of the user")
		table.String("notification_type").Comment("Type of notification (e.g., WelcomeNotification)")
		table.Text("channels").Comment("Enabled channels as JSON array")
		table.Boolean("enabled").Default(true).Comment("Whether this notification type is enabled")
		table.Text("settings").Nullable().Comment("Channel-specific settings as JSON")

		// Timing preferences
		table.String("quiet_hours_start").Nullable().Comment("Start of quiet hours (HH:MM format)")
		table.String("quiet_hours_end").Nullable().Comment("End of quiet hours (HH:MM format)")
		table.String("timezone").Default("UTC").Comment("User's timezone")

		// Frequency control
		table.Integer("max_per_hour").Nullable().Comment("Maximum notifications per hour")
		table.Integer("max_per_day").Nullable().Comment("Maximum notifications per day")
		table.Boolean("digest_enabled").Default(false).Comment("Whether to batch notifications into digest")
		table.String("digest_frequency").Default("daily").Comment("Digest frequency: hourly, daily, weekly")

		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("user_id")
		table.Index("notification_type")
		table.Index("enabled")
		table.Unique("user_id", "notification_type") // One preference per user per notification type

		// Foreign key
		table.Foreign("user_id").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000090CreateNotificationPreferencesTable) Down() error {
	return facades.Schema().DropIfExists("notification_preferences")
}
