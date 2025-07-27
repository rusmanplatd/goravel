package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000091CreateScheduledNotificationsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000091CreateScheduledNotificationsTable) Signature() string {
	return "20250115000091_create_scheduled_notifications_table"
}

// Up Run the migrations.
func (r *M20250115000091CreateScheduledNotificationsTable) Up() error {
	return facades.Schema().Create("scheduled_notifications", func(table schema.Blueprint) {
		table.Ulid("id")
		table.String("notification_type").Comment("Type of notification to send")
		table.Text("notification_data").Comment("Serialized notification data as JSON")
		table.Ulid("notifiable_id").Comment("ID of the notifiable entity")
		table.String("notifiable_type").Comment("Type of the notifiable entity")
		table.TimestampTz("scheduled_at").Comment("When the notification should be sent")
		table.String("status").Default("pending").Comment("Status: pending, sent, cancelled, failed")
		table.TimestampTz("processed_at").Nullable().Comment("When the notification was processed")
		table.Text("failure_reason").Nullable().Comment("Reason for failure if status is failed")
		table.Integer("attempts").Default(0).Comment("Number of delivery attempts")
		table.Integer("max_attempts").Default(3).Comment("Maximum number of attempts")

		// Recurring notification fields
		table.Boolean("is_recurring").Default(false).Comment("Whether this is a recurring notification")
		table.String("recurrence_pattern").Nullable().Comment("Recurrence pattern: daily, weekly, monthly, yearly")
		table.Integer("recurrence_interval").Default(1).Comment("Interval for recurrence (e.g., every 2 weeks)")
		table.TimestampTz("recurrence_end").Nullable().Comment("When the recurrence should end")
		table.TimestampTz("next_scheduled_at").Nullable().Comment("Next scheduled time for recurring notifications")

		// Time zone and localization
		table.String("timezone").Default("UTC").Comment("Time zone for scheduling")
		table.String("locale").Default("en").Comment("Locale for localization")

		// Metadata
		table.Text("metadata").Nullable().Comment("Additional metadata as JSON")

		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes for performance
		table.Index("notifiable_id", "notifiable_type")
		table.Index("notification_type")
		table.Index("status")
		table.Index("scheduled_at")
		table.Index("is_recurring")
		table.Index("next_scheduled_at")
		table.Index("processed_at")

		// Composite indexes for common queries
		table.Index("status", "scheduled_at")  // For finding due notifications
		table.Index("notifiable_id", "status") // For user's scheduled notifications
	})
}

// Down Reverse the migrations.
func (r *M20250115000091CreateScheduledNotificationsTable) Down() error {
	return facades.Schema().DropIfExists("scheduled_notifications")
}
