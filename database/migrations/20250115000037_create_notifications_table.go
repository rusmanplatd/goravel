package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000037CreateNotificationsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000037CreateNotificationsTable) Signature() string {
	return "20250115000037_create_notifications_table"
}

// Up Run the migrations.
func (r *M20250115000037CreateNotificationsTable) Up() error {
	return facades.Schema().Create("notifications", func(table schema.Blueprint) {
		table.Ulid("id")
		table.String("type").Comment("Notification class type")
		table.Text("data").Comment("Notification data as JSON")
		table.Ulid("notifiable_id").Comment("ID of the notifiable entity")
		table.String("notifiable_type").Comment("Type of the notifiable entity")
		table.String("channel").Default("database").Comment("Notification channel")
		table.TimestampTz("read_at").Nullable().Comment("When notification was read")
		table.TimestampTz("sent_at").Nullable().Comment("When notification was sent")
		table.TimestampTz("failed_at").Nullable().Comment("When notification failed to send")
		table.Text("failure_reason").Nullable().Comment("Reason for failure")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("notifiable_id", "notifiable_type")
		table.Index("type")
		table.Index("channel")
		table.Index("read_at")
		table.Index("sent_at")
		table.Index("failed_at")
	})
}

// Down Reverse the migrations.
func (r *M20250115000037CreateNotificationsTable) Down() error {
	return facades.Schema().DropIfExists("notifications")
}
