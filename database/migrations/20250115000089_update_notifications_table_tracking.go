package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000089UpdateNotificationsTableTracking struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000089UpdateNotificationsTableTracking) Signature() string {
	return "20250115000089_update_notifications_table_tracking"
}

// Up Run the migrations.
func (r *M20250115000089UpdateNotificationsTableTracking) Up() error {
	return facades.Schema().Table("notifications", func(table schema.Blueprint) {
		// Add new tracking fields
		table.String("delivery_status").Default("pending").Comment("Delivery status: pending, sent, delivered, failed, read")
		table.Integer("delivery_attempts").Default(0).Comment("Number of delivery attempts")
		table.TimestampTz("last_attempt_at").Nullable().Comment("Last delivery attempt timestamp")
		table.TimestampTz("delivered_at").Nullable().Comment("Delivery confirmation timestamp")
		table.String("priority").Default("normal").Comment("Notification priority: low, normal, high, urgent")
		table.TimestampTz("expires_at").Nullable().Comment("Notification expiration timestamp")
		table.Text("metadata").Nullable().Comment("Additional metadata for the notification as JSON")

		// Add indexes for better query performance
		table.Index("delivery_status")
		table.Index("priority")
		table.Index("expires_at")
		table.Index("last_attempt_at")
	})
}

// Down Reverse the migrations.
func (r *M20250115000089UpdateNotificationsTableTracking) Down() error {
	return facades.Schema().Table("notifications", func(table schema.Blueprint) {
		table.DropColumn("delivery_status", "delivery_attempts", "last_attempt_at", "delivered_at", "priority", "expires_at", "metadata")
	})
}
