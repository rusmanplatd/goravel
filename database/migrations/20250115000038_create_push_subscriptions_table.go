package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000038CreatePushSubscriptionsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000038CreatePushSubscriptionsTable) Signature() string {
	return "20250115000038_create_push_subscriptions_table"
}

// Up Run the migrations.
func (r *M20250115000038CreatePushSubscriptionsTable) Up() error {
	return facades.Schema().Create("push_subscriptions", func(table schema.Blueprint) {
		table.Ulid("id")
		table.Ulid("user_id").Comment("User ID")
		table.String("endpoint", 500).Comment("Push subscription endpoint")
		table.String("p256dh_key", 255).Comment("P-256 DH public key")
		table.String("auth_token", 255).Comment("Authentication token")
		table.String("content_encoding", 20).Default("aes128gcm").Comment("Content encoding")
		table.Boolean("is_active").Default(true).Comment("Whether subscription is active")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("user_id")
		table.Index("endpoint")
		table.Index("is_active")
	})
}

// Down Reverse the migrations.
func (r *M20250115000038CreatePushSubscriptionsTable) Down() error {
	return facades.Schema().DropIfExists("push_subscriptions")
}
