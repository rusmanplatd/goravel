package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000008CreateSessionsTable struct{}

// Signature The unique signature for the migration.
func (r *M20250115000008CreateSessionsTable) Signature() string {
	return "20250115000008_create_sessions_table"
}

// Up Run the migrations.
func (r *M20250115000008CreateSessionsTable) Up() error {
	return facades.Schema().Create("sessions", func(table schema.Blueprint) {
		table.String("id").Comment("Session ID")
		table.Primary("id")
		table.Text("payload").Comment("Session data payload")
		table.Integer("last_activity").Comment("Last activity timestamp")
		table.Ulid("user_id").Nullable().Comment("Associated user ID")
		table.String("ip_address", 45).Nullable().Comment("IP address of the session")
		table.Text("user_agent").Nullable().Comment("User agent string")
		table.TimestampTz("created_at").Comment("Session creation timestamp")
		table.TimestampTz("updated_at").Comment("Session last update timestamp")

		// Indexes for performance
		table.Index("last_activity")
		table.Index("user_id")
	})
}

// Down Reverse the migrations.
func (r *M20250115000008CreateSessionsTable) Down() error {
	return facades.Schema().DropIfExists("sessions")
}
