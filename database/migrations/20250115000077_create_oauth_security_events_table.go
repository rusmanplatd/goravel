package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000077CreateOauthSecurityEventsTable struct{}

// Signature returns the unique identifier for this migration
func (r *M20250115000077CreateOauthSecurityEventsTable) Signature() string {
	return "20250115000077_create_oauth_security_events_table"
}

// Up runs the migration
func (r *M20250115000077CreateOauthSecurityEventsTable) Up() error {
	return facades.Schema().Create("oauth_security_events", func(table schema.Blueprint) {
		table.ID()
		table.String("event_id").Comment("Unique event identifier")
		table.String("event_type", 50).Comment("Type of security event")
		table.Ulid("user_id").Nullable().Comment("User involved in the event")
		table.Ulid("client_id").Nullable().Comment("OAuth client involved")
		table.String("ip_address", 45).Nullable().Comment("IP address of the request")
		table.Text("user_agent").Nullable().Comment("User agent string")
		table.String("session_id").Nullable().Comment("Session identifier")
		table.String("request_id").Nullable().Comment("Request identifier")
		table.String("risk_level", 20).Default("MINIMAL").Comment("Risk level: MINIMAL, LOW, MEDIUM, HIGH")
		table.Integer("risk_score").Default(0).Comment("Calculated risk score")
		table.Json("risk_factors").Nullable().Comment("Risk factors as JSON array")
		table.Json("event_data").Nullable().Comment("Additional event data")
		table.String("location_country", 2).Nullable().Comment("Country code")
		table.String("location_region").Nullable().Comment("Region/state")
		table.String("location_city").Nullable().Comment("City")
		table.Boolean("is_resolved").Default(false).Comment("Whether event is resolved")
		table.String("resolution_action").Nullable().Comment("Action taken to resolve")
		table.Timestamp("resolved_at").Nullable().Comment("When event was resolved")
		table.Ulid("resolved_by").Nullable().Comment("Who resolved the event")
		table.Timestamps()

		// Indexes
		table.Index("event_id")
		table.Index("event_type")
		table.Index("user_id")
		table.Index("client_id")
		table.Index("ip_address")
		table.Index("risk_level")
		table.Index("risk_score")
		table.Index("is_resolved")
		table.Index("created_at")
		table.Index("location_country")

		// Composite indexes for common queries
		table.Index("user_id", "event_type")
		table.Index("client_id", "event_type")
		table.Index("risk_level", "created_at")

		// Foreign keys
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("client_id").References("id").On("oauth_clients")
		table.Foreign("resolved_by").References("id").On("users")
	})
}

// Down reverses the migration
func (r *M20250115000077CreateOauthSecurityEventsTable) Down() error {
	return facades.Schema().DropIfExists("oauth_security_events")
}
