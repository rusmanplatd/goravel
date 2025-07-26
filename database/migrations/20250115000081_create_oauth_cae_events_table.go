package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000081CreateOauthCaeEventsTable struct{}

// Signature returns the unique identifier for this migration
func (r *M20250115000081CreateOauthCaeEventsTable) Signature() string {
	return "20250115000081_create_oauth_cae_events_table"
}

// Up runs the migration
func (r *M20250115000081CreateOauthCaeEventsTable) Up() error {
	return facades.Schema().Create("oauth_cae_events", func(table schema.Blueprint) {
		table.ID()
		table.String("event_id").Comment("Unique CAE event identifier")
		table.String("event_type", 50).Comment("CAE event type: user_risk, location_change, etc.")
		table.String("event_category", 30).Comment("Event category: security, policy, user")
		table.Ulid("user_id").Comment("User associated with event")
		table.Ulid("client_id").Nullable().Comment("OAuth client if applicable")
		table.String("session_id").Nullable().Comment("Session identifier")
		table.String("token_id", 100).Nullable().Comment("Affected token ID")
		table.String("subject", 100).Comment("Event subject (user, resource, etc.)")
		table.String("issuer", 200).Comment("Event issuer")
		table.String("audience", 200).Nullable().Comment("Event audience")
		table.BigInteger("iat").Comment("Issued at timestamp")
		table.BigInteger("exp").Nullable().Comment("Event expiration timestamp")
		table.String("jti").Comment("JWT ID for event")
		table.Json("events").Comment("CAE events payload")
		table.String("risk_level", 20).Default("low").Comment("Risk level: low, medium, high, critical")
		table.Integer("risk_score").Default(0).Comment("Calculated risk score")
		table.String("ip_address", 45).Nullable().Comment("IP address associated with event")
		table.String("location_country", 2).Nullable().Comment("Country code")
		table.String("location_region").Nullable().Comment("Region/state")
		table.String("location_city").Nullable().Comment("City")
		table.String("device_id").Nullable().Comment("Device identifier")
		table.String("user_agent", 500).Nullable().Comment("User agent")
		table.Json("context").Nullable().Comment("Additional event context")
		table.String("action_taken", 50).Nullable().Comment("Action taken: revoke, challenge, allow")
		table.String("status", 20).Default("pending").Comment("Event status: pending, processed, ignored")
		table.Timestamp("processed_at").Nullable().Comment("When event was processed")
		table.Ulid("processed_by").Nullable().Comment("Who processed the event")
		table.Text("processing_notes").Nullable().Comment("Processing notes")
		table.Timestamps()

		// Indexes
		table.Index("event_id")
		table.Index("event_type")
		table.Index("event_category")
		table.Index("user_id")
		table.Index("client_id")
		table.Index("session_id")
		table.Index("token_id")
		table.Index("subject")
		table.Index("issuer")
		table.Index("iat")
		table.Index("exp")
		table.Index("jti")
		table.Index("risk_level")
		table.Index("risk_score")
		table.Index("ip_address")
		table.Index("location_country")
		table.Index("device_id")
		table.Index("action_taken")
		table.Index("status")
		table.Index("processed_at")
		table.Index("created_at")

		// Composite indexes for CAE queries
		table.Index("user_id", "event_type")
		table.Index("client_id", "event_type")
		table.Index("risk_level", "status")
		table.Index("event_type", "created_at")
		table.Index("user_id", "risk_level")
		table.Index("status", "created_at")

		// Unique constraints
		table.Unique("event_id")
		table.Unique("jti")

		// Foreign keys
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("client_id").References("id").On("oauth_clients")
		table.Foreign("processed_by").References("id").On("users")
	})
}

// Down reverses the migration
func (r *M20250115000081CreateOauthCaeEventsTable) Down() error {
	return facades.Schema().DropIfExists("oauth_cae_events")
}
