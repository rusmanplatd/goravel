package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000078CreateOauthAnalyticsTable struct{}

// Signature returns the unique identifier for this migration
func (r *M20250115000078CreateOauthAnalyticsTable) Signature() string {
	return "20250115000078_create_oauth_analytics_table"
}

// Up runs the migration
func (r *M20250115000078CreateOauthAnalyticsTable) Up() error {
	return facades.Schema().Create("oauth_analytics", func(table schema.Blueprint) {
		table.ID()
		table.String("metric_name", 100).Comment("Name of the metric")
		table.String("metric_type", 50).Comment("Type: counter, gauge, histogram, etc.")
		table.Ulid("client_id").Nullable().Comment("OAuth client")
		table.Ulid("user_id").Nullable().Comment("User")
		table.String("scope").Nullable().Comment("OAuth scope")
		table.String("grant_type", 50).Nullable().Comment("OAuth grant type")
		table.String("endpoint", 100).Nullable().Comment("API endpoint")
		table.String("method", 10).Nullable().Comment("HTTP method")
		table.Integer("status_code").Nullable().Comment("HTTP status code")
		table.BigInteger("value").Default(0).Comment("Metric value")
		table.Double("duration_ms").Nullable().Comment("Request duration in milliseconds")
		table.String("ip_address", 45).Nullable().Comment("Client IP address")
		table.String("user_agent", 500).Nullable().Comment("User agent")
		table.String("country", 2).Nullable().Comment("Country code")
		table.String("region").Nullable().Comment("Region/state")
		table.String("city").Nullable().Comment("City")
		table.Json("labels").Nullable().Comment("Additional metric labels")
		table.Json("metadata").Nullable().Comment("Additional metadata")
		table.Date("date").Comment("Date for aggregation")
		table.Integer("hour").Comment("Hour of day (0-23)")
		table.Timestamps()

		// Indexes for analytics queries
		table.Index("metric_name")
		table.Index("metric_type")
		table.Index("client_id")
		table.Index("user_id")
		table.Index("scope")
		table.Index("grant_type")
		table.Index("endpoint")
		table.Index("status_code")
		table.Index("date")
		table.Index("hour")
		table.Index("country")
		table.Index("created_at")

		// Composite indexes for common analytics queries
		table.Index("metric_name", "date")
		table.Index("client_id", "date")
		table.Index("user_id", "date")
		table.Index("scope", "date")
		table.Index("grant_type", "date")
		table.Index("endpoint", "method")
		table.Index("date", "hour")
		table.Index("country", "date")

		// Foreign keys
		table.Foreign("client_id").References("id").On("oauth_clients")
		table.Foreign("user_id").References("id").On("users")
	})
}

// Down reverses the migration
func (r *M20250115000078CreateOauthAnalyticsTable) Down() error {
	return facades.Schema().DropIfExists("oauth_analytics")
}
