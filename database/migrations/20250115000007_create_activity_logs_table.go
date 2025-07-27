package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000007CreateActivityLogsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000007CreateActivityLogsTable) Signature() string {
	return "20250115000007_create_activity_logs_table"
}

// Up Run the migrations.
func (r *M20250115000007CreateActivityLogsTable) Up() error {
	return facades.Schema().Create("activity_logs", func(table schema.Blueprint) {
		// Primary key
		table.Ulid("id").Comment("Unique activity log identifier")

		// Core activity fields
		table.String("log_name", 100).Comment("Log name/category")
		table.Text("description").Comment("Activity description")

		// Activity categorization
		table.String("category", 50).Default("system").Comment("Activity category")
		table.String("severity", 20).Default("info").Comment("Severity level")
		table.String("status", 20).Default("success").Comment("Activity status")

		// Subject and causer information
		table.String("subject_type", 100).Nullable().Comment("Subject model type")
		table.Ulid("subject_id").Nullable().Comment("Subject model identifier")
		table.String("causer_type", 100).Nullable().Comment("Causer model type")
		table.Ulid("causer_id").Nullable().Comment("Causer model identifier")

		// Request context
		table.String("ip_address", 45).Nullable().Comment("Client IP address")
		table.Text("user_agent").Nullable().Comment("User agent string")
		table.String("request_path", 500).Nullable().Comment("Request path")
		table.String("request_method", 10).Nullable().Comment("HTTP method")
		table.Integer("status_code").Nullable().Comment("HTTP status code")
		table.BigInteger("duration").Nullable().Comment("Request duration in milliseconds")

		// Session and tracing
		table.String("session_id", 36).Nullable().Comment("Session identifier")
		table.String("request_id", 36).Nullable().Comment("Request ID for tracing")

		// Geographic and device information
		table.Json("geo_location").Nullable().Comment("Geographic location data")
		table.Json("device_info").Nullable().Comment("Device information")

		// Security and risk assessment
		table.Integer("risk_score").Default(0).Comment("Risk score (0-100)")
		table.String("threat_level", 20).Nullable().Comment("Threat level assessment")

		// Categorization and metadata
		table.Json("tags").Nullable().Comment("Tags for categorization")
		table.Json("properties").Nullable().Comment("Additional activity properties")
		table.Json("compliance_flags").Nullable().Comment("Compliance flags")

		// Timestamps
		table.TimestampTz("event_timestamp").Comment("Event occurrence timestamp")
		table.TimestampsTz()

		// Multi-tenancy
		table.Ulid("tenant_id").Nullable().Comment("Tenant reference")

		// Audit fields from BaseModel
		table.Ulid("created_by").Nullable().Comment("Creator reference")
		table.Ulid("updated_by").Nullable().Comment("Last updater reference")
		table.Timestamp("deleted_at").Nullable().Comment("Soft delete timestamp")
		table.Ulid("deleted_by").Nullable().Comment("Deleter reference")

		// Primary key
		table.Primary("id")

		// Basic field indexes
		table.Index("log_name")
		table.Index("category")
		table.Index("severity")
		table.Index("status")
		table.Index("subject_type")
		table.Index("subject_id")
		table.Index("causer_type")
		table.Index("causer_id")
		table.Index("ip_address")
		table.Index("request_path")
		table.Index("request_method")
		table.Index("status_code")
		table.Index("session_id")
		table.Index("request_id")
		table.Index("risk_score")
		table.Index("threat_level")
		table.Index("event_timestamp")
		table.Index("tenant_id")

		// Composite indexes for common query patterns
		table.Index("tenant_id", "category")
		table.Index("tenant_id", "severity")
		table.Index("tenant_id", "event_timestamp")
		table.Index("subject_id", "event_timestamp")
		table.Index("causer_id", "event_timestamp")
		table.Index("ip_address", "event_timestamp")
		table.Index("category", "severity", "event_timestamp")
		table.Index("tenant_id", "risk_score", "event_timestamp")

		// Security-focused indexes
		table.Index("log_name", "subject_id", "event_timestamp")
		table.Index("status", "event_timestamp")
		table.Index("threat_level", "event_timestamp")

		// Performance indexes for analytics
		table.Index("tenant_id", "category", "event_timestamp")
		table.Index("created_at", "tenant_id")

		// Soft delete index
		table.Index("deleted_at", "tenant_id")

		// Foreign key constraints (commented out due to potential circular dependencies)
		// table.Foreign("tenant_id").References("id").On("tenants").OnDelete("cascade")
		// table.Foreign("subject_id").References("id").On("users").OnDelete("set null")
		// table.Foreign("causer_id").References("id").On("users").OnDelete("set null")
		// table.Foreign("created_by").References("id").On("users").OnDelete("set null")
		// table.Foreign("updated_by").References("id").On("users").OnDelete("set null")
		// table.Foreign("deleted_by").References("id").On("users").OnDelete("set null")

		// Note: Check constraints would be added here in production for data integrity:
		// - risk_score between 0 and 100
		// - severity enum validation
		// - status enum validation
		// - category enum validation
	})
}

// Down Reverse the migrations.
func (r *M20250115000007CreateActivityLogsTable) Down() error {
	return facades.Schema().DropIfExists("activity_logs")
}
