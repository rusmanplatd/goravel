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
		table.Ulid("id")
		table.String("log_name")
		table.Text("description")
		table.String("subject_type")
		table.Ulid("subject_id")
		table.String("causer_type")
		table.Ulid("causer_id")
		table.Json("properties")
		table.Ulid("tenant_id")
		table.TimestampsTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("log_name")
		table.Index("subject_type")
		table.Index("subject_id")
		table.Index("causer_type")
		table.Index("causer_id")
		table.Index("tenant_id")
		table.Index("created_at")

		// Foreign keys - commented out due to type mismatch
		// table.Foreign("tenant_id").References("id").On("tenants")
	})
}

// Down Reverse the migrations.
func (r *M20250115000007CreateActivityLogsTable) Down() error {
	return facades.Schema().DropIfExists("activity_logs")
}
