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
		table.Ulid("id").Comment("Unique activity log identifier")
		table.String("log_name").Comment("Log name/category")
		table.Text("description").Comment("Activity description")
		table.String("subject_type").Comment("Subject model type")
		table.Ulid("subject_id").Comment("Subject model identifier")
		table.String("causer_type").Comment("Causer model type")
		table.Ulid("causer_id").Comment("Causer model identifier")
		table.Json("properties").Comment("Additional activity properties")
		table.Ulid("tenant_id").Comment("Tenant reference")
		table.TimestampsTz()

		// Add audit fields from BaseModel
		table.Ulid("created_by").Nullable().Comment("Creator reference")
		table.Ulid("updated_by").Nullable().Comment("Last updater reference")
		table.Timestamp("deleted_at").Nullable().Comment("Soft delete timestamp")
		table.Ulid("deleted_by").Nullable().Comment("Deleter reference")

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
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_at")
		table.Index("deleted_by")

		// Foreign keys - commented out due to type mismatch
		// table.Foreign("tenant_id").References("id").On("tenants")
		// table.Foreign("created_by").References("id").On("users")
		// table.Foreign("updated_by").References("id").On("users")
		// table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000007CreateActivityLogsTable) Down() error {
	return facades.Schema().DropIfExists("activity_logs")
}
