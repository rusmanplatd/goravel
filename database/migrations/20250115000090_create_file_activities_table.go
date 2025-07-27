package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000090CreateFileActivitiesTable struct{}

// Signature The unique signature for the migration.
func (r *M20250115000090CreateFileActivitiesTable) Signature() string {
	return "20250115000090_create_file_activities_table"
}

// Up Run the migrations.
func (r *M20250115000090CreateFileActivitiesTable) Up() error {
	return facades.Schema().Create("file_activities", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique activity identifier")

		// Activity information
		table.String("action").Comment("Activity type (upload, download, view, edit, delete, share, comment, etc.)")
		table.Text("description").Nullable().Comment("Activity description")
		table.String("ip_address").Nullable().Comment("IP address of the user")
		table.Text("user_agent").Nullable().Comment("User agent")
		table.Json("metadata").Nullable().Comment("Additional metadata")

		// Relationships
		table.Ulid("file_id").Comment("File ID the activity belongs to")
		table.Ulid("user_id").Nullable().Comment("User who performed the activity")
		table.Ulid("tenant_id").Nullable().Comment("Tenant/Organization ID")

		// Timestamps
		table.TimestampsTz()

		// Indexes
		table.Index("file_id")
		table.Index("user_id")
		table.Index("tenant_id")
		table.Index("action")
		table.Index("created_at")

		// Foreign key constraints
		table.Foreign("file_id").References("id").On("files")
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("tenant_id").References("id").On("tenants")
	})
}

// Down Reverse the migrations.
func (r *M20250115000090CreateFileActivitiesTable) Down() error {
	return facades.Schema().DropIfExists("file_activities")
}
