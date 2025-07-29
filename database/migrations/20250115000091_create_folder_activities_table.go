package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000091CreateFolderActivitiesTable struct{}

// Signature The unique signature for the migration.
func (r *M20250115000091CreateFolderActivitiesTable) Signature() string {
	return "20250115000091_create_folder_activities_table"
}

// Up Run the migrations.
func (r *M20250115000091CreateFolderActivitiesTable) Up() error {
	return facades.Schema().Create("folder_activities", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique activity identifier")

		// Activity information
		table.String("action").Comment("Activity type (create, rename, move, delete, share, etc.)")
		table.Text("description").Nullable().Comment("Activity description")
		table.String("ip_address").Nullable().Comment("IP address of the user")
		table.Text("user_agent").Nullable().Comment("User agent")
		table.Json("metadata").Nullable().Comment("Additional metadata")

		// Relationships
		table.Ulid("folder_id").Comment("Folder ID the activity belongs to")
		table.Ulid("user_id").Nullable().Comment("User who performed the activity")
		table.Ulid("organization_id").Nullable().Comment("Organization ID")

		// Timestamps
		table.TimestampsTz()

		// Indexes
		table.Index("folder_id")
		table.Index("user_id")
		table.Index("organization_id")
		table.Index("action")
		table.Index("created_at")

		// Foreign key constraints
		table.Foreign("folder_id").References("id").On("folders")
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("organization_id").References("id").On("organizations")
	})
}

// Down Reverse the migrations.
func (r *M20250115000091CreateFolderActivitiesTable) Down() error {
	return facades.Schema().DropIfExists("folder_activities")
}
