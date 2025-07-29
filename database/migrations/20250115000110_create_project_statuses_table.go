package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000110CreateProjectStatusesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000110CreateProjectStatusesTable) Signature() string {
	return "20250115000110_create_project_statuses_table"
}

// Up Run the migrations.
func (r *M20250115000110CreateProjectStatusesTable) Up() error {
	return facades.Schema().Create("project_statuses", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique status identifier")
		table.String("name").Comment("Status name")
		table.Text("description").Comment("Status description")
		table.String("color").Comment("Status color (hex code)")
		table.String("icon").Nullable().Comment("Status icon")
		table.String("type").Default("custom").Comment("Status type (todo, in_progress, done, custom)")
		table.Integer("position").Default(0).Comment("Status position/order")
		table.Boolean("is_active").Default(true).Comment("Whether status is active")
		table.Boolean("is_default").Default(false).Comment("Whether this is a default status")
		table.Ulid("project_id").Comment("Project reference")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("name")
		table.Index("type")
		table.Index("position")
		table.Index("is_active")
		table.Index("is_default")
		table.Index("project_id")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add unique constraint for name per project
		table.Unique("project_id", "name")

		// Add foreign key constraints
		table.Foreign("project_id").References("id").On("projects")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000110CreateProjectStatusesTable) Down() error {
	return facades.Schema().DropIfExists("project_statuses")
}
