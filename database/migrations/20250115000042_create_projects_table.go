package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000042CreateProjectsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000042CreateProjectsTable) Signature() string {
	return "20250115000042_create_projects_table"
}

// Up Run the migrations.
func (r *M20250115000042CreateProjectsTable) Up() error {
	return facades.Schema().Create("projects", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique project identifier")
		table.String("name").Comment("Project name")
		table.String("code").Nullable().Comment("Project code/identifier")
		table.Text("description").Comment("Project description")
		table.String("status").Default("planning").Comment("Project status (planning, active, on_hold, completed, cancelled)")
		table.String("priority").Default("medium").Comment("Project priority (low, medium, high, urgent)")
		table.String("color").Nullable().Comment("Project color for UI display")
		table.String("icon").Nullable().Comment("Project icon for UI display")
		table.Boolean("is_active").Default(true).Comment("Whether project is active")
		table.Ulid("organization_id").Comment("Organization reference")
		table.Ulid("project_manager_id").Nullable().Comment("Project manager reference")
		table.TimestampTz("start_date").Nullable().Comment("Project start date")
		table.TimestampTz("end_date").Nullable().Comment("Project end date")
		table.Float("budget").Default(0).Comment("Project budget")
		table.Float("progress").Default(0).Comment("Project completion percentage (0-100)")
		table.Json("settings").Comment("Project-specific settings")
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("name")
		table.Index("code")
		table.Index("status")
		table.Index("priority")
		table.Index("is_active")
		table.Index("organization_id")
		table.Index("project_manager_id")
		table.Index("start_date")
		table.Index("end_date")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add foreign key constraints
		table.Foreign("organization_id").References("id").On("organizations")
		table.Foreign("project_manager_id").References("id").On("users")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000042CreateProjectsTable) Down() error {
	return facades.Schema().DropIfExists("projects")
}
