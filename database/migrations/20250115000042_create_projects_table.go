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
		table.Ulid("id")
		table.String("name")
		table.String("code").Nullable()
		table.Text("description")
		table.String("status").Default("planning")
		table.String("priority").Default("medium")
		table.String("color").Nullable()
		table.String("icon").Nullable()
		table.Boolean("is_active").Default(true)
		table.Ulid("organization_id")
		table.Ulid("project_manager_id").Nullable()
		table.TimestampTz("start_date").Nullable()
		table.TimestampTz("end_date").Nullable()
		table.Float("budget").Default(0)
		table.Float("progress").Default(0)
		table.Json("settings")
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

		// Add foreign key constraints
		table.Foreign("organization_id").References("id").On("organizations")
		table.Foreign("project_manager_id").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000042CreateProjectsTable) Down() error {
	return facades.Schema().DropIfExists("projects")
}
