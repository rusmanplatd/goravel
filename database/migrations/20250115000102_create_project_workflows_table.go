package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000102CreateProjectWorkflowsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000102CreateProjectWorkflowsTable) Signature() string {
	return "20250115000102_create_project_workflows_table"
}

// Up Run the migrations.
func (r *M20250115000102CreateProjectWorkflowsTable) Up() error {
	return facades.Schema().Create("project_workflows", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique workflow identifier")
		table.String("name").Comment("Workflow name")
		table.Text("description").Comment("Workflow description")
		table.String("trigger").Comment("Workflow trigger (item_added, item_updated, field_changed, status_changed)")
		table.Json("conditions").Comment("Workflow conditions")
		table.Json("actions").Comment("Workflow actions")
		table.Boolean("is_active").Default(true).Comment("Whether workflow is active")
		table.Integer("position").Default(0).Comment("Workflow position/order")
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
		table.Index("trigger")
		table.Index("is_active")
		table.Index("position")
		table.Index("project_id")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add foreign key constraints
		table.Foreign("project_id").References("id").On("projects")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000102CreateProjectWorkflowsTable) Down() error {
	return facades.Schema().DropIfExists("project_workflows")
}
