package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000112CreateProjectAutomationsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000112CreateProjectAutomationsTable) Signature() string {
	return "20250115000112_create_project_automations_table"
}

// Up Run the migrations.
func (r *M20250115000112CreateProjectAutomationsTable) Up() error {
	return facades.Schema().Create("project_automations", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique automation identifier")
		table.String("name").Comment("Automation name")
		table.Text("description").Comment("Automation description")
		table.String("trigger_event").Comment("Automation trigger event")
		table.Json("conditions").Comment("Automation conditions")
		table.Json("actions").Comment("Automation actions")
		table.Boolean("is_enabled").Default(true).Comment("Whether automation is enabled")
		table.Integer("runs_count").Default(0).Comment("Automation runs count")
		table.TimestampTz("last_run_at").Nullable().Comment("Last run timestamp")
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
		table.Index("trigger_event")
		table.Index("is_enabled")
		table.Index("runs_count")
		table.Index("last_run_at")
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
func (r *M20250115000112CreateProjectAutomationsTable) Down() error {
	return facades.Schema().DropIfExists("project_automations")
}
