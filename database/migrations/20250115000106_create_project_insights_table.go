package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000106CreateProjectInsightsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000106CreateProjectInsightsTable) Signature() string {
	return "20250115000106_create_project_insights_table"
}

// Up Run the migrations.
func (r *M20250115000106CreateProjectInsightsTable) Up() error {
	return facades.Schema().Create("project_insights", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique insight identifier")
		table.String("type").Comment("Insight type (velocity, burndown, completion_rate, task_distribution)")
		table.String("period").Comment("Insight period (daily, weekly, monthly, quarterly)")
		table.TimestampTz("date").Comment("Insight date")
		table.Json("data").Comment("Insight data as JSON")
		table.Ulid("project_id").Comment("Project reference")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("type")
		table.Index("period")
		table.Index("date")
		table.Index("project_id")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add foreign key constraints
		table.Foreign("project_id").References("id").On("projects")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")

		// Unique constraint for type + period + date + project
		table.Unique("type", "period", "date", "project_id")
	})
}

// Down Reverse the migrations.
func (r *M20250115000106CreateProjectInsightsTable) Down() error {
	return facades.Schema().DropIfExists("project_insights")
}
