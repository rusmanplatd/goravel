package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000111CreateProjectIterationsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000111CreateProjectIterationsTable) Signature() string {
	return "20250115000111_create_project_iterations_table"
}

// Up Run the migrations.
func (r *M20250115000111CreateProjectIterationsTable) Up() error {
	return facades.Schema().Create("project_iterations", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique iteration identifier")
		table.String("title").Comment("Iteration title")
		table.Text("description").Comment("Iteration description")
		table.TimestampTz("start_date").Nullable().Comment("Iteration start date")
		table.TimestampTz("end_date").Nullable().Comment("Iteration end date")
		table.Integer("duration").Default(0).Comment("Iteration duration in days")
		table.String("status").Default("planning").Comment("Iteration status (planning, active, completed)")
		table.Boolean("is_current").Default(false).Comment("Whether iteration is current")
		table.Ulid("project_id").Comment("Project reference")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("title")
		table.Index("status")
		table.Index("is_current")
		table.Index("start_date")
		table.Index("end_date")
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
func (r *M20250115000111CreateProjectIterationsTable) Down() error {
	return facades.Schema().DropIfExists("project_iterations")
}
