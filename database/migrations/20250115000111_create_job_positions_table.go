package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000111CreateJobPositionsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000111CreateJobPositionsTable) Signature() string {
	return "20250115000111_create_job_positions_table"
}

// Up Run the migrations.
func (r *M20250115000111CreateJobPositionsTable) Up() error {
	return facades.Schema().Create("job_positions", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique job position identifier")
		table.String("title").Comment("Job position title (e.g., Software Engineer, Product Manager)")
		table.Text("description").Comment("Job position description and responsibilities")
		table.String("code").Nullable().Comment("Job position code/abbreviation")
		table.String("color").Nullable().Comment("Job position color for UI display")
		table.String("icon").Nullable().Comment("Job position icon for UI display")
		table.Boolean("is_active").Default(true).Comment("Whether job position is active")
		table.Boolean("is_remote").Default(false).Comment("Whether position supports remote work")
		table.String("employment_type").Default("full_time").Comment("Employment type (full_time, part_time, contract, intern)")
		table.Float("min_salary").Nullable().Comment("Minimum salary range for this position")
		table.Float("max_salary").Nullable().Comment("Maximum salary range for this position")
		table.String("currency").Default("USD").Comment("Currency for salary range")
		table.Json("requirements").Comment("Job position requirements (skills, experience, etc.)")
		table.Json("responsibilities").Comment("Job position responsibilities and duties")
		table.Json("benefits").Comment("Job position benefits and perks")
		table.Ulid("job_level_id").Comment("Job level reference")
		table.Ulid("department_id").Nullable().Comment("Department reference")
		table.Ulid("organization_id").Comment("Organization reference")
		table.Ulid("reports_to_position_id").Nullable().Comment("Position this role reports to")
		table.Integer("headcount").Default(1).Comment("Number of positions available")
		table.Integer("filled_count").Default(0).Comment("Number of positions filled")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("title")
		table.Index("code")
		table.Index("is_active")
		table.Index("is_remote")
		table.Index("employment_type")
		table.Index("job_level_id")
		table.Index("department_id")
		table.Index("organization_id")
		table.Index("reports_to_position_id")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add unique constraint for title within organization and department
		table.Unique("title,organization_id,department_id", "unique_job_position_title_per_org_dept")
		table.Unique("code,organization_id", "unique_job_position_code_per_org")

		// Add foreign key constraints
		table.Foreign("job_level_id").References("id").On("job_levels")
		table.Foreign("department_id").References("id").On("departments")
		table.Foreign("organization_id").References("id").On("organizations")
		table.Foreign("reports_to_position_id").References("id").On("job_positions")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000111CreateJobPositionsTable) Down() error {
	return facades.Schema().DropIfExists("job_positions")
}
