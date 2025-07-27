package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000115CreateUserEmploymentHistoryTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000115CreateUserEmploymentHistoryTable) Signature() string {
	return "20250115000115_create_user_employment_history_table"
}

// Up Run the migrations.
func (r *M20250115000115CreateUserEmploymentHistoryTable) Up() error {
	return facades.Schema().Create("user_employment_history", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique employment history identifier")
		table.Ulid("user_id").Comment("User reference")
		table.Ulid("organization_id").Comment("Organization reference")
		table.Ulid("job_position_id").Nullable().Comment("Job position reference")
		table.Ulid("job_level_id").Nullable().Comment("Job level reference")
		table.Ulid("department_id").Nullable().Comment("Department reference")
		table.Ulid("team_id").Nullable().Comment("Team reference")
		table.Ulid("manager_id").Nullable().Comment("Manager reference")
		table.String("job_title").Comment("Job title at the time")
		table.String("employee_id").Nullable().Comment("Employee ID at the time")
		table.String("employment_type").Default("full_time").Comment("Employment type (full_time, part_time, contract, intern)")
		table.String("change_type").Comment("Change type (hire, promotion, transfer, demotion, termination, role_change)")
		table.Text("change_reason").Nullable().Comment("Reason for the change")
		table.TimestampTz("effective_date").Comment("Effective date of the change")
		table.TimestampTz("end_date").Nullable().Comment("End date of this position (null if current)")
		table.Boolean("is_current").Default(false).Comment("Whether this is the current position")
		table.Text("salary").Nullable().Comment("Salary at the time (encrypted)")
		table.String("currency").Default("USD").Comment("Currency for salary")
		table.Float("performance_rating").Nullable().Comment("Performance rating at the time of change")
		table.Text("notes").Nullable().Comment("Additional notes about the employment change")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("user_id")
		table.Index("organization_id")
		table.Index("job_position_id")
		table.Index("job_level_id")
		table.Index("department_id")
		table.Index("team_id")
		table.Index("manager_id")
		table.Index("change_type")
		table.Index("effective_date")
		table.Index("end_date")
		table.Index("is_current")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add composite indexes for common queries
		table.Index("user_id,organization_id", "idx_user_org_history")
		table.Index("user_id,is_current", "idx_user_current_position")
		table.Index("organization_id,change_type", "idx_org_change_type")
		table.Index("effective_date,end_date", "idx_employment_period")

		// Add foreign key constraints
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("organization_id").References("id").On("organizations")
		table.Foreign("job_position_id").References("id").On("job_positions")
		table.Foreign("job_level_id").References("id").On("job_levels")
		table.Foreign("department_id").References("id").On("departments")
		table.Foreign("team_id").References("id").On("teams")
		table.Foreign("manager_id").References("id").On("users")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000115CreateUserEmploymentHistoryTable) Down() error {
	return facades.Schema().DropIfExists("user_employment_history")
}
