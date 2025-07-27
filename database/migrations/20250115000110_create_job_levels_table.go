package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000110CreateJobLevelsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000110CreateJobLevelsTable) Signature() string {
	return "20250115000110_create_job_levels_table"
}

// Up Run the migrations.
func (r *M20250115000110CreateJobLevelsTable) Up() error {
	return facades.Schema().Create("job_levels", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique job level identifier")
		table.String("name").Comment("Job level name (e.g., Junior, Senior, Lead, Manager)")
		table.Text("description").Comment("Job level description")
		table.Integer("level_order").Comment("Hierarchical order of the level (1=lowest, higher numbers=higher levels)")
		table.String("code").Nullable().Comment("Job level code/abbreviation")
		table.String("color").Nullable().Comment("Job level color for UI display")
		table.String("icon").Nullable().Comment("Job level icon for UI display")
		table.Boolean("is_active").Default(true).Comment("Whether job level is active")
		table.Float("min_salary").Nullable().Comment("Minimum salary range for this level")
		table.Float("max_salary").Nullable().Comment("Maximum salary range for this level")
		table.String("currency").Default("USD").Comment("Currency for salary range")
		table.Json("requirements").Comment("Job level requirements (experience, skills, etc.)")
		table.Json("benefits").Comment("Job level benefits and perks")
		table.Ulid("organization_id").Comment("Organization reference")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("name")
		table.Index("code")
		table.Index("level_order")
		table.Index("is_active")
		table.Index("organization_id")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add unique constraint for name within organization
		table.Unique("name,organization_id", "unique_job_level_name_per_org")
		table.Unique("code,organization_id", "unique_job_level_code_per_org")
		table.Unique("level_order,organization_id", "unique_job_level_order_per_org")

		// Add foreign key constraints
		table.Foreign("organization_id").References("id").On("organizations")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000110CreateJobLevelsTable) Down() error {
	return facades.Schema().DropIfExists("job_levels")
}
