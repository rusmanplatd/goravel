package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000041CreateTeamsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000041CreateTeamsTable) Signature() string {
	return "20250115000041_create_teams_table"
}

// Up Run the migrations.
func (r *M20250115000041CreateTeamsTable) Up() error {
	return facades.Schema().Create("teams", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique team identifier")
		table.String("name").Comment("Team name")
		table.String("code").Nullable().Comment("Team code")
		table.Text("description").Comment("Team description")
		table.String("type").Default("functional").Comment("Team type (functional, project, cross-functional)")
		table.String("color").Nullable().Comment("Team color for UI display")
		table.String("icon").Nullable().Comment("Team icon for UI display")
		table.Boolean("is_active").Default(true).Comment("Whether team is active")
		table.Ulid("organization_id").Comment("Organization reference")
		table.Ulid("department_id").Nullable().Comment("Department reference")
		table.Ulid("team_lead_id").Nullable().Comment("Team lead reference")
		table.Integer("max_size").Default(10).Comment("Maximum team size")
		table.Integer("current_size").Default(0).Comment("Current team size")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("name")
		table.Index("code")
		table.Index("type")
		table.Index("is_active")
		table.Index("organization_id")
		table.Index("department_id")
		table.Index("team_lead_id")

		// Add foreign key constraints
		table.Foreign("organization_id").References("id").On("organizations")
		table.Foreign("department_id").References("id").On("departments")
		table.Foreign("team_lead_id").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000041CreateTeamsTable) Down() error {
	return facades.Schema().DropIfExists("teams")
}
