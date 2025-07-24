package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000047CreateTeamProjectsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000047CreateTeamProjectsTable) Signature() string {
	return "20250115000047_create_team_projects_table"
}

// Up Run the migrations.
func (r *M20250115000047CreateTeamProjectsTable) Up() error {
	return facades.Schema().Create("team_projects", func(table schema.Blueprint) {
		table.Ulid("team_id").Comment("Team reference")
		table.Ulid("project_id").Comment("Project reference")
		table.String("role").Default("contributor").Comment("Team role in project (owner, contributor, viewer)")
		table.Boolean("is_active").Default(true).Comment("Whether team is active in project")
		table.TimestampTz("joined_at").Comment("When team joined the project")
		table.Float("allocation").Default(100).Comment("Team's time allocation percentage (0-100)")

		// Primary key
		table.Primary("team_id", "project_id")

		// Add indexes
		table.Index("team_id")
		table.Index("project_id")
		table.Index("role")
		table.Index("is_active")
		table.Index("allocation")

		// Add foreign key constraints
		table.Foreign("team_id").References("id").On("teams")
		table.Foreign("project_id").References("id").On("projects")
	})
}

// Down Reverse the migrations.
func (r *M20250115000047CreateTeamProjectsTable) Down() error {
	return facades.Schema().DropIfExists("team_projects")
}
