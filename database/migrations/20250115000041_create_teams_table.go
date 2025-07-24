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
		table.Ulid("id")
		table.String("name")
		table.String("code").Nullable()
		table.Text("description")
		table.String("type").Default("functional")
		table.String("color").Nullable()
		table.String("icon").Nullable()
		table.Boolean("is_active").Default(true)
		table.Ulid("organization_id")
		table.Ulid("department_id").Nullable()
		table.Ulid("team_lead_id").Nullable()
		table.Integer("max_size").Default(10)
		table.Integer("current_size").Default(0)
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
