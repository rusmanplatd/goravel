package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000045CreateUserTeamsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000045CreateUserTeamsTable) Signature() string {
	return "20250115000045_create_user_teams_table"
}

// Up Run the migrations.
func (r *M20250115000045CreateUserTeamsTable) Up() error {
	return facades.Schema().Create("user_teams", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique identifier")
		table.Ulid("user_id").Comment("User reference")
		table.Ulid("team_id").Comment("Team reference")
		table.String("role").Default("member").Comment("User role in team (lead, member)")
		table.Boolean("is_active").Default(true).Comment("Whether user is active in team")
		table.TimestampTz("joined_at").Comment("When user joined the team")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("user_id")
		table.Index("team_id")
		table.Index("role")
		table.Index("is_active")

		// Add foreign key constraints
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("team_id").References("id").On("teams")

		// Unique constraints
		table.Unique("user_id", "team_id")
	})
}

// Down Reverse the migrations.
func (r *M20250115000045CreateUserTeamsTable) Down() error {
	return facades.Schema().DropIfExists("user_teams")
}
