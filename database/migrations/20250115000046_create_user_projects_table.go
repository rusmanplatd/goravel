package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000046CreateUserProjectsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000046CreateUserProjectsTable) Signature() string {
	return "20250115000046_create_user_projects_table"
}

// Up Run the migrations.
func (r *M20250115000046CreateUserProjectsTable) Up() error {
	return facades.Schema().Create("user_projects", func(table schema.Blueprint) {
		table.Ulid("user_id")
		table.Ulid("project_id")
		table.String("role").Default("member")
		table.Boolean("is_active").Default(true)
		table.TimestampTz("joined_at")
		table.Float("allocation").Default(100)

		// Primary key
		table.Primary("user_id", "project_id")

		// Add indexes
		table.Index("user_id")
		table.Index("project_id")
		table.Index("role")
		table.Index("is_active")
		table.Index("allocation")

		// Add foreign key constraints
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("project_id").References("id").On("projects")
	})
}

// Down Reverse the migrations.
func (r *M20250115000046CreateUserProjectsTable) Down() error {
	return facades.Schema().DropIfExists("user_projects")
}
