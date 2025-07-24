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
		table.Ulid("user_id").Comment("User reference")
		table.Ulid("project_id").Comment("Project reference")
		table.String("role").Default("member").Comment("User role in project (manager, member, viewer)")
		table.Boolean("is_active").Default(true).Comment("Whether user is active in project")
		table.TimestampTz("joined_at").Comment("When user joined the project")
		table.Float("allocation").Default(100).Comment("User's time allocation percentage (0-100)")

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
