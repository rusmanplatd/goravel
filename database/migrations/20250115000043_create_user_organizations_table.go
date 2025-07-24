package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000043CreateUserOrganizationsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000043CreateUserOrganizationsTable) Signature() string {
	return "20250115000043_create_user_organizations_table"
}

// Up Run the migrations.
func (r *M20250115000043CreateUserOrganizationsTable) Up() error {
	return facades.Schema().Create("user_organizations", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique identifier")
		table.Ulid("user_id").Comment("User reference")
		table.Ulid("organization_id").Comment("Organization reference")
		table.String("role").Default("member").Comment("User role in organization (owner, admin, member)")
		table.String("status").Default("active").Comment("User status (active, inactive, suspended)")
		table.Boolean("is_active").Default(true).Comment("Whether user is active in organization")
		table.TimestampTz("joined_at").Comment("When user joined the organization")
		table.TimestampTz("expires_at").Nullable().Comment("When user membership expires")
		table.String("title").Nullable().Comment("User's job title")
		table.String("employee_id").Nullable().Comment("Employee ID")
		table.Ulid("department_id").Nullable().Comment("Department reference")
		table.Ulid("team_id").Nullable().Comment("Team reference")
		table.Ulid("manager_id").Nullable().Comment("Manager reference")
		table.TimestampTz("hire_date").Nullable().Comment("When user was hired")
		table.TimestampTz("termination_date").Nullable().Comment("When user was terminated")
		table.Text("salary").Nullable().Comment("User's salary information")
		table.Json("permissions").Comment("User-specific permissions")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("user_id")
		table.Index("organization_id")
		table.Index("role")
		table.Index("status")
		table.Index("is_active")
		table.Index("department_id")
		table.Index("team_id")
		table.Index("manager_id")
		table.Index("hire_date")
		table.Index("termination_date")

		// Add foreign key constraints
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("organization_id").References("id").On("organizations")
		table.Foreign("department_id").References("id").On("departments")
		table.Foreign("team_id").References("id").On("teams")
		table.Foreign("manager_id").References("id").On("users")

		// Unique constraint
		table.Unique("user_id", "organization_id")
	})
}

// Down Reverse the migrations.
func (r *M20250115000043CreateUserOrganizationsTable) Down() error {
	return facades.Schema().DropIfExists("user_organizations")
}
