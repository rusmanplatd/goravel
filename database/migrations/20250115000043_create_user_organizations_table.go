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
		table.Ulid("user_id")
		table.Ulid("organization_id")
		table.String("role").Default("member")
		table.String("status").Default("active")
		table.Boolean("is_active").Default(true)
		table.TimestampTz("joined_at")
		table.TimestampTz("expires_at").Nullable()
		table.String("title").Nullable()
		table.String("employee_id").Nullable()
		table.Ulid("department_id").Nullable()
		table.Ulid("team_id").Nullable()
		table.Ulid("manager_id").Nullable()
		table.TimestampTz("hire_date").Nullable()
		table.TimestampTz("termination_date").Nullable()
		table.Text("salary").Nullable()
		table.Json("permissions")

		// Primary key
		table.Primary("user_id", "organization_id")

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
	})
}

// Down Reverse the migrations.
func (r *M20250115000043CreateUserOrganizationsTable) Down() error {
	return facades.Schema().DropIfExists("user_organizations")
}
