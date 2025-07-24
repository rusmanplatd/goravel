package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000044CreateUserDepartmentsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000044CreateUserDepartmentsTable) Signature() string {
	return "20250115000044_create_user_departments_table"
}

// Up Run the migrations.
func (r *M20250115000044CreateUserDepartmentsTable) Up() error {
	return facades.Schema().Create("user_departments", func(table schema.Blueprint) {
		table.Ulid("user_id")
		table.Ulid("department_id")
		table.String("role").Default("member")
		table.Boolean("is_active").Default(true)
		table.TimestampTz("joined_at")

		// Primary key
		table.Primary("user_id", "department_id")

		// Add indexes
		table.Index("user_id")
		table.Index("department_id")
		table.Index("role")
		table.Index("is_active")

		// Add foreign key constraints
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("department_id").References("id").On("departments")
	})
}

// Down Reverse the migrations.
func (r *M20250115000044CreateUserDepartmentsTable) Down() error {
	return facades.Schema().DropIfExists("user_departments")
}
