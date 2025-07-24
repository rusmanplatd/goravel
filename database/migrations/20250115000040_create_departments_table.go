package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000040CreateDepartmentsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000040CreateDepartmentsTable) Signature() string {
	return "20250115000040_create_departments_table"
}

// Up Run the migrations.
func (r *M20250115000040CreateDepartmentsTable) Up() error {
	return facades.Schema().Create("departments", func(table schema.Blueprint) {
		table.Ulid("id")
		table.String("name")
		table.String("code").Nullable()
		table.Text("description")
		table.String("color").Nullable()
		table.String("icon").Nullable()
		table.Boolean("is_active").Default(true)
		table.Ulid("organization_id")
		table.Ulid("parent_department_id").Nullable()
		table.Integer("level").Default(0)
		table.String("path")
		table.Ulid("manager_id").Nullable()
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("name")
		table.Index("code")
		table.Index("is_active")
		table.Index("organization_id")
		table.Index("parent_department_id")
		table.Index("level")
		table.Index("path")
		table.Index("manager_id")

		// Add foreign key constraints
		table.Foreign("organization_id").References("id").On("organizations")
		table.Foreign("parent_department_id").References("id").On("departments")
		table.Foreign("manager_id").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000040CreateDepartmentsTable) Down() error {
	return facades.Schema().DropIfExists("departments")
}
