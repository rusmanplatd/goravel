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
		table.Ulid("id").Comment("Unique department identifier")
		table.String("name").Comment("Department name")
		table.String("code").Nullable().Comment("Department code")
		table.Text("description").Comment("Department description")
		table.String("color").Nullable().Comment("Department color for UI display")
		table.String("icon").Nullable().Comment("Department icon for UI display")
		table.Boolean("is_active").Default(true).Comment("Whether department is active")
		table.Ulid("organization_id").Comment("Organization reference")
		table.Ulid("parent_department_id").Nullable().Comment("Parent department reference")
		table.Integer("level").Default(0).Comment("Hierarchy level in department tree")
		table.String("path").Comment("Hierarchical path in department tree")
		table.Ulid("manager_id").Nullable().Comment("Department manager reference")
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
