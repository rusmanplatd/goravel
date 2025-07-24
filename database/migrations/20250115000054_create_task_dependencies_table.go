package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000054CreateTaskDependenciesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000054CreateTaskDependenciesTable) Signature() string {
	return "20250115000054_create_task_dependencies_table"
}

// Up Run the migrations.
func (r *M20250115000054CreateTaskDependenciesTable) Up() error {
	return facades.Schema().Create("task_dependencies", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique dependency identifier")
		table.Ulid("task_id").Comment("Task reference")
		table.Ulid("dependent_task_id").Comment("Dependent task reference")
		table.String("type").Default("blocks").Comment("Dependency type (blocks, requires, relates_to)")
		table.Boolean("is_active").Default(true).Comment("Whether dependency is active")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("task_id")
		table.Index("dependent_task_id")
		table.Index("type")
		table.Index("is_active")

		// Add foreign key constraints
		table.Foreign("task_id").References("id").On("tasks")
		table.Foreign("dependent_task_id").References("id").On("tasks")
	})
}

// Down Reverse the migrations.
func (r *M20250115000054CreateTaskDependenciesTable) Down() error {
	return facades.Schema().DropIfExists("task_dependencies")
}
