package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000049CreateTaskLabelsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000049CreateTaskLabelsTable) Signature() string {
	return "20250115000049_create_task_labels_table"
}

// Up Run the migrations.
func (r *M20250115000049CreateTaskLabelsTable) Up() error {
	return facades.Schema().Create("task_labels", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique label identifier")
		table.String("name").Comment("Label name")
		table.Text("description").Comment("Label description")
		table.String("color").Comment("Label color for UI display")
		table.String("icon").Nullable().Comment("Label icon for UI display")
		table.Boolean("is_active").Default(true).Comment("Whether label is active")
		table.Ulid("project_id").Comment("Project reference")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("Label creator reference")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("name")
		table.Index("color")
		table.Index("is_active")
		table.Index("project_id")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add foreign key constraints
		table.Foreign("project_id").References("id").On("projects")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000049CreateTaskLabelsTable) Down() error {
	return facades.Schema().DropIfExists("task_labels")
}
