package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000103CreateTaskFieldValuesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000103CreateTaskFieldValuesTable) Signature() string {
	return "20250115000103_create_task_field_values_table"
}

// Up Run the migrations.
func (r *M20250115000103CreateTaskFieldValuesTable) Up() error {
	return facades.Schema().Create("task_field_values", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique field value identifier")
		table.Ulid("task_id").Comment("Task reference")
		table.Ulid("field_id").Comment("Custom field reference")
		table.Text("value").Comment("Field value as string")
		table.Json("value_json").Comment("Field value as JSON for complex types")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("task_id")
		table.Index("field_id")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add foreign key constraints
		table.Foreign("task_id").References("id").On("tasks")
		table.Foreign("field_id").References("id").On("project_custom_fields")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")

		// Unique constraint to prevent duplicate field values for same task
		table.Unique("task_id", "field_id")
	})
}

// Down Reverse the migrations.
func (r *M20250115000103CreateTaskFieldValuesTable) Down() error {
	return facades.Schema().DropIfExists("task_field_values")
}
