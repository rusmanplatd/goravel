package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000101CreateProjectCustomFieldsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000101CreateProjectCustomFieldsTable) Signature() string {
	return "20250115000101_create_project_custom_fields_table"
}

// Up Run the migrations.
func (r *M20250115000101CreateProjectCustomFieldsTable) Up() error {
	return facades.Schema().Create("project_custom_fields", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique field identifier")
		table.String("name").Comment("Field name")
		table.Text("description").Comment("Field description")
		table.String("type").Comment("Field type (text, number, date, select, multi_select, checkbox, url, email)")
		table.Json("options").Comment("Field options for select fields")
		table.Boolean("is_required").Default(false).Comment("Whether field is required")
		table.Integer("position").Default(0).Comment("Field position/order")
		table.Boolean("is_active").Default(true).Comment("Whether field is active")
		table.Ulid("project_id").Comment("Project reference")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("name")
		table.Index("type")
		table.Index("is_required")
		table.Index("position")
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
func (r *M20250115000101CreateProjectCustomFieldsTable) Down() error {
	return facades.Schema().DropIfExists("project_custom_fields")
}
