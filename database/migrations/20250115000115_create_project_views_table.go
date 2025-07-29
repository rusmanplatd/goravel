package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type CreateProjectViewsTable struct{}

// Signature The name and signature of the console command.
func (receiver *CreateProjectViewsTable) Signature() string {
	return "20250115000115_create_project_views_table"
}

// Description The console command description.
func (receiver *CreateProjectViewsTable) Description() string {
	return "Create project_views table for GitHub Projects v2 style views"
}

// Up Run the migrations.
func (receiver *CreateProjectViewsTable) Up() error {
	return facades.Schema().Create("project_views", func(table schema.Blueprint) {
		table.String("id", 36)
		table.String("name")
		table.Text("description")

		// View type and configuration
		table.String("type", 50).Default("table")
		table.Json("layout")
		table.Json("filters")
		table.Json("sorting")
		table.Json("grouping")
		table.Json("columns")

		// View properties
		table.Boolean("is_default").Default(false)
		table.Boolean("is_public").Default(false)
		table.Boolean("is_template").Default(false)
		table.Integer("position").Default(0)

		// Relationships
		table.String("project_id", 36)
		table.String("created_by", 36)
		table.String("updated_by", 36)

		// Timestamps and soft deletes
		table.TimestampsTz()
		table.SoftDeletes()

		// Primary key
		table.Primary("id")

		// Indexes
		table.Index("project_id")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("type")
		table.Index("is_default")
		table.Index("is_public")
		table.Index("position")

		// Unique constraint for default views per project
		table.Unique("project_id", "name")

		// Foreign key constraints
		table.Foreign("project_id").References("id").On("projects")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (receiver *CreateProjectViewsTable) Down() error {
	return facades.Schema().DropIfExists("project_views")
}
