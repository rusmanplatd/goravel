package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000051CreateMilestonesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000051CreateMilestonesTable) Signature() string {
	return "20250115000051_create_milestones_table"
}

// Up Run the migrations.
func (r *M20250115000051CreateMilestonesTable) Up() error {
	return facades.Schema().Create("milestones", func(table schema.Blueprint) {
		table.Ulid("id")
		table.String("title")
		table.Text("description")
		table.String("status").Default("open")
		table.String("color").Nullable()
		table.String("icon").Nullable()
		table.Ulid("project_id")
		table.Ulid("created_by")
		table.TimestampTz("due_date").Nullable()
		table.TimestampTz("completed_at").Nullable()
		table.Float("progress").Default(0)
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("title")
		table.Index("status")
		table.Index("project_id")
		table.Index("created_by")
		table.Index("due_date")
		table.Index("completed_at")

		// Add foreign key constraints
		table.Foreign("project_id").References("id").On("projects")
		table.Foreign("created_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000051CreateMilestonesTable) Down() error {
	return facades.Schema().DropIfExists("milestones")
}
