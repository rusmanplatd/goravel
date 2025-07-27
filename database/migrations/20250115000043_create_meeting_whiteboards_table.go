package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000043CreateMeetingWhiteboardsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000043CreateMeetingWhiteboardsTable) Signature() string {
	return "20250115000043_create_meeting_whiteboards_table"
}

// Up Run the migrations.
func (r *M20250115000043CreateMeetingWhiteboardsTable) Up() error {
	return facades.Schema().Create("meeting_whiteboards", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique whiteboard identifier")
		table.Ulid("meeting_id").Comment("Meeting reference")
		table.String("title").Comment("Whiteboard title")
		table.Text("description").Comment("Whiteboard description")
		table.Boolean("is_active").Comment("Whether whiteboard is currently active")
		table.Boolean("is_shared").Comment("Whether whiteboard is shared with all participants")
		table.Text("canvas_data").Comment("Canvas drawing data as JSON")
		table.String("canvas_version").Comment("Canvas version for conflict resolution")
		table.Integer("width").Comment("Canvas width in pixels")
		table.Integer("height").Comment("Canvas height in pixels")
		table.String("background_color").Comment("Canvas background color")
		table.Text("collaborators").Comment("List of collaborator user IDs as JSON")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("Whiteboard creator reference")
		table.Ulid("updated_by").Comment("Whiteboard updater reference")
		table.Ulid("deleted_by").Nullable().Comment("Whiteboard deleter reference")

		// Primary key
		table.Primary("id")

		// Foreign keys
		table.Foreign("meeting_id").References("id").On("meetings")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")

		// Indexes
		table.Index("meeting_id")
		table.Index("is_active")
		table.Index("is_shared")
		table.Index("created_by")
	})
}

// Down Reverse the migrations.
func (r *M20250115000043CreateMeetingWhiteboardsTable) Down() error {
	return facades.Schema().DropIfExists("meeting_whiteboards")
}
