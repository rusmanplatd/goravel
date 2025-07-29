package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000121CreateMeetingTemplatesTable struct{}

// Signature The name and signature of the console command.
func (r *M20250115000121CreateMeetingTemplatesTable) Signature() string {
	return "20250115000121_create_meeting_templates_table"
}

// Up Run the migrations.
func (r *M20250115000121CreateMeetingTemplatesTable) Up() error {
	return facades.Schema().Create("meeting_templates", func(table schema.Blueprint) {
		table.ID()
		table.String("name").Comment("Template name")
		table.Text("description").Nullable().Comment("Template description")
		table.String("category").Default("general").Comment("Template category")
		table.String("created_by").Comment("User ID who created this template")
		table.Boolean("is_public").Default(false).Comment("Whether this template is publicly available")
		table.Boolean("is_active").Default(true).Comment("Whether this template is active/enabled")
		table.Integer("usage_count").Default(0).Comment("Number of times this template has been used")
		table.String("version").Default("1.0.0").Comment("Template version for tracking changes")
		table.Json("tags").Nullable().Comment("Template tags for categorization and search")
		table.Json("default_settings").Nullable().Comment("Default meeting settings stored as JSON")
		table.Text("agenda_template").Nullable().Comment("Meeting agenda template")
		table.Integer("default_duration").Default(60).Comment("Default meeting duration in minutes")
		table.String("default_meeting_type").Default("video").Comment("Default meeting type")
		table.String("default_platform").Default("teams").Comment("Default platform")
		table.Json("default_participant_settings").Nullable().Comment("Default participant roles and permissions")
		table.Json("default_security_settings").Nullable().Comment("Default security settings")
		table.Json("default_notification_settings").Nullable().Comment("Default notification settings")
		table.String("thumbnail_url").Nullable().Comment("Template thumbnail/icon URL")
		table.String("color_theme").Nullable().Comment("Template color theme")
		table.Json("metadata").Nullable().Comment("Template metadata for extensibility")
		table.TimestampTz("last_used_at").Nullable().Comment("When the template was last used")
		table.Timestamps()

		// Indexes for performance
		table.Index("created_by")
		table.Index("category")
		table.Index("is_public")
		table.Index("is_active")
		table.Index("usage_count")
		table.Index("last_used_at")
	})
}

// Down Reverse the migrations.
func (r *M20250115000121CreateMeetingTemplatesTable) Down() error {
	return facades.Schema().DropIfExists("meeting_templates")
}
