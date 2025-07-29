package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type CreateUserCalendarsTable struct{}

// Signature The name and signature of the migration.
func (r *CreateUserCalendarsTable) Signature() string {
	return "20250115000150_create_user_calendars_table"
}

// Up Run the migrations.
func (r *CreateUserCalendarsTable) Up() error {
	return facades.Schema().Create("user_calendars", func(table schema.Blueprint) {
		table.Ulid("id")
		table.String("name")
		table.Text("description").Nullable()
		table.String("color").Default("#1976d2")
		table.String("type").Default("personal")
		table.Boolean("is_visible").Default(true)
		table.Boolean("is_default").Default(false)
		table.String("timezone").Default("UTC")
		table.String("visibility").Default("private")
		table.Boolean("notifications_enabled").Default(true)
		table.Text("default_reminders").Nullable()
		table.Text("external_settings").Nullable()
		table.TimestampTz("last_sync_at").Nullable()
		table.String("sync_status").Default("none")
		table.Text("sync_error").Nullable()
		table.Integer("sort_order").Default(0)
		table.String("user_id")
		table.String("organization_id")
		table.String("created_by").Nullable()
		table.String("updated_by").Nullable()
		table.TimestampsTz()
	})
}

// Down Reverse the migrations.
func (r *CreateUserCalendarsTable) Down() error {
	return facades.Schema().DropIfExists("user_calendars")
}
