package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000021CreateChatRoomsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000021CreateChatRoomsTable) Signature() string {
	return "20250115000021_create_chat_rooms_table"
}

// Up Run the migrations.
func (r *M20250115000021CreateChatRoomsTable) Up() error {
	return facades.Schema().Create("chat_rooms", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique chat room identifier")
		table.String("name").Comment("Chat room name")
		table.Text("description").Comment("Chat room description")
		table.String("type").Comment("Chat room type (direct, group, channel)")
		table.Boolean("is_active").Comment("Whether chat room is active")
		table.String("avatar").Comment("Chat room avatar URL")
		table.Ulid("tenant_id").Comment("Tenant reference")
		table.Timestamp("last_activity_at").Comment("Last activity timestamp")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("tenant_id")
		table.Index("type")
		table.Index("last_activity_at")
		table.Index("tenant_id", "is_active")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add foreign key constraints
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000021CreateChatRoomsTable) Down() error {
	return facades.Schema().DropIfExists("chat_rooms")
}
