package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000088CreateFolderSharesTable struct{}

// Signature The unique signature for the migration.
func (r *M20250115000088CreateFolderSharesTable) Signature() string {
	return "20250115000088_create_folder_shares_table"
}

// Up Run the migrations.
func (r *M20250115000088CreateFolderSharesTable) Up() error {
	return facades.Schema().Create("folder_shares", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique share identifier")

		// Share configuration
		table.String("share_type").Comment("Share type (user, link, email)")
		table.String("permission").Comment("Permission level (view, edit, comment, owner)")
		table.Boolean("is_active").Default(true).Comment("Whether share is active")
		table.TimestampTz("expires_at").Nullable().Comment("Share expiration date")
		table.String("share_token").Nullable().Comment("Share token for link sharing")
		table.String("email").Nullable().Comment("Email for email sharing")
		table.Text("message").Nullable().Comment("Share message")

		// Security
		table.Boolean("require_password").Default(false).Comment("Whether password is required for access")
		table.String("password").Nullable().Comment("Password for protected sharing")
		table.Boolean("include_subfolders").Default(true).Comment("Whether to include subfolders")

		// Access tracking
		table.TimestampTz("last_accessed_at").Nullable().Comment("Last accessed time")

		// Relationships
		table.Ulid("folder_id").Comment("Folder ID being shared")
		table.Ulid("shared_with_id").Nullable().Comment("User being shared with (for user shares)")
		table.Ulid("shared_by_id").Comment("User who created the share")

		// Timestamps
		table.TimestampsTz()

		// Indexes
		table.Index("folder_id")
		table.Index("shared_with_id")
		table.Index("shared_by_id")
		table.Index("share_type")
		table.Index("permission")
		table.Index("is_active")
		table.Index("expires_at")
		table.Index("created_at")

		// Unique index for share token
		table.Unique("share_token")

		// Foreign key constraints
		table.Foreign("folder_id").References("id").On("folders")
		table.Foreign("shared_with_id").References("id").On("users")
		table.Foreign("shared_by_id").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000088CreateFolderSharesTable) Down() error {
	return facades.Schema().DropIfExists("folder_shares")
}
