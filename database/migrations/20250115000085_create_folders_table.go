package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000085CreateFoldersTable struct{}

// Signature The unique signature for the migration.
func (r *M20250115000085CreateFoldersTable) Signature() string {
	return "20250115000085_create_folders_table"
}

// Up Run the migrations.
func (r *M20250115000085CreateFoldersTable) Up() error {
	return facades.Schema().Create("folders", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique folder identifier")

		// Basic folder information
		table.String("name").Comment("Folder name")
		table.Text("description").Nullable().Comment("Folder description")
		table.String("color").Nullable().Comment("Folder color (hex code)")

		// Status and flags
		table.Boolean("is_public").Default(false).Comment("Whether folder is public")
		table.Boolean("is_starred").Default(false).Comment("Whether folder is starred/favorited")
		table.Boolean("is_trashed").Default(false).Comment("Whether folder is in trash")
		table.TimestampTz("trashed_at").Nullable().Comment("When folder was trashed")

		// Hierarchy
		table.String("path").Nullable().Comment("Folder path (for breadcrumbs)")
		table.Integer("level").Default(0).Comment("Folder level (depth in hierarchy)")
		table.Integer("sort_order").Default(0).Comment("Sort order")

		// Relationships
		table.Ulid("owner_id").Comment("Owner of the folder")
		table.Ulid("parent_id").Nullable().Comment("Parent folder ID")
		table.Ulid("tenant_id").Nullable().Comment("Tenant/Organization ID")

		// Timestamps
		table.TimestampsTz()

		// Indexes
		table.Index("owner_id")
		table.Index("parent_id")
		table.Index("tenant_id")
		table.Index("is_trashed")
		table.Index("level")
		table.Index("sort_order")
		table.Index("created_at")

		// Foreign key constraints
		table.Foreign("owner_id").References("id").On("users")
		table.Foreign("parent_id").References("id").On("folders")
		table.Foreign("tenant_id").References("id").On("tenants")
	})
}

// Down Reverse the migrations.
func (r *M20250115000085CreateFoldersTable) Down() error {
	return facades.Schema().DropIfExists("folders")
}
