package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000086CreateFileVersionsTable struct{}

// Signature The unique signature for the migration.
func (r *M20250115000086CreateFileVersionsTable) Signature() string {
	return "20250115000086_create_file_versions_table"
}

// Up Run the migrations.
func (r *M20250115000086CreateFileVersionsTable) Up() error {
	return facades.Schema().Create("file_versions", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique version identifier")

		// Version information
		table.Integer("version").Comment("Version number")
		table.String("path").Comment("File path on storage")
		table.BigInteger("size").Comment("File size in bytes")
		table.String("hash").Comment("File hash")
		table.Text("comment").Nullable().Comment("Version comment/description")
		table.Boolean("is_current").Default(false).Comment("Whether this is the current version")
		table.String("storage_provider").Default("minio").Comment("Storage provider")

		// Relationships
		table.Ulid("file_id").Comment("File ID this version belongs to")
		table.Ulid("created_by_id").Comment("User who created this version")

		// Timestamps
		table.TimestampsTz()

		// Indexes
		table.Index("file_id")
		table.Index("created_by_id")
		table.Index("version")
		table.Index("is_current")
		table.Index("hash")
		table.Index("created_at")

		// Foreign key constraints
		table.Foreign("file_id").References("id").On("files")
		table.Foreign("created_by_id").References("id").On("users")

		// Unique constraint for current version per file
		table.Unique("file_id", "version")
	})
}

// Down Reverse the migrations.
func (r *M20250115000086CreateFileVersionsTable) Down() error {
	return facades.Schema().DropIfExists("file_versions")
}
