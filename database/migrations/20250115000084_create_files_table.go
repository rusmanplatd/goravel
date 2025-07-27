package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000084CreateFilesTable struct{}

// Signature The unique signature for the migration.
func (r *M20250115000084CreateFilesTable) Signature() string {
	return "20250115000084_create_files_table"
}

// Up Run the migrations.
func (r *M20250115000084CreateFilesTable) Up() error {
	return facades.Schema().Create("files", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique file identifier")

		// Basic file information
		table.String("name").Comment("File name")
		table.String("original_name").Comment("Original filename when uploaded")
		table.String("path").Comment("File path on storage")
		table.BigInteger("size").Comment("File size in bytes")
		table.String("mime_type").Comment("MIME type")
		table.String("extension").Nullable().Comment("File extension")
		table.String("hash").Nullable().Comment("File hash for deduplication")
		table.String("storage_provider").Default("minio").Comment("Storage provider")

		// Metadata and description
		table.Text("description").Nullable().Comment("File description")
		table.Json("tags").Nullable().Comment("File tags")
		table.Json("metadata").Nullable().Comment("File metadata")

		// Status and flags
		table.Boolean("is_public").Default(false).Comment("Whether file is public")
		table.Boolean("is_starred").Default(false).Comment("Whether file is starred/favorited")
		table.Boolean("is_trashed").Default(false).Comment("Whether file is in trash")
		table.TimestampTz("trashed_at").Nullable().Comment("When file was trashed")
		table.String("status").Default("active").Comment("File status (active, processing, failed, deleted)")

		// Usage statistics
		table.BigInteger("download_count").Default(0).Comment("Download count")
		table.BigInteger("view_count").Default(0).Comment("View count")
		table.TimestampTz("last_accessed_at").Nullable().Comment("Last accessed time")

		// Security
		table.String("virus_scan_status").Default("pending").Comment("Virus scan status")
		table.Text("virus_scan_result").Nullable().Comment("Virus scan result")
		table.TimestampTz("virus_scanned_at").Nullable().Comment("When virus scan was performed")

		// Relationships
		table.Ulid("owner_id").Comment("Owner of the file")
		table.Ulid("folder_id").Nullable().Comment("Parent folder ID")
		table.Ulid("tenant_id").Nullable().Comment("Tenant/Organization ID")

		// Timestamps
		table.TimestampsTz()

		// Indexes
		table.Index("owner_id")
		table.Index("folder_id")
		table.Index("tenant_id")
		table.Index("hash")
		table.Index("is_trashed")
		table.Index("status")
		table.Index("mime_type")
		table.Index("created_at")

		// Foreign key constraints
		table.Foreign("owner_id").References("id").On("users")
		table.Foreign("folder_id").References("id").On("folders")
		table.Foreign("tenant_id").References("id").On("tenants")
	})
}

// Down Reverse the migrations.
func (r *M20250115000084CreateFilesTable) Down() error {
	return facades.Schema().DropIfExists("files")
}
