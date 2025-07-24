package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000018CreateProvincesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000018CreateProvincesTable) Signature() string {
	return "20250115000018_create_provinces_table"
}

// Up Run the migrations.
func (r *M20250115000018CreateProvincesTable) Up() error {
	return facades.Schema().Create("provinces", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique province identifier")
		table.String("name").Comment("Province name")
		table.String("code").Comment("Province code")
		table.Boolean("is_active").Comment("Whether province is active")
		table.Ulid("country_id").Comment("Country reference")
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Foreign key
		table.Foreign("country_id").References("id").On("countries")

		// Add indexes
		table.Index("name")
		table.Index("code")
		table.Index("is_active")
		table.Index("country_id")
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
func (r *M20250115000018CreateProvincesTable) Down() error {
	return facades.Schema().DropIfExists("provinces")
}
