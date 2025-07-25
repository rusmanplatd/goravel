package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000019CreateCitiesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000019CreateCitiesTable) Signature() string {
	return "20250115000019_create_cities_table"
}

// Up Run the migrations.
func (r *M20250115000019CreateCitiesTable) Up() error {
	return facades.Schema().Create("cities", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique city identifier")
		table.String("name").Comment("City name")
		table.String("code").Comment("City code")
		table.Boolean("is_active").Comment("Whether city is active")
		table.Ulid("province_id").Comment("Province reference")
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Foreign key
		table.Foreign("province_id").References("id").On("provinces")
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")

		// Add indexes
		table.Index("name")
		table.Index("code")
		table.Index("is_active")
		table.Index("province_id")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

	})
}

// Down Reverse the migrations.
func (r *M20250115000019CreateCitiesTable) Down() error {
	return facades.Schema().DropIfExists("cities")
}
