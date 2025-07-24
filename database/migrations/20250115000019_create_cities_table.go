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
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Foreign key
		table.Foreign("province_id").References("id").On("provinces")

		// Add indexes
		table.Index("name")
		table.Index("code")
		table.Index("is_active")
		table.Index("province_id")
	})
}

// Down Reverse the migrations.
func (r *M20250115000019CreateCitiesTable) Down() error {
	return facades.Schema().DropIfExists("cities")
}
