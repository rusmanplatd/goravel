package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000017CreateCountriesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000017CreateCountriesTable) Signature() string {
	return "20250115000017_create_countries_table"
}

// Up Run the migrations.
func (r *M20250115000017CreateCountriesTable) Up() error {
	return facades.Schema().Create("countries", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique country identifier")
		table.String("name").Comment("Country name")
		table.String("code", 2).Nullable().Comment("ISO 3166-1 alpha-2 country code")
		table.String("code3", 3).Nullable().Comment("ISO 3166-1 alpha-3 country code")
		table.String("numeric_code", 3).Nullable().Comment("ISO 3166-1 numeric country code")
		table.Boolean("is_active").Comment("Whether country is active")

		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("name")
		table.Index("code")
		table.Index("code3")
		table.Index("is_active")

		// Add unique constraints
		table.Unique("code")
		table.Unique("code3")
	})
}

// Down Reverse the migrations.
func (r *M20250115000017CreateCountriesTable) Down() error {
	return facades.Schema().DropIfExists("countries")
}
