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
		table.Ulid("id")
		table.String("name")
		table.String("code", 2).Nullable()
		table.String("code3", 3).Nullable()
		table.String("numeric_code", 3).Nullable()
		table.Boolean("is_active")

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
