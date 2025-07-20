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
		table.Ulid("id")
		table.String("name")
		table.String("code")
		table.Boolean("is_active")
		table.Ulid("country_id")

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
	})
}

// Down Reverse the migrations.
func (r *M20250115000018CreateProvincesTable) Down() error {
	return facades.Schema().DropIfExists("provinces")
}
