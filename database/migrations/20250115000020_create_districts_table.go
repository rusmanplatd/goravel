package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000020CreateDistrictsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000020CreateDistrictsTable) Signature() string {
	return "20250115000020_create_districts_table"
}

// Up Run the migrations.
func (r *M20250115000020CreateDistrictsTable) Up() error {
	return facades.Schema().Create("districts", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique district identifier")
		table.String("name").Comment("District name")
		table.String("code").Comment("District code")
		table.Integer("numeric_code").Nullable().Comment("numeric district code")
		table.Boolean("is_active").Comment("Whether district is active")
		table.Ulid("city_id").Comment("City reference")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Foreign key
		table.Foreign("city_id").References("id").On("cities")

		// Add indexes
		table.Index("name")
		table.Index("code")
		table.Index("numeric_code")
		table.Index("is_active")
		table.Index("city_id")
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
func (r *M20250115000020CreateDistrictsTable) Down() error {
	return facades.Schema().DropIfExists("districts")
}
