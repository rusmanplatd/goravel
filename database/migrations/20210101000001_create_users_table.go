package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20210101000001CreateUsersTable struct{}

// Signature The unique signature for the migration.
func (r *M20210101000001CreateUsersTable) Signature() string {
	return "20210101000001_create_users_table"
}

// Up Run the migrations.
func (r *M20210101000001CreateUsersTable) Up() error {
	return facades.Schema().Create("users", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique user identifier")
		table.String("name").Comment("User's full name")
		table.String("email").Comment("User's email address")
		table.String("password").Comment("Hashed user password")
		table.TimestampTz("email_verified_at").Nullable().Comment("When email was verified")
		table.String("remember_token").Comment("Remember me token")
		table.Boolean("is_active").Comment("Whether user account is active")

		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("email")
		table.Index("is_active")
	})
}

// Down Reverse the migrations.
func (r *M20210101000001CreateUsersTable) Down() error {
	return facades.Schema().DropIfExists("users")
}
