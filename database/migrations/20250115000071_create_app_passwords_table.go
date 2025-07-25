package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000071CreateAppPasswordsTable struct{}

// Signature The name and signature of the console command.
func (r *M20250115000071CreateAppPasswordsTable) Signature() string {
	return "20250115000071_create_app_passwords_table"
}

// Up Run the migrations.
func (r *M20250115000071CreateAppPasswordsTable) Up() error {
	return facades.Schema().Create("app_passwords", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique app password identifier")
		table.Ulid("user_id").Comment("User who owns the app password")
		table.String("name", 255).Comment("Descriptive name for the app password")
		table.String("password", 255).Comment("The generated app password")
		table.TimestampTz("last_used_at").Nullable().Comment("When the password was last used")
		table.Boolean("revoked").Default(false).Comment("Whether the password is revoked")
		table.TimestampTz("expires_at").Nullable().Comment("When the password expires")
		table.TimestampsTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("user_id")
		table.Index("password")
		table.Index("revoked")

		// Foreign key constraints
		table.Foreign("user_id").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000071CreateAppPasswordsTable) Down() error {
	return facades.Schema().DropIfExists("app_passwords")
}
