package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000010CreatePasswordResetTokensTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000010CreatePasswordResetTokensTable) Signature() string {
	return "20250115000010_create_password_reset_tokens_table"
}

// Up Run the migrations.
func (r *M20250115000010CreatePasswordResetTokensTable) Up() error {
	return facades.Schema().Create("password_reset_tokens", func(table schema.Blueprint) {
		table.String("email").Comment("User email address")
		table.String("token").Comment("Password reset token")
		table.TimestampTz("created_at").Comment("Token creation timestamp")

		// Primary key
		table.Primary("email")

		// Add indexes
		table.Index("email")
		table.Index("token")
	})
}

// Down Reverse the migrations.
func (r *M20250115000010CreatePasswordResetTokensTable) Down() error {
	return facades.Schema().DropIfExists("password_reset_tokens")
}
