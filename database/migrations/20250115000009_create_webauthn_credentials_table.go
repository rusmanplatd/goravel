package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000009CreateWebauthnCredentialsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000009CreateWebauthnCredentialsTable) Signature() string {
	return "20250115000009_create_webauthn_credentials_table"
}

// Up Run the migrations.
func (r *M20250115000009CreateWebauthnCredentialsTable) Up() error {
	return facades.Schema().Create("webauthn_credentials", func(table schema.Blueprint) {
		table.Ulid("id")
		table.Ulid("user_id")
		table.String("name")
		table.String("credential_id")
		table.Text("public_key")
		table.String("attestation_type")
		table.Text("transports")
		table.String("flags")
		table.Boolean("backup_eligible").Default(false)
		table.Boolean("backed_up").Default(false)
		table.Integer("sign_count").Default(0)
		table.TimestampTz("last_used_at").Nullable()

		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("user_id")
		table.Index("credential_id")
		table.Index("last_used_at")
		table.Unique("credential_id")
	})
}

// Down Reverse the migrations.
func (r *M20250115000009CreateWebauthnCredentialsTable) Down() error {
	return facades.Schema().DropIfExists("webauthn_credentials")
}
