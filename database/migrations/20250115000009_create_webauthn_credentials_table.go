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
		table.Ulid("id").Comment("Unique credential identifier")
		table.Ulid("user_id").Comment("User reference")
		table.String("name").Comment("Credential name/description")
		table.String("credential_id").Comment("WebAuthn credential ID")
		table.Text("public_key").Comment("Public key data")
		table.String("attestation_type").Comment("Attestation type")
		table.Text("transports").Comment("Supported transports (usb, nfc, ble, internal)")
		table.String("flags").Comment("Credential flags")
		table.Boolean("backup_eligible").Default(false).Comment("Whether credential is backup eligible")
		table.Boolean("backed_up").Default(false).Comment("Whether credential is backed up")
		table.Integer("sign_count").Default(0).Comment("Signature counter")
		table.TimestampTz("last_used_at").Nullable().Comment("When credential was last used")
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
