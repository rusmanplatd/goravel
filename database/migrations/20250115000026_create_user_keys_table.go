package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000026CreateUserKeysTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000026CreateUserKeysTable) Signature() string {
	return "20250115000026_create_user_keys_table"
}

// Up Run the migrations.
func (r *M20250115000026CreateUserKeysTable) Up() error {
	return facades.Schema().Create("user_keys", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique key identifier")
		table.Ulid("user_id").Comment("User reference")
		table.String("key_type").Comment("Key type (encryption, signing, etc.)")
		table.Text("public_key").Comment("Public key data")
		table.Text("encrypted_private_key").Comment("Encrypted private key data")
		table.Integer("version").Comment("Key version number")
		table.Boolean("is_active").Comment("Whether key is currently active")
		table.Timestamp("expires_at").Comment("Key expiration timestamp")
		table.TimestampsTz()
		table.SoftDeletesTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("user_id")
		table.Index("key_type")
		table.Index("version")
		table.Index("is_active")
		table.Index("expires_at")
		table.Index("user_id", "key_type")
		table.Index("user_id", "is_active")
	})
}

// Down Reverse the migrations.
func (r *M20250115000026CreateUserKeysTable) Down() error {
	return facades.Schema().DropIfExists("user_keys")
}
