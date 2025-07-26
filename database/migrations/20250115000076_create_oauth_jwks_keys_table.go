package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000076CreateOauthJwksKeysTable struct{}

// Signature returns the unique identifier for this migration
func (r *M20250115000076CreateOauthJwksKeysTable) Signature() string {
	return "20250115000076_create_oauth_jwks_keys_table"
}

// Up runs the migration
func (r *M20250115000076CreateOauthJwksKeysTable) Up() error {
	return facades.Schema().Create("oauth_jwks_keys", func(table schema.Blueprint) {
		table.ID()
		table.String("key_id").Comment("Unique key identifier (kid)")
		table.String("key_type", 10).Default("RSA").Comment("Key type (RSA, EC, etc.)")
		table.String("algorithm", 10).Default("RS256").Comment("Signing algorithm")
		table.Text("public_key").Comment("PEM encoded public key")
		table.Text("private_key").Nullable().Comment("PEM encoded private key (encrypted)")
		table.String("use", 10).Default("sig").Comment("Key usage (sig, enc)")
		table.Json("key_ops").Nullable().Comment("Key operations array")
		table.String("x5t").Nullable().Comment("X.509 certificate thumbprint (SHA-1)")
		table.String("x5t_s256").Nullable().Comment("X.509 certificate thumbprint (SHA-256)")
		table.Boolean("is_active").Default(true).Comment("Whether key is active")
		table.Boolean("is_primary").Default(false).Comment("Whether this is the primary signing key")
		table.Timestamp("expires_at").Nullable().Comment("Key expiration time")
		table.Timestamp("rotated_at").Nullable().Comment("When key was rotated")
		table.Text("metadata").Nullable().Comment("Additional key metadata as JSON")
		table.Timestamps()

		// Indexes
		table.Index("key_id")
		table.Index("key_type")
		table.Index("algorithm")
		table.Index("is_active")
		table.Index("is_primary")
		table.Index("expires_at")
		table.Index("rotated_at")

		// Unique constraint
		table.Unique("key_id")
	})
}

// Down reverses the migration
func (r *M20250115000076CreateOauthJwksKeysTable) Down() error {
	return facades.Schema().DropIfExists("oauth_jwks_keys")
}
