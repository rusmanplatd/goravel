package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000080CreateOauthTokenBindingsTable struct{}

// Signature returns the unique identifier for this migration
func (r *M20250115000080CreateOauthTokenBindingsTable) Signature() string {
	return "20250115000080_create_oauth_token_bindings_table"
}

// Up runs the migration
func (r *M20250115000080CreateOauthTokenBindingsTable) Up() error {
	return facades.Schema().Create("oauth_token_bindings", func(table schema.Blueprint) {
		table.ID()
		table.String("binding_id").Comment("Unique token binding identifier")
		table.String("token_id", 100).Comment("Associated access token ID")
		table.String("token_type", 20).Default("access_token").Comment("Token type: access_token, refresh_token")
		table.Ulid("client_id").Comment("OAuth client")
		table.Ulid("user_id").Nullable().Comment("User associated with token")
		table.String("binding_method", 50).Comment("Binding method: mtls, dpop, etc.")
		table.String("binding_value", 500).Comment("Binding value (certificate thumbprint, DPoP key, etc.)")
		table.Text("binding_data").Nullable().Comment("Additional binding data as JSON")
		table.String("certificate_thumbprint", 128).Nullable().Comment("X.509 certificate thumbprint")
		table.Text("certificate_chain").Nullable().Comment("X.509 certificate chain")
		table.String("dpop_jkt", 128).Nullable().Comment("DPoP JSON Web Key thumbprint")
		table.Json("dpop_key").Nullable().Comment("DPoP public key as JWK")
		table.String("device_certificate", 128).Nullable().Comment("Device certificate thumbprint")
		table.String("attestation_data", 500).Nullable().Comment("Device attestation data")
		table.String("status", 20).Default("active").Comment("Binding status: active, revoked, expired")
		table.Timestamp("bound_at").Comment("When token was bound")
		table.Timestamp("expires_at").Nullable().Comment("Binding expiration")
		table.Timestamp("revoked_at").Nullable().Comment("When binding was revoked")
		table.String("revocation_reason").Nullable().Comment("Reason for revocation")
		table.Json("metadata").Nullable().Comment("Additional metadata")
		table.Timestamps()

		// Indexes
		table.Index("binding_id")
		table.Index("token_id")
		table.Index("token_type")
		table.Index("client_id")
		table.Index("user_id")
		table.Index("binding_method")
		table.Index("binding_value")
		table.Index("certificate_thumbprint")
		table.Index("dpop_jkt")
		table.Index("status")
		table.Index("bound_at")
		table.Index("expires_at")
		table.Index("revoked_at")

		// Composite indexes
		table.Index("token_id", "binding_method")
		table.Index("client_id", "binding_method")
		table.Index("user_id", "binding_method")
		table.Index("status", "expires_at")

		// Unique constraints
		table.Unique("binding_id")
		table.Unique("token_id", "binding_method") // One binding per token per method

		// Foreign keys
		table.Foreign("client_id").References("id").On("oauth_clients")
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("token_id").References("id").On("oauth_access_tokens")
	})
}

// Down reverses the migration
func (r *M20250115000080CreateOauthTokenBindingsTable) Down() error {
	return facades.Schema().DropIfExists("oauth_token_bindings")
}
