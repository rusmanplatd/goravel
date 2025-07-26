package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000072CreateOauthIdentityProvidersTable struct{}

// Signature returns the unique identifier for this migration
func (r *M20250115000072CreateOauthIdentityProvidersTable) Signature() string {
	return "20250115000072_create_oauth_identity_providers_table"
}

// Up runs the migration
func (r *M20250115000072CreateOauthIdentityProvidersTable) Up() error {
	return facades.Schema().Create("oauth_identity_providers", func(table schema.Blueprint) {
		table.ID()
		table.String("name").Comment("Provider name (google, github, microsoft, etc.)")
		table.String("display_name").Comment("Human readable provider name")
		table.String("client_id").Comment("OAuth client ID")
		table.String("client_secret").Comment("OAuth client secret")
		table.String("redirect_url").Comment("OAuth redirect URL")
		table.Text("scopes").Comment("JSON array of OAuth scopes")
		table.String("authorization_url").Comment("OAuth authorization endpoint")
		table.String("token_url").Comment("OAuth token endpoint")
		table.String("userinfo_url").Comment("User info endpoint")
		table.Text("userinfo_mapping").Comment("JSON mapping for user info fields")
		table.String("icon_url").Nullable().Comment("Provider icon URL")
		table.String("button_color").Nullable().Comment("Button color for UI")
		table.Boolean("enabled").Default(false).Comment("Whether this provider is enabled")
		table.Integer("sort_order").Default(0).Comment("Display order")
		table.Timestamps()

		// Indexes
		table.Index("name")
		table.Index("enabled")
		table.Index("sort_order")
	})
}

// Down reverses the migration
func (r *M20250115000072CreateOauthIdentityProvidersTable) Down() error {
	return facades.Schema().DropIfExists("oauth_identity_providers")
}
