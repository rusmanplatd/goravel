package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000079CreateOauthSessionsTable struct{}

// Signature returns the unique identifier for this migration
func (r *M20250115000079CreateOauthSessionsTable) Signature() string {
	return "20250115000079_create_oauth_sessions_table"
}

// Up runs the migration
func (r *M20250115000079CreateOauthSessionsTable) Up() error {
	return facades.Schema().Create("oauth_sessions", func(table schema.Blueprint) {
		table.ID()
		table.String("session_id").Comment("Unique session identifier")
		table.Ulid("user_id").Comment("User associated with session")
		table.Ulid("client_id").Comment("OAuth client")
		table.String("session_type", 50).Default("oauth").Comment("Session type: oauth, sso, etc.")
		table.String("state", 255).Nullable().Comment("OAuth state parameter")
		table.String("nonce", 255).Nullable().Comment("OpenID Connect nonce")
		table.Text("scopes").Nullable().Comment("Requested scopes")
		table.String("redirect_uri", 500).Nullable().Comment("Redirect URI")
		table.String("code_challenge", 255).Nullable().Comment("PKCE code challenge")
		table.String("code_challenge_method", 10).Nullable().Comment("PKCE challenge method")
		table.String("response_type", 100).Nullable().Comment("OAuth response type")
		table.String("response_mode", 50).Nullable().Comment("OAuth response mode")
		table.String("ip_address", 45).Comment("Client IP address")
		table.Text("user_agent").Nullable().Comment("User agent string")
		table.String("device_id").Nullable().Comment("Device identifier")
		table.String("browser_fingerprint").Nullable().Comment("Browser fingerprint")
		table.Json("session_data").Nullable().Comment("Additional session data")
		table.String("status", 20).Default("active").Comment("Session status: active, expired, revoked")
		table.Timestamp("auth_time").Nullable().Comment("When user was authenticated")
		table.Timestamp("last_activity").Comment("Last activity timestamp")
		table.Timestamp("expires_at").Comment("Session expiration time")
		table.Boolean("is_persistent").Default(false).Comment("Whether session should persist")
		table.String("acr", 10).Nullable().Comment("Authentication Context Class Reference")
		table.Json("amr").Nullable().Comment("Authentication Methods References")
		table.Timestamps()

		// Indexes
		table.Index("session_id")
		table.Index("user_id")
		table.Index("client_id")
		table.Index("session_type")
		table.Index("state")
		table.Index("status")
		table.Index("ip_address")
		table.Index("device_id")
		table.Index("auth_time")
		table.Index("last_activity")
		table.Index("expires_at")
		table.Index("created_at")

		// Composite indexes
		table.Index("user_id", "client_id")
		table.Index("user_id", "status")
		table.Index("client_id", "status")
		table.Index("status", "expires_at")
		table.Index("user_id", "last_activity")

		// Unique constraints
		table.Unique("session_id")

		// Foreign keys
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("client_id").References("id").On("oauth_clients")
	})
}

// Down reverses the migration
func (r *M20250115000079CreateOauthSessionsTable) Down() error {
	return facades.Schema().DropIfExists("oauth_sessions")
}
