package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000075CreateOauthPushedAuthRequestsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000075CreateOauthPushedAuthRequestsTable) Signature() string {
	return "20250115000075_create_oauth_pushed_auth_requests_table"
}

// Up Run the migrations.
func (r *M20250115000075CreateOauthPushedAuthRequestsTable) Up() error {
	return facades.Schema().Create("oauth_pushed_auth_requests", func(table schema.Blueprint) {
		table.Ulid("id").Comment("PAR request ID")
		table.Ulid("client_id").Comment("OAuth client ID")
		table.String("request_uri", 255).Comment("Request URI for authorization")
		table.Text("parameters").Nullable().Comment("JSON-encoded authorization parameters")
		table.Boolean("used").Default(false).Comment("Whether the PAR request has been used")
		table.TimestampTz("expires_at").Comment("When the PAR request expires")
		table.TimestampsTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("client_id")
		table.Index("request_uri")
		table.Index("used")
		table.Index("expires_at")

		// Add foreign key constraints
		table.Foreign("client_id").References("id").On("oauth_clients")
	})
}

// Down Reverse the migrations.
func (r *M20250115000075CreateOauthPushedAuthRequestsTable) Down() error {
	return facades.Schema().DropIfExists("oauth_pushed_auth_requests")
}
