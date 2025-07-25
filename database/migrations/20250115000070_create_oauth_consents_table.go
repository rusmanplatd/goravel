package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000070CreateOauthConsentsTable struct{}

// Signature The name and signature of the console command.
func (r *M20250115000070CreateOauthConsentsTable) Signature() string {
	return "20250115000070_create_oauth_consents_table"
}

// Up Run the migrations.
func (r *M20250115000070CreateOauthConsentsTable) Up() error {
	return facades.Schema().Create("oauth_consents", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique consent identifier")
		table.Ulid("user_id").Comment("User who granted consent")
		table.Ulid("client_id").Comment("OAuth client")
		table.Text("scopes").Nullable().Comment("Granted scopes as JSON")
		table.Boolean("granted").Default(true).Comment("Whether consent was granted")
		table.Boolean("revoked").Default(false).Comment("Whether consent was revoked")
		table.TimestampTz("expires_at").Nullable().Comment("When consent expires")
		table.TimestampsTz()

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("user_id")
		table.Index("client_id")
		table.Index("granted")
		table.Index("revoked")

		// Foreign key constraints
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("client_id").References("id").On("oauth_clients")
	})
}

// Down Reverse the migrations.
func (r *M20250115000070CreateOauthConsentsTable) Down() error {
	return facades.Schema().DropIfExists("oauth_consents")
}
