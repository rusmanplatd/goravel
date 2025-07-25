package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000011CreateOauthClientsTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000011CreateOauthClientsTable) Signature() string {
	return "20250115000011_create_oauth_clients_table"
}

// Up Run the migrations.
func (r *M20250115000011CreateOauthClientsTable) Up() error {
	return facades.Schema().Create("oauth_clients", func(table schema.Blueprint) {
		table.Ulid("id").Comment("Unique OAuth client identifier")
		table.Ulid("user_id").Nullable().Comment("User who created the client")
		table.String("name", 255).Comment("Client name")
		table.String("secret", 100).Nullable().Comment("Client secret")
		table.String("provider", 255).Nullable().Comment("Provider name")
		table.Text("redirect").Comment("Redirect URI")
		table.Boolean("personal_access_client").Default(false).Comment("Whether this is a personal access client")
		table.Boolean("password_client").Default(false).Comment("Whether this is a password client")
		table.Boolean("revoked").Default(false).Comment("Whether client is revoked")
		table.TimestampsTz()
		table.SoftDeletesTz()
		table.Ulid("created_by").Comment("User who created data")
		table.Ulid("updated_by").Comment("User who updated data")
		table.Ulid("deleted_by").Nullable().Comment("User who deleted data")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("user_id")
		table.Index("personal_access_client")
		table.Index("password_client")
		table.Index("revoked")
		table.Index("created_by")
		table.Index("updated_by")
		table.Index("deleted_by")

		// Add foreign key constraints
		table.Foreign("created_by").References("id").On("users")
		table.Foreign("updated_by").References("id").On("users")
		table.Foreign("deleted_by").References("id").On("users")
	})
}

// Down Reverse the migrations.
func (r *M20250115000011CreateOauthClientsTable) Down() error {
	return facades.Schema().DropIfExists("oauth_clients")
}
