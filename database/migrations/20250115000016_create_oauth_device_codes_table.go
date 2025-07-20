package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000016CreateOauthDeviceCodesTable struct {
}

// Signature The unique signature for the migration.
func (r *M20250115000016CreateOauthDeviceCodesTable) Signature() string {
	return "20250115000016_create_oauth_device_codes_table"
}

// Up Run the migrations.
func (r *M20250115000016CreateOauthDeviceCodesTable) Up() error {
	return facades.Schema().Create("oauth_device_codes", func(table schema.Blueprint) {
		table.String("id", 100)
		table.Ulid("user_id").Nullable()
		table.Ulid("client_id")
		table.Text("scopes").Nullable()
		table.String("user_code", 10)
		table.Boolean("revoked")
		table.Boolean("authorized")
		table.TimestampTz("expires_at")
		table.TimestampTz("created_at")
		table.TimestampTz("updated_at")

		// Primary key
		table.Primary("id")

		// Add indexes
		table.Index("user_id")
		table.Index("client_id")
		table.Index("user_code")
		table.Index("revoked")
		table.Index("authorized")
	})
}

// Down Reverse the migrations.
func (r *M20250115000016CreateOauthDeviceCodesTable) Down() error {
	return facades.Schema().DropIfExists("oauth_device_codes")
}
