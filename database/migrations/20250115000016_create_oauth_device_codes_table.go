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
		table.String("id", 100).Comment("Device code identifier")
		table.Ulid("user_id").Nullable().Comment("User reference (set after authorization)")
		table.Ulid("client_id").Comment("OAuth client reference")
		table.Text("scopes").Nullable().Comment("Requested scopes")
		table.String("user_code", 10).Comment("User-friendly code for device authorization")
		table.Boolean("revoked").Comment("Whether device code is revoked")
		table.Boolean("authorized").Comment("Whether device is authorized")
		table.TimestampTz("expires_at").Comment("Device code expiration timestamp")
		table.TimestampTz("created_at").Comment("Code creation timestamp")
		table.TimestampTz("updated_at").Comment("Code update timestamp")

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
