package migrations

import (
	"github.com/goravel/framework/contracts/database/schema"
	"github.com/goravel/framework/facades"
)

type M20250115000082CreateOauthStepUpChallengesTable struct{}

// Signature returns the unique identifier for this migration
func (r *M20250115000082CreateOauthStepUpChallengesTable) Signature() string {
	return "20250115000082_create_oauth_step_up_challenges_table"
}

// Up runs the migration
func (r *M20250115000082CreateOauthStepUpChallengesTable) Up() error {
	return facades.Schema().Create("oauth_step_up_challenges", func(table schema.Blueprint) {
		table.ID()
		table.String("challenge_id").Comment("Unique challenge identifier")
		table.Ulid("user_id").Comment("User being challenged")
		table.Ulid("client_id").Comment("OAuth client requesting step-up")
		table.String("session_id").Nullable().Comment("Associated session")
		table.String("token_id", 100).Nullable().Comment("Token requiring step-up")
		table.String("challenge_type", 50).Comment("Challenge type: mfa, biometric, device_confirmation")
		table.String("challenge_method", 50).Comment("Method: totp, sms, email, webauthn, etc.")
		table.String("required_acr", 20).Comment("Required Authentication Context Class Reference")
		table.String("current_acr", 20).Nullable().Comment("Current ACR level")
		table.Json("required_amr").Nullable().Comment("Required Authentication Methods References")
		table.Json("current_amr").Nullable().Comment("Current AMR")
		table.String("challenge_reason", 100).Comment("Why step-up is required")
		table.Text("challenge_data").Nullable().Comment("Challenge-specific data as JSON")
		table.String("challenge_code", 100).Nullable().Comment("Challenge code/token")
		table.String("verification_code", 20).Nullable().Comment("User verification code")
		table.String("status", 20).Default("pending").Comment("Challenge status: pending, completed, failed, expired")
		table.Integer("attempts").Default(0).Comment("Number of attempts")
		table.Integer("max_attempts").Default(3).Comment("Maximum allowed attempts")
		table.Timestamp("issued_at").Comment("When challenge was issued")
		table.Timestamp("expires_at").Comment("Challenge expiration")
		table.Timestamp("completed_at").Nullable().Comment("When challenge was completed")
		table.Timestamp("last_attempt_at").Nullable().Comment("Last attempt timestamp")
		table.String("completion_method").Nullable().Comment("How challenge was completed")
		table.Json("completion_data").Nullable().Comment("Completion data")
		table.String("failure_reason").Nullable().Comment("Reason for failure")
		table.String("ip_address", 45).Nullable().Comment("IP address")
		table.String("user_agent", 500).Nullable().Comment("User agent")
		table.String("device_id").Nullable().Comment("Device identifier")
		table.Json("metadata").Nullable().Comment("Additional metadata")
		table.Timestamps()

		// Indexes
		table.Index("challenge_id")
		table.Index("user_id")
		table.Index("client_id")
		table.Index("session_id")
		table.Index("token_id")
		table.Index("challenge_type")
		table.Index("challenge_method")
		table.Index("required_acr")
		table.Index("challenge_reason")
		table.Index("status")
		table.Index("issued_at")
		table.Index("expires_at")
		table.Index("completed_at")
		table.Index("last_attempt_at")
		table.Index("ip_address")
		table.Index("device_id")
		table.Index("created_at")

		// Composite indexes
		table.Index("user_id", "challenge_type")
		table.Index("client_id", "challenge_type")
		table.Index("user_id", "status")
		table.Index("status", "expires_at")
		table.Index("challenge_type", "status")
		table.Index("user_id", "issued_at")

		// Unique constraints
		table.Unique("challenge_id")

		// Foreign keys
		table.Foreign("user_id").References("id").On("users")
		table.Foreign("client_id").References("id").On("oauth_clients")
	})
}

// Down reverses the migration
func (r *M20250115000082CreateOauthStepUpChallengesTable) Down() error {
	return facades.Schema().DropIfExists("oauth_step_up_challenges")
}
