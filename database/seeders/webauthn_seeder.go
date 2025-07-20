package seeders

import (
	"encoding/base64"
	"encoding/json"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type WebAuthnSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *WebAuthnSeeder) Signature() string {
	return "WebAuthnSeeder"
}

// Run executes the seeder logic.
func (s *WebAuthnSeeder) Run() error {
	// Get a test user to associate with WebAuthn credentials
	var user models.User
	err := facades.Orm().Query().First(&user)
	if err != nil {
		facades.Log().Info("No users found, skipping WebAuthn seeder")
		return nil
	}

	// Create sample WebAuthn credentials for testing
	transports1Bytes, _ := json.Marshal([]string{"usb", "nfc"})
	transports2Bytes, _ := json.Marshal([]string{"usb"})

	credentials := []models.WebauthnCredential{
		{
			UserID:          user.ID,
			Name:            "Test Security Key",
			CredentialID:    base64.StdEncoding.EncodeToString([]byte("test-credential-id-1")),
			PublicKey:       base64.StdEncoding.EncodeToString([]byte("test-public-key-1")),
			AttestationType: "none",
			Transports:      string(transports1Bytes),
			Flags:           "backup_eligible",
			BackupEligible:  true,
			BackedUp:        false,
			SignCount:       0,
		},
		{
			UserID:          user.ID,
			Name:            "Backup Security Key",
			CredentialID:    base64.StdEncoding.EncodeToString([]byte("test-credential-id-2")),
			PublicKey:       base64.StdEncoding.EncodeToString([]byte("test-public-key-2")),
			AttestationType: "none",
			Transports:      string(transports2Bytes),
			Flags:           "backup_eligible,backed_up",
			BackupEligible:  true,
			BackedUp:        true,
			SignCount:       5,
		},
	}

	// Create credentials in database
	for _, credential := range credentials {
		err := facades.Orm().Query().Create(&credential)
		if err != nil {
			facades.Log().Error("Failed to create WebAuthn credential " + credential.Name + ": " + err.Error())
			return err
		}
	}

	facades.Log().Info("WebAuthn credentials seeded successfully")
	return nil
}
