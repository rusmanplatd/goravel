package seeders

import (
	"encoding/json"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type WebAuthnCredentialSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *WebAuthnCredentialSeeder) Signature() string {
	return "WebAuthnCredentialSeeder"
}

// Run executes the seeder logic.
func (s *WebAuthnCredentialSeeder) Run() error {
	// Get users to associate with WebAuthn credentials
	var users []models.User
	err := facades.Orm().Query().Limit(5).Find(&users)
	if err != nil {
		facades.Log().Info("No users found, skipping WebAuthnCredentialSeeder")
		return nil
	}

	if len(users) == 0 {
		facades.Log().Info("No users found, skipping WebAuthnCredentialSeeder")
		return nil
	}

	// Create WebAuthn credentials
	transports1Bytes, _ := json.Marshal([]string{"usb", "nfc"})
	transports2Bytes, _ := json.Marshal([]string{"usb"})
	transports3Bytes, _ := json.Marshal([]string{"usb", "ble"})
	transports4Bytes, _ := json.Marshal([]string{"usb", "nfc", "ble"})
	transports5Bytes, _ := json.Marshal([]string{"usb", "nfc", "ble", "internal"})

	webauthnCredentials := []models.WebauthnCredential{
		{
			UserID:          users[0].ID,
			Name:            "Primary Security Key",
			CredentialID:    "credential-1",
			PublicKey:       "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/",
			AttestationType: "none",
			Transports:      string(transports1Bytes),
			Flags:           "backup_eligible,backed_up",
			BackupEligible:  true,
			BackedUp:        true,
			SignCount:       1,
		},
		{
			UserID:          users[0].ID,
			Name:            "Backup Security Key",
			CredentialID:    "credential-2",
			PublicKey:       "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/",
			AttestationType: "none",
			Transports:      string(transports2Bytes),
			Flags:           "backup_eligible",
			BackupEligible:  true,
			BackedUp:        false,
			SignCount:       5,
		},
		{
			UserID:          users[0].ID,
			Name:            "Inactive Security Key",
			CredentialID:    "credential-3",
			PublicKey:       "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/",
			AttestationType: "none",
			Transports:      string(transports3Bytes),
			Flags:           "backup_eligible",
			BackupEligible:  true,
			BackedUp:        false,
			SignCount:       10,
		},
	}

	// Add WebAuthn credentials for other users
	if len(users) > 1 {
		webauthnCredentials = append(webauthnCredentials, models.WebauthnCredential{
			UserID:          users[1].ID,
			Name:            "User 2 Security Key",
			CredentialID:    "credential-4",
			PublicKey:       "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/",
			AttestationType: "none",
			Transports:      string(transports4Bytes),
			Flags:           "backup_eligible,backed_up",
			BackupEligible:  true,
			BackedUp:        true,
			SignCount:       3,
		})
	}

	if len(users) > 2 {
		webauthnCredentials = append(webauthnCredentials, models.WebauthnCredential{
			UserID:          users[2].ID,
			Name:            "User 3 Primary Key",
			CredentialID:    "credential-5",
			PublicKey:       "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/",
			AttestationType: "none",
			Transports:      string(transports2Bytes),
			Flags:           "backup_eligible",
			BackupEligible:  true,
			BackedUp:        false,
			SignCount:       7,
		})
	}

	// Create WebAuthn credentials in database
	for _, credential := range webauthnCredentials {
		// Check if WebAuthn credential already exists
		var existingCredential models.WebauthnCredential
		err := facades.Orm().Query().Where("user_id = ? AND name = ?", credential.UserID, credential.Name).First(&existingCredential)
		if err == nil {
			facades.Log().Info("WebAuthn credential already exists: " + credential.Name)
			continue
		}

		err = facades.Orm().Query().Create(&credential)
		if err != nil {
			facades.Log().Error("Failed to create WebAuthn credential: " + err.Error())
			return err
		}

		facades.Log().Info("Created WebAuthn credential: " + credential.Name)
	}

	// Create additional WebAuthn credentials for testing edge cases
	edgeCaseCredentials := []models.WebauthnCredential{
		{
			UserID:          users[0].ID,
			Name:            "High Sign Count Key",
			CredentialID:    "credential-6",
			PublicKey:       "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/",
			AttestationType: "none",
			Transports:      string(transports5Bytes),
			Flags:           "backup_eligible,backed_up",
			BackupEligible:  true,
			BackedUp:        true,
			SignCount:       1000,
		},
		{
			UserID:          users[0].ID,
			Name:            "Different Flags Key",
			CredentialID:    "credential-7",
			PublicKey:       "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/",
			AttestationType: "none",
			Transports:      string(transports2Bytes),
			Flags:           "backup_eligible",
			BackupEligible:  true,
			BackedUp:        false,
			SignCount:       15,
		},
	}

	// Create edge case credentials in database
	for _, credential := range edgeCaseCredentials {
		// Check if WebAuthn credential already exists
		var existingCredential models.WebauthnCredential
		err := facades.Orm().Query().Where("user_id = ? AND name = ?", credential.UserID, credential.Name).First(&existingCredential)
		if err == nil {
			facades.Log().Info("WebAuthn credential already exists: " + credential.Name)
			continue
		}

		err = facades.Orm().Query().Create(&credential)
		if err != nil {
			facades.Log().Error("Failed to create edge case WebAuthn credential: " + err.Error())
			return err
		}

		facades.Log().Info("Created edge case WebAuthn credential: " + credential.Name)
	}

	facades.Log().Info("WebAuthn credentials seeded successfully")
	return nil
}
