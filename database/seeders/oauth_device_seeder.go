package seeders

import (
	"encoding/json"
	"fmt"
	"goravel/app/helpers"
	"goravel/app/models"
	"time"

	"github.com/goravel/framework/facades"
)

type OAuthDeviceSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *OAuthDeviceSeeder) Signature() string {
	return "OAuthDeviceSeeder"
}

// Run executes the seeder logic.
func (s *OAuthDeviceSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	// Get a test user to associate with device codes
	var user models.User
	err := facades.Orm().Query().First(&user)
	if err != nil {
		facades.Log().Info("No users found, skipping OAuthDeviceSeeder")
		return nil
	}

	// Get the personal access client
	var client models.OAuthClient
	err = facades.Orm().Query().Where("personal_access_client = ?", true).First(&client)
	if err != nil {
		facades.Log().Info("No OAuth client found, skipping OAuthDeviceSeeder")
		return nil
	}

	// Create sample OAuth device codes for testing
	now := time.Now()

	scopes1Bytes, _ := json.Marshal([]string{"read", "write"})
	scopes2Bytes, _ := json.Marshal([]string{"read"})
	scopes3Bytes, _ := json.Marshal([]string{"read", "write"})

	scopes1 := string(scopes1Bytes)
	scopes2 := string(scopes2Bytes)
	scopes3 := string(scopes3Bytes)

	deviceCodes := []models.OAuthDeviceCode{
		{
			ID:         helpers.GenerateULID(),
			UserID:     &user.ID,
			ClientID:   client.ID,
			Scopes:     &scopes1,
			UserCode:   "ABC123",
			Revoked:    false,
			Authorized: true,
			ExpiresAt:  now.Add(10 * time.Minute),
		},
		{
			ID:         helpers.GenerateULID(),
			UserID:     &user.ID,
			ClientID:   client.ID,
			Scopes:     &scopes2,
			UserCode:   "DEF456",
			Revoked:    false,
			Authorized: false,
			ExpiresAt:  now.Add(5 * time.Minute),
		},
		{
			ID:         helpers.GenerateULID(),
			UserID:     nil,
			ClientID:   client.ID,
			Scopes:     &scopes3,
			UserCode:   "GHI789",
			Revoked:    false,
			Authorized: false,
			ExpiresAt:  now.Add(-1 * time.Minute), // Expired
		},
	}

	// Create device codes in database
	for _, deviceCode := range deviceCodes {
		err := facades.Orm().Query().Create(&deviceCode)
		if err != nil {
			facades.Log().Error("Failed to create OAuth device code: " + err.Error())
			return err
		}
	}

	facades.Log().Info("OAuth device codes seeded successfully")
	return nil
}
