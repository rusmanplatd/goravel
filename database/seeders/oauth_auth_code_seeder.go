package seeders

import (
	"encoding/json"
	"goravel/app/helpers"
	"goravel/app/models"
	"time"

	"github.com/goravel/framework/facades"
)

type OAuthAuthCodeSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *OAuthAuthCodeSeeder) Signature() string {
	return "OAuthAuthCodeSeeder"
}

// Run executes the seeder logic.
func (s *OAuthAuthCodeSeeder) Run() error {
	// Get a test user to associate with auth codes
	var user models.User
	err := facades.Orm().Query().First(&user)
	if err != nil {
		facades.Log().Info("No users found, skipping OAuthAuthCodeSeeder")
		return nil
	}

	// Get OAuth clients
	var clients []models.OAuthClient
	err = facades.Orm().Query().Find(&clients)
	if err != nil {
		facades.Log().Info("No OAuth clients found, skipping OAuthAuthCodeSeeder")
		return nil
	}

	if len(clients) == 0 {
		facades.Log().Info("No OAuth clients found, skipping OAuthAuthCodeSeeder")
		return nil
	}

	// Create OAuth auth codes
	now := time.Now()
	scopes1Bytes, _ := json.Marshal([]string{"read", "write"})
	scopes2Bytes, _ := json.Marshal([]string{"read"})
	scopes3Bytes, _ := json.Marshal([]string{"read", "write", "admin"})
	scopes4Bytes, _ := json.Marshal([]string{"read", "write", "delete"})

	scopes1 := string(scopes1Bytes)
	scopes2 := string(scopes2Bytes)
	scopes3 := string(scopes3Bytes)
	scopes4 := string(scopes4Bytes)

	authCodes := []models.OAuthAuthCode{
		{
			ID:        helpers.GenerateULID(),
			UserID:    user.ID,
			ClientID:  clients[0].ID,
			Scopes:    &scopes1,
			Revoked:   false,
			ExpiresAt: now.Add(10 * time.Minute),
		},
		{
			ID:        helpers.GenerateULID(),
			UserID:    user.ID,
			ClientID:  clients[0].ID,
			Scopes:    &scopes2,
			Revoked:   false,
			ExpiresAt: now.Add(5 * time.Minute),
		},
		{
			ID:        helpers.GenerateULID(),
			UserID:    user.ID,
			ClientID:  clients[0].ID,
			Scopes:    &scopes3,
			Revoked:   true,
			ExpiresAt: now.Add(-1 * time.Hour), // Expired
		},
		{
			ID:        helpers.GenerateULID(),
			UserID:    user.ID,
			ClientID:  clients[0].ID,
			Scopes:    &scopes4,
			Revoked:   false,
			ExpiresAt: now.Add(15 * time.Minute),
		},
	}

	// Add auth codes for other clients if available
	if len(clients) > 1 {
		authCodes = append(authCodes, models.OAuthAuthCode{
			ID:        helpers.GenerateULID(),
			UserID:    user.ID,
			ClientID:  clients[1].ID,
			Scopes:    &scopes1,
			Revoked:   false,
			ExpiresAt: now.Add(8 * time.Minute),
		})
	}

	if len(clients) > 2 {
		authCodes = append(authCodes, models.OAuthAuthCode{
			ID:        helpers.GenerateULID(),
			UserID:    user.ID,
			ClientID:  clients[2].ID,
			Scopes:    &scopes2,
			Revoked:   false,
			ExpiresAt: now.Add(12 * time.Minute),
		})
	}

	// Create auth codes in database
	for _, code := range authCodes {
		// Check if auth code already exists
		var existingCode models.OAuthAuthCode
		err := facades.Orm().Query().Where("id = ?", code.ID).First(&existingCode)
		if err == nil {
			facades.Log().Info("Auth code already exists: " + code.ID)
			continue
		}

		err = facades.Orm().Query().Create(&code)
		if err != nil {
			facades.Log().Error("Failed to create OAuth auth code: " + err.Error())
			return err
		}

		facades.Log().Info("Created OAuth auth code: " + code.ID)
	}

	// Create additional auth codes for other users
	var otherUsers []models.User
	err = facades.Orm().Query().Where("email != ?", user.Email).Limit(2).Find(&otherUsers)
	if err == nil && len(otherUsers) > 0 {
		for _, otherUser := range otherUsers {
			// Create one auth code per other user
			code := models.OAuthAuthCode{
				ID:        helpers.GenerateULID(),
				UserID:    otherUser.ID,
				ClientID:  clients[0].ID,
				Scopes:    &scopes1,
				Revoked:   false,
				ExpiresAt: now.Add(20 * time.Minute),
			}

			// Check if auth code already exists
			var existingCode models.OAuthAuthCode
			err := facades.Orm().Query().Where("id = ?", code.ID).First(&existingCode)
			if err == nil {
				facades.Log().Info("Auth code already exists: " + code.ID)
				continue
			}

			err = facades.Orm().Query().Create(&code)
			if err != nil {
				facades.Log().Error("Failed to create OAuth auth code for other user: " + err.Error())
				return err
			}

			facades.Log().Info("Created OAuth auth code for user: " + otherUser.Email)
		}
	}

	facades.Log().Info("OAuth auth codes seeded successfully")
	return nil
}
