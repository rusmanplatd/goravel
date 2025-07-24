package seeders

import (
	"encoding/json"
	"fmt"
	"goravel/app/helpers"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type OAuthAccessTokenSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *OAuthAccessTokenSeeder) Signature() string {
	return "OAuthAccessTokenSeeder"
}

// Run executes the seeder logic.
func (s *OAuthAccessTokenSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	// Get a test user to associate with access tokens
	var user models.User
	err := facades.Orm().Query().First(&user)
	if err != nil {
		facades.Log().Info("No users found, skipping OAuthAccessTokenSeeder")
		return nil
	}

	// Get OAuth clients
	var clients []models.OAuthClient
	err = facades.Orm().Query().Find(&clients)
	if err != nil {
		facades.Log().Info("No OAuth clients found, skipping OAuthAccessTokenSeeder")
		return nil
	}

	if len(clients) == 0 {
		facades.Log().Info("No OAuth clients found, skipping OAuthAccessTokenSeeder")
		return nil
	}

	// Create OAuth access tokens
	scopes1Bytes, _ := json.Marshal([]string{"read", "write"})
	scopes2Bytes, _ := json.Marshal([]string{"read"})
	scopes3Bytes, _ := json.Marshal([]string{"read", "write", "admin"})
	scopes4Bytes, _ := json.Marshal([]string{"read", "write", "delete"})
	scopes5Bytes, _ := json.Marshal([]string{"read", "write", "admin", "delete"})

	scopes1 := string(scopes1Bytes)
	scopes2 := string(scopes2Bytes)
	scopes3 := string(scopes3Bytes)
	scopes4 := string(scopes4Bytes)
	scopes5 := string(scopes5Bytes)

	accessTokens := []models.OAuthAccessToken{
		{
			ID:       helpers.GenerateULID(),
			UserID:   &user.ID,
			ClientID: clients[0].ID,
			Scopes:   &scopes1,
			Revoked:  false,
		},
		{
			ID:       helpers.GenerateULID(),
			UserID:   &user.ID,
			ClientID: clients[0].ID,
			Scopes:   &scopes2,
			Revoked:  false,
		},
		{
			ID:       helpers.GenerateULID(),
			UserID:   &user.ID,
			ClientID: clients[0].ID,
			Scopes:   &scopes3,
			Revoked:  true,
		},
		{
			ID:       helpers.GenerateULID(),
			UserID:   &user.ID,
			ClientID: clients[0].ID,
			Scopes:   &scopes4,
			Revoked:  false,
		},
		{
			ID:       helpers.GenerateULID(),
			UserID:   &user.ID,
			ClientID: clients[0].ID,
			Scopes:   &scopes5,
			Revoked:  false,
		},
	}

	// Add access tokens for other clients if available
	if len(clients) > 1 {
		accessTokens = append(accessTokens, models.OAuthAccessToken{
			ID:       helpers.GenerateULID(),
			UserID:   &user.ID,
			ClientID: clients[1].ID,
			Scopes:   &scopes1,
			Revoked:  false,
		})
	}

	if len(clients) > 2 {
		accessTokens = append(accessTokens, models.OAuthAccessToken{
			ID:       helpers.GenerateULID(),
			UserID:   &user.ID,
			ClientID: clients[2].ID,
			Scopes:   &scopes2,
			Revoked:  false,
		})
	}

	// Create access tokens in database
	for _, token := range accessTokens {
		// Check if access token already exists
		var existingToken models.OAuthAccessToken
		err := facades.Orm().Query().Where("id = ?", token.ID).First(&existingToken)
		if err == nil {
			facades.Log().Info("Access token already exists: " + token.ID)
			continue
		}

		err = facades.Orm().Query().Create(&token)
		if err != nil {
			facades.Log().Error("Failed to create OAuth access token: " + err.Error())
			return err
		}

		facades.Log().Info("Created OAuth access token: " + token.ID)
	}

	// Create additional access tokens for other users
	var otherUsers []models.User
	err = facades.Orm().Query().Where("email != ?", user.Email).Limit(3).Find(&otherUsers)
	if err == nil && len(otherUsers) > 0 {
		for i, otherUser := range otherUsers {
			// Create one access token per other user
			token := models.OAuthAccessToken{
				ID:       helpers.GenerateULID(),
				UserID:   &otherUser.ID,
				ClientID: clients[0].ID,
				Scopes:   &scopes1,
				Revoked:  false,
			}

			// Check if access token already exists
			var existingToken models.OAuthAccessToken
			err := facades.Orm().Query().Where("id = ?", token.ID).First(&existingToken)
			if err == nil {
				facades.Log().Info("Access token already exists: " + token.ID)
				continue
			}

			err = facades.Orm().Query().Create(&token)
			if err != nil {
				facades.Log().Error("Failed to create OAuth access token for other user: " + err.Error())
				return err
			}

			facades.Log().Info("Created OAuth access token for user: " + otherUser.Email)

			// Create a second access token for some users
			if i < 2 {
				token2 := models.OAuthAccessToken{
					ID:       helpers.GenerateULID(),
					UserID:   &otherUser.ID,
					ClientID: clients[0].ID,
					Scopes:   &scopes2,
					Revoked:  false,
				}

				// Check if access token already exists
				err = facades.Orm().Query().Where("id = ?", token2.ID).First(&existingToken)
				if err == nil {
					facades.Log().Info("Access token already exists: " + token2.ID)
					continue
				}

				err = facades.Orm().Query().Create(&token2)
				if err != nil {
					facades.Log().Error("Failed to create second OAuth access token for other user: " + err.Error())
					return err
				}

				facades.Log().Info("Created second OAuth access token for user: " + otherUser.Email)
			}
		}
	}

	facades.Log().Info("OAuth access tokens seeded successfully")
	return nil
}
