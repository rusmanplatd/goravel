package seeders

import (
	"encoding/json"
	"fmt"
	"goravel/app/helpers"
	"goravel/app/models"
	"time"

	"github.com/goravel/framework/facades"
)

type OAuthRefreshTokenSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *OAuthRefreshTokenSeeder) Signature() string {
	return "OAuthRefreshTokenSeeder"
}

// Run executes the seeder logic.
func (s *OAuthRefreshTokenSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	// Get a test user to associate with refresh tokens
	var user models.User
	err := facades.Orm().Query().First(&user)
	if err != nil {
		facades.Log().Info("No users found, skipping OAuthRefreshTokenSeeder")
		return nil
	}

	// Get OAuth clients
	var clients []models.OAuthClient
	err = facades.Orm().Query().Find(&clients)
	if err != nil {
		facades.Log().Info("No OAuth clients found, skipping OAuthRefreshTokenSeeder")
		return nil
	}

	if len(clients) == 0 {
		facades.Log().Info("No OAuth clients found, skipping OAuthRefreshTokenSeeder")
		return nil
	}

	// Create OAuth access tokens first (required for refresh tokens)
	now := time.Now()
	scopes1Bytes, _ := json.Marshal([]string{"read", "write"})
	scopes2Bytes, _ := json.Marshal([]string{"read"})
	scopes3Bytes, _ := json.Marshal([]string{"read", "write", "admin"})

	scopes1 := string(scopes1Bytes)
	scopes2 := string(scopes2Bytes)
	scopes3 := string(scopes3Bytes)

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

	// Create OAuth refresh tokens
	refreshTokens := []models.OAuthRefreshToken{
		{
			ID:            helpers.GenerateULID(),
			AccessTokenID: accessTokens[0].ID,
			Revoked:       false,
			ExpiresAt:     now.Add(30 * 24 * time.Hour), // 30 days
		},
		{
			ID:            helpers.GenerateULID(),
			AccessTokenID: accessTokens[1].ID,
			Revoked:       false,
			ExpiresAt:     now.Add(30 * 24 * time.Hour), // 30 days
		},
		{
			ID:            helpers.GenerateULID(),
			AccessTokenID: accessTokens[2].ID,
			Revoked:       true,
			ExpiresAt:     now.Add(-1 * time.Hour), // Expired
		},
	}

	// Add refresh tokens for other access tokens if available
	if len(accessTokens) > 3 {
		refreshTokens = append(refreshTokens, models.OAuthRefreshToken{
			ID:            helpers.GenerateULID(),
			AccessTokenID: accessTokens[3].ID,
			Revoked:       false,
			ExpiresAt:     now.Add(30 * 24 * time.Hour), // 30 days
		})
	}

	// Create refresh tokens in database
	for _, token := range refreshTokens {
		// Check if refresh token already exists
		var existingToken models.OAuthRefreshToken
		err := facades.Orm().Query().Where("id = ?", token.ID).First(&existingToken)
		if err == nil {
			facades.Log().Info("Refresh token already exists: " + token.ID)
			continue
		}

		err = facades.Orm().Query().Create(&token)
		if err != nil {
			facades.Log().Error("Failed to create OAuth refresh token: " + err.Error())
			return err
		}

		facades.Log().Info("Created OAuth refresh token: " + token.ID)
	}

	// Create additional refresh tokens for other users
	var otherUsers []models.User
	err = facades.Orm().Query().Where("email != ?", user.Email).Limit(2).Find(&otherUsers)
	if err == nil && len(otherUsers) > 0 {
		for _, otherUser := range otherUsers {
			// Create access token for other user
			accessToken := models.OAuthAccessToken{
				ID:       helpers.GenerateULID(),
				UserID:   &otherUser.ID,
				ClientID: clients[0].ID,
				Scopes:   &scopes1,
				Revoked:  false,
			}

			// Check if access token already exists
			var existingToken models.OAuthAccessToken
			err := facades.Orm().Query().Where("id = ?", accessToken.ID).First(&existingToken)
			if err == nil {
				facades.Log().Info("Access token already exists: " + accessToken.ID)
				continue
			}

			err = facades.Orm().Query().Create(&accessToken)
			if err != nil {
				facades.Log().Error("Failed to create OAuth access token for other user: " + err.Error())
				return err
			}

			// Create refresh token for the access token
			refreshToken := models.OAuthRefreshToken{
				ID:            helpers.GenerateULID(),
				AccessTokenID: accessToken.ID,
				Revoked:       false,
				ExpiresAt:     now.Add(30 * 24 * time.Hour), // 30 days
			}

			// Check if refresh token already exists
			err = facades.Orm().Query().Where("id = ?", refreshToken.ID).First(&existingToken)
			if err == nil {
				facades.Log().Info("Refresh token already exists: " + refreshToken.ID)
				continue
			}

			err = facades.Orm().Query().Create(&refreshToken)
			if err != nil {
				facades.Log().Error("Failed to create OAuth refresh token for other user: " + err.Error())
				return err
			}

			facades.Log().Info("Created OAuth refresh token for user: " + otherUser.Email)
		}
	}

	facades.Log().Info("OAuth refresh tokens seeded successfully")
	return nil
}
