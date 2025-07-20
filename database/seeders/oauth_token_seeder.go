package seeders

import (
	"time"

	"goravel/app/helpers"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type OAuthTokenSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *OAuthTokenSeeder) Signature() string {
	return "OAuthTokenSeeder"
}

// Run executes the seeder logic.
func (s *OAuthTokenSeeder) Run() error {
	facades.Log().Info("Starting OAuth token seeder...")

	// Get OAuth clients
	var clients []models.OAuthClient
	err := facades.Orm().Query().Find(&clients)
	if err != nil {
		facades.Log().Error("Failed to fetch OAuth clients: " + err.Error())
		return err
	}

	// Get users
	var users []models.User
	err = facades.Orm().Query().Find(&users)
	if err != nil {
		facades.Log().Error("Failed to fetch users: " + err.Error())
		return err
	}

	if len(clients) == 0 {
		facades.Log().Warning("No OAuth clients found, skipping token seeding")
		return nil
	}

	if len(users) == 0 {
		facades.Log().Warning("No users found, skipping token seeding")
		return nil
	}

	// Create access tokens
	webAppTokenName := "Web App Token"
	webAppTokenScopes := "read write profile"
	mobileAppTokenName := "Mobile App Token"
	mobileAppTokenScopes := "read profile email"
	apiTokenName := "API Token"
	apiTokenScopes := "read write admin"
	revokedTokenName := "Revoked Token"
	revokedTokenScopes := "read"
	integrationTokenName := "Integration Token"
	integrationTokenScopes := "read write api"

	accessTokens := []models.OAuthAccessToken{
		{
			ID:       helpers.GenerateULID(),
			UserID:   &users[0].ID,
			ClientID: clients[0].ID,
			Name:     &webAppTokenName,
			Scopes:   &webAppTokenScopes,
			Revoked:  false,
		},
		{
			ID:       helpers.GenerateULID(),
			UserID:   &users[1].ID,
			ClientID: clients[1].ID,
			Name:     &mobileAppTokenName,
			Scopes:   &mobileAppTokenScopes,
			Revoked:  false,
		},
		{
			ID:       helpers.GenerateULID(),
			UserID:   &users[0].ID,
			ClientID: clients[2].ID,
			Name:     &apiTokenName,
			Scopes:   &apiTokenScopes,
			Revoked:  false,
		},
		{
			ID:       helpers.GenerateULID(),
			UserID:   &users[1].ID,
			ClientID: clients[3].ID,
			Name:     &revokedTokenName,
			Scopes:   &revokedTokenScopes,
			Revoked:  true,
		},
		{
			ID:       helpers.GenerateULID(),
			UserID:   &users[0].ID,
			ClientID: clients[4].ID,
			Name:     &integrationTokenName,
			Scopes:   &integrationTokenScopes,
			Revoked:  false,
		},
	}

	// Create access tokens in database
	for _, token := range accessTokens {
		// Check if token already exists
		var existingToken models.OAuthAccessToken
		err := facades.Orm().Query().Where("id = ?", token.ID).First(&existingToken)
		if err != nil {
			err = facades.Orm().Query().Create(&token)
			if err != nil {
				facades.Log().Error("Failed to create access token " + *token.Name + ": " + err.Error())
				return err
			}
			facades.Log().Info("Created access token: " + *token.Name + " for user " + *token.UserID)
		} else {
			if existingToken.Name != nil {
				facades.Log().Info("Access token already exists: " + *existingToken.Name)
			} else {
				facades.Log().Info("Access token already exists: " + existingToken.ID)
			}
		}
	}

	// Create refresh tokens for some access tokens
	refreshTokens := []models.OAuthRefreshToken{
		{
			ID:            helpers.GenerateULID(),
			AccessTokenID: accessTokens[0].ID,
			Revoked:       false,
			ExpiresAt:     time.Now().Add(30 * 24 * time.Hour), // 30 days
		},
		{
			ID:            helpers.GenerateULID(),
			AccessTokenID: accessTokens[1].ID,
			Revoked:       false,
			ExpiresAt:     time.Now().Add(60 * 24 * time.Hour), // 60 days
		},
		{
			ID:            helpers.GenerateULID(),
			AccessTokenID: accessTokens[2].ID,
			Revoked:       false,
			ExpiresAt:     time.Now().Add(90 * 24 * time.Hour), // 90 days
		},
		{
			ID:            helpers.GenerateULID(),
			AccessTokenID: accessTokens[4].ID,
			Revoked:       false,
			ExpiresAt:     time.Now().Add(180 * 24 * time.Hour), // 180 days
		},
	}

	// Create refresh tokens in database
	for _, token := range refreshTokens {
		// Check if token already exists
		var existingToken models.OAuthRefreshToken
		err := facades.Orm().Query().Where("id = ?", token.ID).First(&existingToken)
		if err != nil {
			err = facades.Orm().Query().Create(&token)
			if err != nil {
				facades.Log().Error("Failed to create refresh token: " + err.Error())
				return err
			}
			facades.Log().Info("Created refresh token for access token: " + token.AccessTokenID)
		} else {
			facades.Log().Info("Refresh token already exists for access token: " + existingToken.AccessTokenID)
		}
	}

	facades.Log().Info("OAuth token seeder completed successfully")
	return nil
}
