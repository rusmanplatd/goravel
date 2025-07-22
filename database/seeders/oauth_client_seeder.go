package seeders

import (
	"goravel/app/helpers"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type OAuthClientSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *OAuthClientSeeder) Signature() string {
	return "OAuthClientSeeder"
}

// Run executes the seeder logic.
func (s *OAuthClientSeeder) Run() error {
	facades.Log().Info("Starting OAuth client seeder...")

	// Check if clients already exist
	var existingClients []models.OAuthClient
	err := facades.Orm().Query().Limit(1).Find(&existingClients)
	if err == nil && len(existingClients) > 0 {
		facades.Log().Info("OAuth clients already exist, skipping OAuthClientSeeder")
		return nil
	}

	// Get a test user to associate with some clients
	var user models.User
	err = facades.Orm().Query().First(&user)
	if err != nil {
		facades.Log().Info("No users found, creating OAuth clients without user association")
	}

	// Create various types of OAuth clients
	clients := []models.OAuthClient{
		{
			ID:                   helpers.GenerateULID(),
			UserID:               &user.ID,
			Name:                 "Web Application Client",
			PersonalAccessClient: false,
			PasswordClient:       false,
			Revoked:              false,
		},
		{
			ID:                   helpers.GenerateULID(),
			UserID:               &user.ID,
			Name:                 "Mobile Application Client",
			PersonalAccessClient: false,
			PasswordClient:       true,
			Revoked:              false,
		},
		{
			ID:                   helpers.GenerateULID(),
			Name:                 "Public API Client",
			PersonalAccessClient: false,
			PasswordClient:       false,
			Revoked:              false,
		},
		{
			ID:                   helpers.GenerateULID(),
			UserID:               &user.ID,
			Name:                 "Test Client (Revoked)",
			PersonalAccessClient: false,
			PasswordClient:       false,
			Revoked:              true,
		},
		{
			ID:                   helpers.GenerateULID(),
			Name:                 "Third-party Integration",
			PersonalAccessClient: false,
			PasswordClient:       true,
			Revoked:              false,
		},
		{
			ID:                   helpers.GenerateULID(),
			UserID:               &user.ID,
			Name:                 "Desktop Application",
			PersonalAccessClient: false,
			PasswordClient:       true,
			Revoked:              false,
		},
		{
			ID:                   helpers.GenerateULID(),
			Name:                 "IoT Device Client",
			PersonalAccessClient: false,
			PasswordClient:       false,
			Revoked:              false,
		},
		{
			ID:                   helpers.GenerateULID(),
			UserID:               &user.ID,
			Name:                 "Admin Dashboard",
			PersonalAccessClient: false,
			PasswordClient:       true,
			Revoked:              false,
		},
		{
			ID:                   helpers.GenerateULID(),
			Name:                 "Microservice Client",
			PersonalAccessClient: false,
			PasswordClient:       true,
			Revoked:              false,
		},
		{
			ID:                   helpers.GenerateULID(),
			UserID:               &user.ID,
			Name:                 "Development Client",
			PersonalAccessClient: false,
			PasswordClient:       true,
			Revoked:              false,
		},
	}

	// Set redirect URIs for each client
	clients[0].SetRedirectURIs([]string{"https://webapp.example.com/callback", "http://localhost:3000/callback", "https://staging.webapp.example.com/callback"})
	clients[1].SetRedirectURIs([]string{"com.mobileapp://oauth/callback", "com.mobileapp://auth", "com.mobileapp://login"})
	clients[2].SetRedirectURIs([]string{"https://api.example.com/oauth/callback", "https://api-staging.example.com/oauth/callback"})
	clients[3].SetRedirectURIs([]string{"https://revoked-app.example.com/callback"})
	clients[4].SetRedirectURIs([]string{"https://integration.example.com/oauth/callback", "https://partner.example.com/oauth/callback"})
	clients[5].SetRedirectURIs([]string{"http://localhost:3000/callback", "https://desktop.example.com/callback"})
	clients[6].SetRedirectURIs([]string{"https://iot.example.com/device/callback", "https://sensor.example.com/auth"})
	clients[7].SetRedirectURIs([]string{"https://admin.example.com/dashboard/callback", "http://localhost:4000/admin/callback"})
	clients[8].SetRedirectURIs([]string{"https://microservice.example.com/oauth/callback", "https://service.example.com/auth"})
	clients[9].SetRedirectURIs([]string{"http://localhost:5000/callback", "https://dev.example.com/oauth/callback"})

	// Create clients in database
	for _, client := range clients {
		err := facades.Orm().Query().Create(&client)
		if err != nil {
			facades.Log().Error("Failed to create OAuth client " + client.Name + ": " + err.Error())
			return err
		}
		facades.Log().Info("Created OAuth client: " + client.Name + " (ID: " + client.ID + ")")
	}

	facades.Log().Info("OAuth clients seeded successfully - Created " + string(rune(len(clients))) + " clients")
	return nil
}
