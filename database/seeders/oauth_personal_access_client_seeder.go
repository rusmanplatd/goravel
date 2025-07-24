package seeders

import (
	"fmt"
	"goravel/app/helpers"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type OAuthPersonalAccessClientSeeder struct {
}

// Signature The name and signature of the seeder.
func (s *OAuthPersonalAccessClientSeeder) Signature() string {
	return "OAuthPersonalAccessClientSeeder"
}

// Run executes the seeder logic.
func (s *OAuthPersonalAccessClientSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))
	// Get a test user to associate with personal access clients
	var user models.User
	err := facades.Orm().Query().First(&user)
	if err != nil {
		facades.Log().Info("No users found, skipping OAuthPersonalAccessClientSeeder")
		return nil
	}

	// Create OAuth clients that are personal access clients
	personalAccessClients := []models.OAuthClient{
		{
			ID:                   helpers.GenerateULID(),
			UserID:               &user.ID,
			Name:                 "Personal Access Client 1",
			PersonalAccessClient: true,
			PasswordClient:       false,
			Revoked:              false,
		},
		{
			ID:                   helpers.GenerateULID(),
			UserID:               &user.ID,
			Name:                 "Personal Access Client 2",
			PersonalAccessClient: true,
			PasswordClient:       false,
			Revoked:              false,
		},
		{
			ID:                   helpers.GenerateULID(),
			UserID:               &user.ID,
			Name:                 "Mobile Personal Client",
			PersonalAccessClient: true,
			PasswordClient:       false,
			Revoked:              false,
		},
		{
			ID:                   helpers.GenerateULID(),
			UserID:               &user.ID,
			Name:                 "API Testing Client",
			PersonalAccessClient: true,
			PasswordClient:       false,
			Revoked:              false,
		},
		{
			ID:                   helpers.GenerateULID(),
			UserID:               &user.ID,
			Name:                 "Development Client",
			PersonalAccessClient: true,
			PasswordClient:       false,
			Revoked:              false,
		},
	}

	// Create OAuth clients in database
	for _, client := range personalAccessClients {
		// Check if OAuth client already exists
		var existingClient models.OAuthClient
		err := facades.Orm().Query().Where("user_id = ? AND name = ?", client.UserID, client.Name).First(&existingClient)
		if err == nil {
			facades.Log().Info("OAuth client already exists: " + client.Name)
			continue
		}

		err = facades.Orm().Query().Create(&client)
		if err != nil {
			facades.Log().Error("Failed to create OAuth client " + client.Name + ": " + err.Error())
			return err
		}

		// Create the personal access client reference
		personalAccessClient := models.OAuthPersonalAccessClient{
			ID:       helpers.GenerateULID(),
			ClientID: client.ID,
		}

		err = facades.Orm().Query().Create(&personalAccessClient)
		if err != nil {
			facades.Log().Error("Failed to create personal access client reference: " + err.Error())
			return err
		}

		facades.Log().Info("Created personal access client: " + client.Name)
	}

	// Create additional personal access clients for other users
	var otherUsers []models.User
	err = facades.Orm().Query().Where("email != ?", user.Email).Limit(3).Find(&otherUsers)
	if err == nil && len(otherUsers) > 0 {
		for i, otherUser := range otherUsers {
			client := models.OAuthClient{
				ID:                   helpers.GenerateULID(),
				UserID:               &otherUser.ID,
				Name:                 "Personal Client for " + otherUser.Name,
				PersonalAccessClient: true,
				PasswordClient:       false,
				Revoked:              false,
			}

			// Check if OAuth client already exists
			var existingClient models.OAuthClient
			err := facades.Orm().Query().Where("user_id = ? AND name = ?", client.UserID, client.Name).First(&existingClient)
			if err == nil {
				facades.Log().Info("OAuth client already exists: " + client.Name)
				continue
			}

			err = facades.Orm().Query().Create(&client)
			if err != nil {
				facades.Log().Error("Failed to create OAuth client " + client.Name + ": " + err.Error())
				return err
			}

			// Create the personal access client reference
			personalAccessClient := models.OAuthPersonalAccessClient{
				ID:       helpers.GenerateULID(),
				ClientID: client.ID,
			}

			err = facades.Orm().Query().Create(&personalAccessClient)
			if err != nil {
				facades.Log().Error("Failed to create personal access client reference: " + err.Error())
				return err
			}

			facades.Log().Info("Created personal access client: " + client.Name)

			// Limit to 2 additional clients per user
			if i >= 1 {
				break
			}
		}
	}

	facades.Log().Info("OAuth personal access clients seeded successfully")
	return nil
}
