package seeders

import (
	"fmt"
	"goravel/app/helpers"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type OAuthSeeder struct {
}

// Signature The unique signature for the seeder.
func (s *OAuthSeeder) Signature() string {
	return "oauth_seeder"
}

// Run Run the seeders.
func (s *OAuthSeeder) Run() error {
	facades.Log().Info(fmt.Sprintf("%s started", s.Signature()))
	defer facades.Log().Info(fmt.Sprintf("%s completed", s.Signature()))

	// Create personal access client if it doesn't exist
	var personalClient models.OAuthPersonalAccessClient
	err := facades.Orm().Query().First(&personalClient)
	if err != nil {
		// Create the personal access client
		client := &models.OAuthClient{
			ID:                   helpers.GenerateULID(),
			Name:                 "Goravel Personal Access Client",
			PersonalAccessClient: true,
			PasswordClient:       false,
			Revoked:              false,
		}
		client.SetRedirectURIs([]string{})

		err = facades.Orm().Query().Create(client)
		if err != nil {
			facades.Log().Error("Failed to create personal access client: " + err.Error())
			return err
		}

		// Create the personal access client record
		personalClient = models.OAuthPersonalAccessClient{
			ID:       helpers.GenerateULID(),
			ClientID: client.ID,
		}

		err = facades.Orm().Query().Create(&personalClient)
		if err != nil {
			facades.Log().Error("Failed to create personal access client record: " + err.Error())
			return err
		}

		facades.Log().Info("Personal access client created successfully")
	} else {
		facades.Log().Info("Personal access client already exists")
	}

	// Create password client for API access
	var passwordClient models.OAuthClient
	err = facades.Orm().Query().Where("password_client = ?", true).First(&passwordClient)
	if err != nil {
		passwordClient = models.OAuthClient{
			ID:                   helpers.GenerateULID(),
			Name:                 "Goravel Password Client",
			PersonalAccessClient: false,
			PasswordClient:       true,
			Revoked:              false,
		}
		passwordClient.SetRedirectURIs([]string{})

		err = facades.Orm().Query().Create(&passwordClient)
		if err != nil {
			facades.Log().Error("Failed to create password client: " + err.Error())
			return err
		}

		facades.Log().Info("Password client created successfully")
	} else {
		facades.Log().Info("Password client already exists")
	}

	// Create authorization code client
	var authCodeClient models.OAuthClient
	err = facades.Orm().Query().Where("name = ?", "Goravel Authorization Code Client").First(&authCodeClient)
	if err != nil {
		authCodeClient = models.OAuthClient{
			ID:                   helpers.GenerateULID(),
			Name:                 "Goravel Authorization Code Client",
			PersonalAccessClient: false,
			PasswordClient:       false,
			Revoked:              false,
		}
		authCodeClient.SetRedirectURIs([]string{
			"http://localhost:7000/oauth/callback",
			"https://app.goravel.com/oauth/callback",
			"https://demo.goravel.com/oauth/callback",
		})

		err = facades.Orm().Query().Create(&authCodeClient)
		if err != nil {
			facades.Log().Error("Failed to create authorization code client: " + err.Error())
			return err
		}

		facades.Log().Info("Authorization code client created successfully")
	} else {
		facades.Log().Info("Authorization code client already exists")
	}

	// Create device authorization client
	var deviceClient models.OAuthClient
	err = facades.Orm().Query().Where("name = ?", "Goravel Device Authorization Client").First(&deviceClient)
	if err != nil {
		deviceClient = models.OAuthClient{
			ID:                   helpers.GenerateULID(),
			Name:                 "Goravel Device Authorization Client",
			PersonalAccessClient: false,
			PasswordClient:       false,
			Revoked:              false,
		}
		deviceClient.SetRedirectURIs([]string{
			"https://device.goravel.com/oauth/device",
			"http://localhost:7000/oauth/device",
		})

		err = facades.Orm().Query().Create(&deviceClient)
		if err != nil {
			facades.Log().Error("Failed to create device authorization client: " + err.Error())
			return err
		}

		facades.Log().Info("Device authorization client created successfully")
	} else {
		facades.Log().Info("Device authorization client already exists")
	}

	return nil
}
