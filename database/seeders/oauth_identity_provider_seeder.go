package seeders

import (
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type OAuthIdentityProviderSeeder struct {
}

// Signature The unique signature for the seeder.
func (s *OAuthIdentityProviderSeeder) Signature() string {
	return "OAuthIdentityProviderSeeder"
}

// Run executes the seeder.
func (s *OAuthIdentityProviderSeeder) Run() error {
	providers := []models.OAuthIdentityProvider{
		{
			Name:             "google",
			DisplayName:      "Google",
			ClientID:         facades.Config().GetString("auth.oauth_providers.google.client_id"),
			ClientSecret:     facades.Config().GetString("auth.oauth_providers.google.client_secret"),
			RedirectURL:      facades.Config().GetString("auth.oauth_providers.google.redirect_url"),
			AuthorizationURL: "https://accounts.google.com/o/oauth2/auth",
			TokenURL:         "https://oauth2.googleapis.com/token",
			UserinfoURL:      "https://www.googleapis.com/oauth2/v2/userinfo",
			IconURL:          stringPtr("https://developers.google.com/identity/images/g-logo.png"),
			ButtonColor:      stringPtr("#4285f4"),
			Enabled:          facades.Config().GetBool("auth.oauth_providers.google.enabled"),
			SortOrder:        1,
		},
		{
			Name:             "github",
			DisplayName:      "GitHub",
			ClientID:         facades.Config().GetString("auth.oauth_providers.github.client_id"),
			ClientSecret:     facades.Config().GetString("auth.oauth_providers.github.client_secret"),
			RedirectURL:      facades.Config().GetString("auth.oauth_providers.github.redirect_url"),
			AuthorizationURL: "https://github.com/login/oauth/authorize",
			TokenURL:         "https://github.com/login/oauth/access_token",
			UserinfoURL:      "https://api.github.com/user",
			IconURL:          stringPtr("https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png"),
			ButtonColor:      stringPtr("#333333"),
			Enabled:          facades.Config().GetBool("auth.oauth_providers.github.enabled"),
			SortOrder:        2,
		},
		{
			Name:             "microsoft",
			DisplayName:      "Microsoft",
			ClientID:         facades.Config().GetString("auth.oauth_providers.microsoft.client_id"),
			ClientSecret:     facades.Config().GetString("auth.oauth_providers.microsoft.client_secret"),
			RedirectURL:      facades.Config().GetString("auth.oauth_providers.microsoft.redirect_url"),
			AuthorizationURL: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			TokenURL:         "https://login.microsoftonline.com/common/oauth2/v2.0/token",
			UserinfoURL:      "https://graph.microsoft.com/v1.0/me",
			IconURL:          stringPtr("https://docs.microsoft.com/en-us/azure/active-directory/develop/media/howto-add-branding-in-azure-ad-apps/ms-symbollockup_mssymbol_19.png"),
			ButtonColor:      stringPtr("#0078d4"),
			Enabled:          facades.Config().GetBool("auth.oauth_providers.microsoft.enabled"),
			SortOrder:        3,
		},
		{
			Name:             "discord",
			DisplayName:      "Discord",
			ClientID:         facades.Config().GetString("auth.oauth_providers.discord.client_id"),
			ClientSecret:     facades.Config().GetString("auth.oauth_providers.discord.client_secret"),
			RedirectURL:      facades.Config().GetString("auth.oauth_providers.discord.redirect_url"),
			AuthorizationURL: "https://discord.com/api/oauth2/authorize",
			TokenURL:         "https://discord.com/api/oauth2/token",
			UserinfoURL:      "https://discord.com/api/users/@me",
			IconURL:          stringPtr("https://assets-global.website-files.com/6257adef93867e50d84d30e2/636e0a6a49cf127bf92de1e2_icon_clyde_blurple_RGB.png"),
			ButtonColor:      stringPtr("#5865f2"),
			Enabled:          facades.Config().GetBool("auth.oauth_providers.discord.enabled"),
			SortOrder:        4,
		},
	}

	for _, provider := range providers {
		// Set scopes from config
		scopes := facades.Config().Get("auth.oauth_providers." + provider.Name + ".scopes").([]string)
		if err := provider.SetScopes(scopes); err != nil {
			facades.Log().Error("Failed to set scopes for provider", map[string]interface{}{
				"provider": provider.Name,
				"error":    err.Error(),
			})
			continue
		}

		// Set userinfo mapping based on provider
		mapping := getUserinfoMapping(provider.Name)
		if err := provider.SetUserinfoMapping(mapping); err != nil {
			facades.Log().Error("Failed to set userinfo mapping for provider", map[string]interface{}{
				"provider": provider.Name,
				"error":    err.Error(),
			})
			continue
		}

		// Check if provider already exists
		var existingProvider models.OAuthIdentityProvider
		err := facades.Orm().Query().Where("name", provider.Name).First(&existingProvider)
		if err != nil {
			// Provider doesn't exist, create it
			if err := facades.Orm().Query().Create(&provider); err != nil {
				facades.Log().Error("Failed to create OAuth provider", map[string]interface{}{
					"provider": provider.Name,
					"error":    err.Error(),
				})
			} else {
				facades.Log().Info("Created OAuth provider", map[string]interface{}{
					"provider":     provider.Name,
					"display_name": provider.DisplayName,
					"enabled":      provider.Enabled,
				})
			}
		} else {
			// Provider exists, update it
			existingProvider.DisplayName = provider.DisplayName
			existingProvider.ClientID = provider.ClientID
			existingProvider.ClientSecret = provider.ClientSecret
			existingProvider.RedirectURL = provider.RedirectURL
			existingProvider.Scopes = provider.Scopes
			existingProvider.AuthorizationURL = provider.AuthorizationURL
			existingProvider.TokenURL = provider.TokenURL
			existingProvider.UserinfoURL = provider.UserinfoURL
			existingProvider.UserinfoMapping = provider.UserinfoMapping
			existingProvider.IconURL = provider.IconURL
			existingProvider.ButtonColor = provider.ButtonColor
			existingProvider.Enabled = provider.Enabled
			existingProvider.SortOrder = provider.SortOrder

			if err := facades.Orm().Query().Save(&existingProvider); err != nil {
				facades.Log().Error("Failed to update OAuth provider", map[string]interface{}{
					"provider": provider.Name,
					"error":    err.Error(),
				})
			} else {
				facades.Log().Info("Updated OAuth provider", map[string]interface{}{
					"provider":     provider.Name,
					"display_name": provider.DisplayName,
					"enabled":      provider.Enabled,
				})
			}
		}
	}

	return nil
}

// getUserinfoMapping returns the userinfo field mapping for different providers
func getUserinfoMapping(providerName string) map[string]string {
	switch providerName {
	case "google":
		return map[string]string{
			"id":     "id",
			"email":  "email",
			"name":   "name",
			"avatar": "picture",
		}
	case "github":
		return map[string]string{
			"id":       "id",
			"email":    "email",
			"name":     "name",
			"username": "login",
			"avatar":   "avatar_url",
		}
	case "microsoft":
		return map[string]string{
			"id":     "id",
			"email":  "mail",
			"name":   "displayName",
			"avatar": "photo",
		}
	case "discord":
		return map[string]string{
			"id":       "id",
			"email":    "email",
			"name":     "global_name",
			"username": "username",
			"avatar":   "avatar",
		}
	default:
		return map[string]string{
			"id":     "id",
			"email":  "email",
			"name":   "name",
			"avatar": "avatar",
		}
	}
}

// stringPtr returns a pointer to a string
func stringPtr(s string) *string {
	return &s
}
