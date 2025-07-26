package web

import (
	"strconv"
	"strings"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
	"goravel/app/services"
)

type OAuthProviderController struct {
	oauthIdpService *services.OAuthIdpService
	templateService *services.OAuthProviderTemplateService
}

// NewOAuthProviderController creates a new OAuth provider management controller
func NewOAuthProviderController() *OAuthProviderController {
	return &OAuthProviderController{
		oauthIdpService: services.NewOAuthIdpService(),
		templateService: services.NewOAuthProviderTemplateService(),
	}
}

// Index displays the OAuth providers management page
func (c *OAuthProviderController) Index(ctx http.Context) http.Response {
	// Get all providers (including disabled ones for admin)
	var providers []models.OAuthIdentityProvider
	err := facades.Orm().Query().OrderBy("sort_order").Find(&providers)
	if err != nil {
		facades.Log().Error("Failed to get OAuth providers", map[string]interface{}{
			"error": err.Error(),
		})
		return ctx.Response().Redirect(302, "/dashboard?error=Failed to load OAuth providers")
	}

	return ctx.Response().View().Make("oauth/providers/index.tmpl", map[string]interface{}{
		"title":     "OAuth Providers",
		"providers": providers,
	})
}

// Create displays the create provider form
func (c *OAuthProviderController) Create(ctx http.Context) http.Response {
	return ctx.Response().View().Make("oauth/providers/create.tmpl", map[string]interface{}{
		"title": "Add OAuth Provider",
	})
}

// Store creates a new OAuth provider
func (c *OAuthProviderController) Store(ctx http.Context) http.Response {
	// Validate required fields
	name := strings.TrimSpace(ctx.Request().Input("name"))
	displayName := strings.TrimSpace(ctx.Request().Input("display_name"))
	clientID := strings.TrimSpace(ctx.Request().Input("client_id"))
	clientSecret := strings.TrimSpace(ctx.Request().Input("client_secret"))
	redirectURL := strings.TrimSpace(ctx.Request().Input("redirect_url"))
	authorizationURL := strings.TrimSpace(ctx.Request().Input("authorization_url"))
	tokenURL := strings.TrimSpace(ctx.Request().Input("token_url"))
	userinfoURL := strings.TrimSpace(ctx.Request().Input("userinfo_url"))

	if name == "" || displayName == "" || clientID == "" || clientSecret == "" {
		return ctx.Response().Redirect(302, "/oauth/providers/create?error=Name, display name, client ID, and client secret are required")
	}

	// Check if provider name already exists
	var existingProvider models.OAuthIdentityProvider
	err := facades.Orm().Query().Where("name", name).First(&existingProvider)
	if err == nil {
		return ctx.Response().Redirect(302, "/oauth/providers/create?error=Provider name already exists")
	}

	// Parse scopes
	scopesInput := strings.TrimSpace(ctx.Request().Input("scopes"))
	scopes := "[]"
	if scopesInput != "" {
		// Convert comma-separated to JSON array
		scopeList := strings.Split(scopesInput, ",")
		var cleanScopes []string
		for _, scope := range scopeList {
			cleanScope := strings.TrimSpace(scope)
			if cleanScope != "" {
				cleanScopes = append(cleanScopes, `"`+cleanScope+`"`)
			}
		}
		scopes = "[" + strings.Join(cleanScopes, ",") + "]"
	}

	// Parse userinfo mapping
	userinfoMapping := `{"id": "id", "email": "email", "name": "name", "avatar": "picture"}`
	if mappingInput := strings.TrimSpace(ctx.Request().Input("userinfo_mapping")); mappingInput != "" {
		userinfoMapping = mappingInput
	}

	// Get optional fields
	iconURL := strings.TrimSpace(ctx.Request().Input("icon_url"))
	buttonColor := strings.TrimSpace(ctx.Request().Input("button_color"))
	enabled := ctx.Request().Input("enabled") == "on"

	sortOrder := 999
	if sortInput := ctx.Request().Input("sort_order"); sortInput != "" {
		if parsed, err := strconv.Atoi(sortInput); err == nil {
			sortOrder = parsed
		}
	}

	// Create provider
	provider := models.OAuthIdentityProvider{
		Name:             name,
		DisplayName:      displayName,
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		RedirectURL:      redirectURL,
		Scopes:           scopes,
		AuthorizationURL: authorizationURL,
		TokenURL:         tokenURL,
		UserinfoURL:      userinfoURL,
		UserinfoMapping:  userinfoMapping,
		Enabled:          enabled,
		SortOrder:        sortOrder,
	}

	if iconURL != "" {
		provider.IconURL = &iconURL
	}
	if buttonColor != "" {
		provider.ButtonColor = &buttonColor
	}

	err = facades.Orm().Query().Create(&provider)
	if err != nil {
		facades.Log().Error("Failed to create OAuth provider", map[string]interface{}{
			"error": err.Error(),
			"name":  name,
		})
		return ctx.Response().Redirect(302, "/oauth/providers/create?error=Failed to create provider")
	}

	facades.Log().Info("OAuth provider created", map[string]interface{}{
		"provider_id":   provider.ID,
		"provider_name": provider.Name,
	})

	return ctx.Response().Redirect(302, "/oauth/providers?success=Provider created successfully")
}

// Edit displays the edit provider form
func (c *OAuthProviderController) Edit(ctx http.Context) http.Response {
	providerID := ctx.Request().Route("id")
	if providerID == "" {
		return ctx.Response().Redirect(302, "/oauth/providers?error=Provider ID is required")
	}

	var provider models.OAuthIdentityProvider
	err := facades.Orm().Query().Where("id", providerID).First(&provider)
	if err != nil {
		facades.Log().Error("OAuth provider not found", map[string]interface{}{
			"provider_id": providerID,
			"error":       err.Error(),
		})
		return ctx.Response().Redirect(302, "/oauth/providers?error=Provider not found")
	}

	// Parse scopes for display
	scopes, _ := provider.GetScopes()
	scopesDisplay := strings.Join(scopes, ", ")

	return ctx.Response().View().Make("oauth/providers/edit.tmpl", map[string]interface{}{
		"title":          "Edit OAuth Provider",
		"provider":       provider,
		"scopes_display": scopesDisplay,
	})
}

// Update updates an existing OAuth provider
func (c *OAuthProviderController) Update(ctx http.Context) http.Response {
	providerID := ctx.Request().Route("id")
	if providerID == "" {
		return ctx.Response().Redirect(302, "/oauth/providers?error=Provider ID is required")
	}

	var provider models.OAuthIdentityProvider
	err := facades.Orm().Query().Where("id", providerID).First(&provider)
	if err != nil {
		return ctx.Response().Redirect(302, "/oauth/providers?error=Provider not found")
	}

	// Validate required fields
	displayName := strings.TrimSpace(ctx.Request().Input("display_name"))
	clientID := strings.TrimSpace(ctx.Request().Input("client_id"))
	clientSecret := strings.TrimSpace(ctx.Request().Input("client_secret"))
	redirectURL := strings.TrimSpace(ctx.Request().Input("redirect_url"))
	authorizationURL := strings.TrimSpace(ctx.Request().Input("authorization_url"))
	tokenURL := strings.TrimSpace(ctx.Request().Input("token_url"))
	userinfoURL := strings.TrimSpace(ctx.Request().Input("userinfo_url"))

	if displayName == "" || clientID == "" || clientSecret == "" {
		return ctx.Response().Redirect(302, "/oauth/providers/"+providerID+"/edit?error=Display name, client ID, and client secret are required")
	}

	// Parse scopes
	scopesInput := strings.TrimSpace(ctx.Request().Input("scopes"))
	scopes := "[]"
	if scopesInput != "" {
		scopeList := strings.Split(scopesInput, ",")
		var cleanScopes []string
		for _, scope := range scopeList {
			cleanScope := strings.TrimSpace(scope)
			if cleanScope != "" {
				cleanScopes = append(cleanScopes, `"`+cleanScope+`"`)
			}
		}
		scopes = "[" + strings.Join(cleanScopes, ",") + "]"
	}

	// Parse userinfo mapping
	userinfoMapping := strings.TrimSpace(ctx.Request().Input("userinfo_mapping"))
	if userinfoMapping == "" {
		userinfoMapping = `{"id": "id", "email": "email", "name": "name", "avatar": "picture"}`
	}

	// Update provider fields
	provider.DisplayName = displayName
	provider.ClientID = clientID
	provider.ClientSecret = clientSecret
	provider.RedirectURL = redirectURL
	provider.Scopes = scopes
	provider.AuthorizationURL = authorizationURL
	provider.TokenURL = tokenURL
	provider.UserinfoURL = userinfoURL
	provider.UserinfoMapping = userinfoMapping
	provider.Enabled = ctx.Request().Input("enabled") == "on"

	if sortInput := ctx.Request().Input("sort_order"); sortInput != "" {
		if parsed, err := strconv.Atoi(sortInput); err == nil {
			provider.SortOrder = parsed
		}
	}

	// Handle optional fields
	iconURL := strings.TrimSpace(ctx.Request().Input("icon_url"))
	if iconURL != "" {
		provider.IconURL = &iconURL
	} else {
		provider.IconURL = nil
	}

	buttonColor := strings.TrimSpace(ctx.Request().Input("button_color"))
	if buttonColor != "" {
		provider.ButtonColor = &buttonColor
	} else {
		provider.ButtonColor = nil
	}

	err = facades.Orm().Query().Save(&provider)
	if err != nil {
		facades.Log().Error("Failed to update OAuth provider", map[string]interface{}{
			"provider_id": providerID,
			"error":       err.Error(),
		})
		return ctx.Response().Redirect(302, "/oauth/providers/"+providerID+"/edit?error=Failed to update provider")
	}

	facades.Log().Info("OAuth provider updated", map[string]interface{}{
		"provider_id":   provider.ID,
		"provider_name": provider.Name,
	})

	return ctx.Response().Redirect(302, "/oauth/providers?success=Provider updated successfully")
}

// Delete removes an OAuth provider
func (c *OAuthProviderController) Delete(ctx http.Context) http.Response {
	providerID := ctx.Request().Route("id")
	if providerID == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "bad_request",
			"message": "Provider ID is required",
		})
	}

	var provider models.OAuthIdentityProvider
	err := facades.Orm().Query().Where("id", providerID).First(&provider)
	if err != nil {
		return ctx.Response().Json(404, map[string]interface{}{
			"error":   "not_found",
			"message": "Provider not found",
		})
	}

	// Check if provider has associated user identities
	identityCount, _ := facades.Orm().Query().Model(&models.OAuthUserIdentity{}).Where("provider_id", providerID).Count()

	if identityCount > 0 {
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "provider_in_use",
			"message": "Cannot delete provider that has active user connections",
		})
	}

	_, err = facades.Orm().Query().Delete(&provider)
	if err != nil {
		facades.Log().Error("Failed to delete OAuth provider", map[string]interface{}{
			"provider_id": providerID,
			"error":       err.Error(),
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"error":   "server_error",
			"message": "Failed to delete provider",
		})
	}

	facades.Log().Info("OAuth provider deleted", map[string]interface{}{
		"provider_id":   providerID,
		"provider_name": provider.Name,
	})

	return ctx.Response().Json(200, map[string]interface{}{
		"message": "Provider deleted successfully",
	})
}

// Toggle enables or disables an OAuth provider
func (c *OAuthProviderController) Toggle(ctx http.Context) http.Response {
	providerID := ctx.Request().Route("id")
	if providerID == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "bad_request",
			"message": "Provider ID is required",
		})
	}

	var provider models.OAuthIdentityProvider
	err := facades.Orm().Query().Where("id", providerID).First(&provider)
	if err != nil {
		return ctx.Response().Json(404, map[string]interface{}{
			"error":   "not_found",
			"message": "Provider not found",
		})
	}

	// Toggle enabled status
	provider.Enabled = !provider.Enabled

	err = facades.Orm().Query().Save(&provider)
	if err != nil {
		facades.Log().Error("Failed to toggle OAuth provider", map[string]interface{}{
			"provider_id": providerID,
			"error":       err.Error(),
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"error":   "server_error",
			"message": "Failed to toggle provider status",
		})
	}

	status := "disabled"
	if provider.Enabled {
		status = "enabled"
	}

	facades.Log().Info("OAuth provider toggled", map[string]interface{}{
		"provider_id":   providerID,
		"provider_name": provider.Name,
		"new_status":    status,
	})

	return ctx.Response().Json(200, map[string]interface{}{
		"message": "Provider " + status + " successfully",
		"enabled": provider.Enabled,
	})
}

// Templates displays available provider templates
func (c *OAuthProviderController) Templates(ctx http.Context) http.Response {
	templates := c.templateService.GetAvailableTemplates()

	return ctx.Response().View().Make("oauth/providers/templates.tmpl", map[string]interface{}{
		"title":     "OAuth Provider Templates",
		"templates": templates,
	})
}

// CreateFromTemplate creates a provider from a template
func (c *OAuthProviderController) CreateFromTemplate(ctx http.Context) http.Response {
	templateName := ctx.Request().Input("template")
	clientID := strings.TrimSpace(ctx.Request().Input("client_id"))
	clientSecret := strings.TrimSpace(ctx.Request().Input("client_secret"))
	redirectURL := strings.TrimSpace(ctx.Request().Input("redirect_url"))

	if templateName == "" || clientID == "" || clientSecret == "" || redirectURL == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "bad_request",
			"message": "Template, client ID, client secret, and redirect URL are required",
		})
	}

	provider, err := c.templateService.CreateProviderFromTemplate(templateName, clientID, clientSecret, redirectURL)
	if err != nil {
		facades.Log().Error("Failed to create provider from template", map[string]interface{}{
			"template": templateName,
			"error":    err.Error(),
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"error":   "server_error",
			"message": "Failed to create provider from template",
		})
	}

	facades.Log().Info("Provider created from template", map[string]interface{}{
		"template":     templateName,
		"provider_id":  provider.ID,
		"display_name": provider.DisplayName,
	})

	return ctx.Response().Json(200, map[string]interface{}{
		"message":  "Provider created successfully from template",
		"provider": provider,
	})
}

// GetTemplate returns a specific template with setup instructions
func (c *OAuthProviderController) GetTemplate(ctx http.Context) http.Response {
	templateName := ctx.Request().Route("template")
	if templateName == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "bad_request",
			"message": "Template name is required",
		})
	}

	template, err := c.templateService.GetTemplate(templateName)
	if err != nil {
		return ctx.Response().Json(404, map[string]interface{}{
			"error":   "not_found",
			"message": "Template not found",
		})
	}

	return ctx.Response().Json(200, template)
}
