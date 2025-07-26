package web

import (
	"fmt"
	"strings"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
	"goravel/app/services"
)

type OAuthClientController struct {
	oauthService *services.OAuthService
}

// NewOAuthClientController creates a new OAuth client controller
func NewOAuthClientController() *OAuthClientController {
	return &OAuthClientController{
		oauthService: services.NewOAuthService(),
	}
}

// getCurrentUser gets the current authenticated user from context
func (c *OAuthClientController) getCurrentUser(ctx http.Context) *models.User {
	// Get user from context (set by WebAuth middleware)
	user := ctx.Value("user")
	if user == nil {
		return nil
	}

	// Type assertion to ensure it's a User pointer
	if userPtr, ok := user.(*models.User); ok {
		return userPtr
	}

	return nil
}

// Index displays the OAuth clients list
func (c *OAuthClientController) Index(ctx http.Context) http.Response {
	// Get authenticated user
	authenticatedUser := c.getCurrentUser(ctx)
	if authenticatedUser == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get user's OAuth clients
	var clients []models.OAuthClient
	err := facades.Orm().Query().Where("user_id", authenticatedUser.ID).Find(&clients)
	if err != nil {
		facades.Log().Error("Failed to retrieve OAuth clients", map[string]interface{}{
			"error":   err.Error(),
			"user_id": authenticatedUser.ID,
		})
		return ctx.Response().View().Make("oauth/clients/index.tmpl", map[string]interface{}{
			"title":   "OAuth Clients",
			"clients": []models.OAuthClient{},
			"error":   "Failed to retrieve OAuth clients",
		})
	}

	return ctx.Response().View().Make("oauth/clients/index.tmpl", map[string]interface{}{
		"title":   "OAuth Clients",
		"clients": clients,
	})
}

// Store creates a new OAuth client
func (c *OAuthClientController) Store(ctx http.Context) http.Response {
	// Get authenticated user
	authenticatedUser := c.getCurrentUser(ctx)
	if authenticatedUser == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get form data
	name := ctx.Request().Input("name")
	clientType := ctx.Request().Input("client_type", "confidential")
	redirectURIsInput := ctx.Request().Input("redirect_uris", "")

	// Validate required fields
	if name == "" {
		return ctx.Response().Redirect(302, "/oauth/clients?error=Application name is required")
	}

	// Parse redirect URIs
	var redirectURIs []string
	if redirectURIsInput != "" {
		uris := strings.Split(redirectURIsInput, "\n")
		for _, uri := range uris {
			trimmed := strings.TrimSpace(uri)
			if trimmed != "" {
				redirectURIs = append(redirectURIs, trimmed)
			}
		}
	}

	// Also check for array format (from JavaScript form submission)
	if len(redirectURIs) == 0 {
		// Try to get redirect URIs as array
		for i := 0; ; i++ {
			uri := ctx.Request().Input(fmt.Sprintf("redirect_uris[%d]", i))
			if uri == "" {
				break
			}
			redirectURIs = append(redirectURIs, uri)
		}
	}

	// Determine client configuration based on type
	var personalAccessClient, passwordClient bool
	switch clientType {
	case "personal":
		personalAccessClient = true
	case "password":
		passwordClient = true
	}

	// Create the OAuth client
	client, err := c.oauthService.CreateClient(
		name,
		&authenticatedUser.ID,
		redirectURIs,
		personalAccessClient,
		passwordClient,
	)
	if err != nil {
		facades.Log().Error("Failed to create OAuth client", map[string]interface{}{
			"error":   err.Error(),
			"user_id": authenticatedUser.ID,
			"name":    name,
		})
		return ctx.Response().Redirect(302, "/oauth/clients?error=Failed to create OAuth client")
	}

	facades.Log().Info("OAuth client created", map[string]interface{}{
		"client_id": client.ID,
		"user_id":   authenticatedUser.ID,
		"name":      client.Name,
	})

	return ctx.Response().Redirect(302, "/oauth/clients?success=OAuth client created successfully")
}

// Show displays a specific OAuth client
func (c *OAuthClientController) Show(ctx http.Context) http.Response {
	clientID := ctx.Request().Route("id")

	// Get authenticated user
	authenticatedUser := c.getCurrentUser(ctx)
	if authenticatedUser == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get the OAuth client
	var client models.OAuthClient
	err := facades.Orm().Query().Where("id", clientID).Where("user_id", authenticatedUser.ID).First(&client)
	if err != nil {
		return ctx.Response().Redirect(302, "/oauth/clients?error=OAuth client not found")
	}

	// Get client's access tokens
	var tokens []models.OAuthAccessToken
	facades.Orm().Query().Where("client_id", client.ID).Find(&tokens)

	return ctx.Response().View().Make("oauth/clients/show.tmpl", map[string]interface{}{
		"title":  "OAuth Client Details",
		"client": client,
		"tokens": tokens,
	})
}

// Edit displays the edit form for an OAuth client
func (c *OAuthClientController) Edit(ctx http.Context) http.Response {
	clientID := ctx.Request().Route("id")

	// Get authenticated user
	authenticatedUser := c.getCurrentUser(ctx)
	if authenticatedUser == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get the OAuth client
	var client models.OAuthClient
	err := facades.Orm().Query().Where("id", clientID).Where("user_id", authenticatedUser.ID).First(&client)
	if err != nil {
		return ctx.Response().Redirect(302, "/oauth/clients?error=OAuth client not found")
	}

	return ctx.Response().View().Make("oauth/clients/edit.tmpl", map[string]interface{}{
		"title":  "Edit OAuth Client",
		"client": client,
	})
}

// Update updates an OAuth client
func (c *OAuthClientController) Update(ctx http.Context) http.Response {
	clientID := ctx.Request().Route("id")

	// Get authenticated user
	authenticatedUser := c.getCurrentUser(ctx)
	if authenticatedUser == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get the OAuth client
	var client models.OAuthClient
	err := facades.Orm().Query().Where("id", clientID).Where("user_id", authenticatedUser.ID).First(&client)
	if err != nil {
		return ctx.Response().Redirect(302, "/oauth/clients?error=OAuth client not found")
	}

	// Get form data
	name := ctx.Request().Input("name")
	redirectURIsInput := ctx.Request().Input("redirect_uris", "")

	// Validate required fields
	if name == "" {
		return ctx.Response().Redirect(302, fmt.Sprintf("/oauth/clients/%s/edit?error=Application name is required", clientID))
	}

	// Parse redirect URIs
	var redirectURIs []string
	if redirectURIsInput != "" {
		uris := strings.Split(redirectURIsInput, "\n")
		for _, uri := range uris {
			trimmed := strings.TrimSpace(uri)
			if trimmed != "" {
				redirectURIs = append(redirectURIs, trimmed)
			}
		}
	}

	// Update client
	client.Name = name
	client.SetRedirectURIs(redirectURIs)

	err = facades.Orm().Query().Save(&client)
	if err != nil {
		facades.Log().Error("Failed to update OAuth client", map[string]interface{}{
			"error":     err.Error(),
			"client_id": client.ID,
			"user_id":   authenticatedUser.ID,
		})
		return ctx.Response().Redirect(302, fmt.Sprintf("/oauth/clients/%s/edit?error=Failed to update OAuth client", clientID))
	}

	facades.Log().Info("OAuth client updated", map[string]interface{}{
		"client_id": client.ID,
		"user_id":   authenticatedUser.ID,
		"name":      client.Name,
	})

	return ctx.Response().Redirect(302, fmt.Sprintf("/oauth/clients/%s?success=OAuth client updated successfully", clientID))
}

// Delete deletes an OAuth client
func (c *OAuthClientController) Delete(ctx http.Context) http.Response {
	clientID := ctx.Request().Route("id")

	// Get authenticated user
	authenticatedUser := c.getCurrentUser(ctx)
	if authenticatedUser == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get the OAuth client
	var client models.OAuthClient
	err := facades.Orm().Query().Where("id", clientID).Where("user_id", authenticatedUser.ID).First(&client)
	if err != nil {
		return ctx.Response().Redirect(302, "/oauth/clients?error=OAuth client not found")
	}

	// Revoke all associated tokens first
	var tokens []models.OAuthAccessToken
	facades.Orm().Query().Where("client_id", client.ID).Find(&tokens)
	for _, token := range tokens {
		token.Revoke()
	}

	// Delete the client
	_, err = facades.Orm().Query().Delete(&client)
	if err != nil {
		facades.Log().Error("Failed to delete OAuth client", map[string]interface{}{
			"error":     err.Error(),
			"client_id": client.ID,
			"user_id":   authenticatedUser.ID,
		})
		return ctx.Response().Redirect(302, "/oauth/clients?error=Failed to delete OAuth client")
	}

	facades.Log().Info("OAuth client deleted", map[string]interface{}{
		"client_id": client.ID,
		"user_id":   authenticatedUser.ID,
		"name":      client.Name,
	})

	return ctx.Response().Redirect(302, "/oauth/clients?success=OAuth client deleted successfully")
}
