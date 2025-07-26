package web

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
	"goravel/app/services"
)

type OAuthSecurityController struct {
	oauthService *services.OAuthService
}

// NewOAuthSecurityController creates a new OAuth security controller
func NewOAuthSecurityController() *OAuthSecurityController {
	return &OAuthSecurityController{
		oauthService: services.NewOAuthService(),
	}
}

// getCurrentUser gets the current authenticated user from context
func (c *OAuthSecurityController) getCurrentUser(ctx http.Context) *models.User {
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

// Index displays the security center with connected apps
func (c *OAuthSecurityController) Index(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get all active consents for the user
	var consents []models.OAuthConsent
	err := facades.Orm().Query().
		Where("user_id", user.ID).
		Where("granted", true).
		Where("revoked", false).
		With("Client").
		OrderBy("created_at", "desc").
		Get(&consents)

	if err != nil {
		facades.Log().Error("Failed to fetch user consents: " + err.Error())
		consents = []models.OAuthConsent{}
	}

	// Get active access tokens
	var activeTokens []models.OAuthAccessToken
	err = facades.Orm().Query().
		Where("user_id", user.ID).
		Where("revoked", false).
		With("Client").
		OrderBy("created_at", "desc").
		Get(&activeTokens)

	if err != nil {
		facades.Log().Error("Failed to fetch active tokens: " + err.Error())
		activeTokens = []models.OAuthAccessToken{}
	}

	// Group consents by client for better display
	clientConsents := make(map[string]*models.OAuthConsent)
	for i, consent := range consents {
		if consent.IsActive() {
			clientConsents[consent.ClientID] = &consents[i]
		}
	}

	data := map[string]interface{}{
		"user":              user,
		"consents":          clientConsents,
		"activeTokens":      activeTokens,
		"totalApps":         len(clientConsents),
		"totalTokens":       len(activeTokens),
		"scopeDescriptions": c.getScopeDescriptions(),
	}

	return ctx.Response().View().Make("oauth/security/index.tmpl", data)
}

// RevokeConsent revokes a user's consent for a specific client
func (c *OAuthSecurityController) RevokeConsent(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}
	clientID := ctx.Request().Route("client_id")

	// Find and revoke the consent
	var consent models.OAuthConsent
	err := facades.Orm().Query().
		Where("user_id", user.ID).
		Where("client_id", clientID).
		Where("revoked", false).
		First(&consent)

	if err != nil {
		return ctx.Response().Json(400, map[string]interface{}{
			"success": false,
			"message": "Consent not found",
		})
	}

	// Revoke the consent
	consent.Revoke()
	facades.Orm().Query().Save(&consent)

	// Also revoke all active tokens for this client
	facades.Orm().Query().
		Model(&models.OAuthAccessToken{}).
		Where("user_id", user.ID).
		Where("client_id", clientID).
		Where("revoked", false).
		Update("revoked", true)

	// Also revoke refresh tokens
	var accessTokens []models.OAuthAccessToken
	facades.Orm().Query().
		Where("user_id", user.ID).
		Where("client_id", clientID).
		Get(&accessTokens)

	for _, token := range accessTokens {
		facades.Orm().Query().
			Model(&models.OAuthRefreshToken{}).
			Where("access_token_id", token.ID).
			Where("revoked", false).
			Update("revoked", true)
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "Access revoked successfully",
	})
}

// RevokeToken revokes a specific access token
func (c *OAuthSecurityController) RevokeToken(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}
	tokenID := ctx.Request().Route("token_id")

	// Find and revoke the token
	var token models.OAuthAccessToken
	err := facades.Orm().Query().
		Where("id", tokenID).
		Where("user_id", user.ID).
		Where("revoked", false).
		First(&token)

	if err != nil {
		return ctx.Response().Json(400, map[string]interface{}{
			"success": false,
			"message": "Token not found",
		})
	}

	// Revoke the token
	token.Revoke()

	// Also revoke associated refresh token
	facades.Orm().Query().
		Model(&models.OAuthRefreshToken{}).
		Where("access_token_id", token.ID).
		Where("revoked", false).
		Update("revoked", true)

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "Token revoked successfully",
	})
}

// ConsentHistory shows the consent history for a user
func (c *OAuthSecurityController) ConsentHistory(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get all consents (including revoked ones) for the user
	var consents []models.OAuthConsent
	err := facades.Orm().Query().
		Where("user_id", user.ID).
		With("Client").
		OrderBy("created_at", "desc").
		Paginate(1, 20, &consents, nil)

	if err != nil {
		facades.Log().Error("Failed to fetch consent history: " + err.Error())
		consents = []models.OAuthConsent{}
	}

	data := map[string]interface{}{
		"user":              user,
		"consents":          consents,
		"scopeDescriptions": c.getScopeDescriptions(),
	}

	return ctx.Response().View().Make("oauth/security/history.tmpl", data)
}

// AppDetails shows detailed information about a connected app
func (c *OAuthSecurityController) AppDetails(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}
	clientID := ctx.Request().Route("client_id")

	// Get client information
	var client models.OAuthClient
	err := facades.Orm().Query().Where("id", clientID).First(&client)
	if err != nil {
		return ctx.Response().Status(404).Json(map[string]interface{}{
			"error": "Application not found",
		})
	}

	// Get consent information
	var consent models.OAuthConsent
	err = facades.Orm().Query().
		Where("user_id", user.ID).
		Where("client_id", clientID).
		Where("revoked", false).
		First(&consent)

	if err != nil {
		return ctx.Response().Status(404).Json(map[string]interface{}{
			"error": "No active consent found",
		})
	}

	// Get active tokens for this client
	var tokens []models.OAuthAccessToken
	facades.Orm().Query().
		Where("user_id", user.ID).
		Where("client_id", clientID).
		Where("revoked", false).
		OrderBy("created_at", "desc").
		Get(&tokens)

	data := map[string]interface{}{
		"user":              user,
		"client":            &client,
		"consent":           &consent,
		"tokens":            tokens,
		"grantedScopes":     consent.GetScopes(),
		"scopeDescriptions": c.getScopeDescriptions(),
	}

	return ctx.Response().View().Make("oauth/security/app-details.tmpl", data)
}

// getScopeDescriptions returns human-readable descriptions for OAuth scopes
func (c *OAuthSecurityController) getScopeDescriptions() map[string]map[string]interface{} {
	return map[string]map[string]interface{}{
		"profile": {
			"title":       "Basic profile information",
			"description": "View your name and profile picture",
			"sensitive":   false,
		},
		"email": {
			"title":       "Email address",
			"description": "View your email address",
			"sensitive":   false,
		},
		"openid": {
			"title":       "Sign you in",
			"description": "Allow this app to sign you in with your account",
			"sensitive":   false,
		},
		"read": {
			"title":       "Read your data",
			"description": "View your account data and content",
			"sensitive":   false,
		},
		"write": {
			"title":       "Modify your data",
			"description": "Create and update content in your account",
			"sensitive":   false,
		},
		"delete": {
			"title":       "Delete your data",
			"description": "Remove your account data and associated information",
			"sensitive":   true,
		},
		"admin": {
			"title":       "Full administrative access",
			"description": "Complete access to all features and data in your account",
			"sensitive":   true,
		},
		"calendar:read": {
			"title":       "View your calendar",
			"description": "See your calendar events and schedule",
			"sensitive":   false,
		},
		"calendar:write": {
			"title":       "Manage your calendar",
			"description": "Create, edit, and delete calendar events",
			"sensitive":   false,
		},
		"chat:read": {
			"title":       "View your messages",
			"description": "Read your chat messages and conversation history",
			"sensitive":   false,
		},
		"chat:write": {
			"title":       "Send messages",
			"description": "Send messages and participate in conversations",
			"sensitive":   false,
		},
		"tasks:read": {
			"title":       "View your tasks",
			"description": "See your tasks, projects, and work assignments",
			"sensitive":   false,
		},
		"tasks:write": {
			"title":       "Manage your tasks",
			"description": "Create, update, and organize your tasks and projects",
			"sensitive":   false,
		},
		"org:read": {
			"title":       "View organization information",
			"description": "See organization details, departments, and team structure",
			"sensitive":   false,
		},
		"org:write": {
			"title":       "Modify organization data",
			"description": "Update organization information and team assignments",
			"sensitive":   false,
		},
		"org:admin": {
			"title":       "Organization administration",
			"description": "Full administrative access to organization settings and members",
			"sensitive":   true,
		},
	}
}
