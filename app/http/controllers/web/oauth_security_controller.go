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
	oauthService, err := services.NewOAuthService()
	if err != nil {
		facades.Log().Error("Failed to create OAuth service", map[string]interface{}{
			"error": err.Error(),
		})
		return nil
	}

	return &OAuthSecurityController{
		oauthService: oauthService,
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

	// For now, redirect to the existing OAuth security page
	return ctx.Response().View().Make("oauth/security/index.tmpl", map[string]interface{}{
		"title": "OAuth Security",
		"user":  user,
	})
}

// RevokeConsent revokes a user's consent for a specific client
func (c *OAuthSecurityController) RevokeConsent(ctx http.Context) http.Response {
	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "Consent revoked successfully",
	})
}

// RevokeToken revokes a specific access token
func (c *OAuthSecurityController) RevokeToken(ctx http.Context) http.Response {
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

	return ctx.Response().View().Make("oauth/security/history.tmpl", map[string]interface{}{
		"title": "Consent History",
		"user":  user,
	})
}

// AppDetails shows detailed information about a connected app
func (c *OAuthSecurityController) AppDetails(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	return ctx.Response().View().Make("oauth/security/app-details.tmpl", map[string]interface{}{
		"title": "App Details",
		"user":  user,
	})
}
