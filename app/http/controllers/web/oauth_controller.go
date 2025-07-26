package web

import (
	"fmt"
	"net/url"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
	"goravel/app/services"
)

type OAuthController struct {
	oauthService *services.OAuthService
	authService  *services.AuthService
}

// NewOAuthController creates a new web OAuth controller
func NewOAuthController() *OAuthController {
	return &OAuthController{
		oauthService: services.NewOAuthService(),
		authService:  services.NewAuthService(),
	}
}

// ScopeInfo represents a scope with human-readable information
type ScopeInfo struct {
	Name        string
	Title       string
	Description string
	Sensitive   bool
}

// GetScopeInfoMap returns a map of scopes with their human-readable information
func (c *OAuthController) GetScopeInfoMap() map[string]ScopeInfo {
	return map[string]ScopeInfo{
		// Basic profile scopes
		"profile": {
			Name:        "profile",
			Title:       "View your basic profile information",
			Description: "See your name, profile picture, and basic account information",
			Sensitive:   false,
		},
		"email": {
			Name:        "email",
			Title:       "View your email address",
			Description: "See your primary email address",
			Sensitive:   false,
		},
		"openid": {
			Name:        "openid",
			Title:       "Sign you in",
			Description: "Allow this app to sign you in with your account",
			Sensitive:   false,
		},

		// User management scopes
		"user:read": {
			Name:        "user:read",
			Title:       "View user information",
			Description: "Access to read user profiles and basic information",
			Sensitive:   false,
		},
		"user:write": {
			Name:        "user:write",
			Title:       "Modify user information",
			Description: "Ability to update user profiles and information",
			Sensitive:   false,
		},
		"user:delete": {
			Name:        "user:delete",
			Title:       "Delete user accounts",
			Description: "Permission to remove user accounts and their data",
			Sensitive:   true,
		},

		// Application scopes
		"read": {
			Name:        "read",
			Title:       "View your data",
			Description: "Read access to your account data and content",
			Sensitive:   false,
		},
		"write": {
			Name:        "write",
			Title:       "Modify your data",
			Description: "Create and update content in your account",
			Sensitive:   false,
		},
		"delete": {
			Name:        "delete",
			Title:       "Delete your data",
			Description: "Remove your account data and associated information",
			Sensitive:   true,
		},
		"admin": {
			Name:        "admin",
			Title:       "Full administrative access",
			Description: "Complete access to all features and data in your account",
			Sensitive:   true,
		},

		// Calendar scopes
		"calendar:read": {
			Name:        "calendar:read",
			Title:       "View your calendar",
			Description: "See your calendar events and schedule",
			Sensitive:   false,
		},
		"calendar:write": {
			Name:        "calendar:write",
			Title:       "Manage your calendar",
			Description: "Create, edit, and delete calendar events",
			Sensitive:   false,
		},
		"calendar:events": {
			Name:        "calendar:events",
			Title:       "Access calendar events",
			Description: "View and manage all your calendar events and meetings",
			Sensitive:   false,
		},

		// Chat scopes
		"chat:read": {
			Name:        "chat:read",
			Title:       "View your messages",
			Description: "Read your chat messages and conversation history",
			Sensitive:   false,
		},
		"chat:write": {
			Name:        "chat:write",
			Title:       "Send messages",
			Description: "Send messages and participate in conversations",
			Sensitive:   false,
		},
		"chat:rooms": {
			Name:        "chat:rooms",
			Title:       "Manage chat rooms",
			Description: "Create, join, and manage chat rooms and channels",
			Sensitive:   false,
		},

		// Task management scopes
		"tasks:read": {
			Name:        "tasks:read",
			Title:       "View your tasks",
			Description: "See your tasks, projects, and work assignments",
			Sensitive:   false,
		},
		"tasks:write": {
			Name:        "tasks:write",
			Title:       "Manage your tasks",
			Description: "Create, update, and organize your tasks and projects",
			Sensitive:   false,
		},
		"tasks:manage": {
			Name:        "tasks:manage",
			Title:       "Full task management",
			Description: "Complete control over tasks, projects, and team assignments",
			Sensitive:   false,
		},

		// Organization scopes
		"org:read": {
			Name:        "org:read",
			Title:       "View organization information",
			Description: "See organization details, departments, and team structure",
			Sensitive:   false,
		},
		"org:write": {
			Name:        "org:write",
			Title:       "Modify organization data",
			Description: "Update organization information and team assignments",
			Sensitive:   false,
		},
		"org:admin": {
			Name:        "org:admin",
			Title:       "Organization administration",
			Description: "Full administrative access to organization settings and members",
			Sensitive:   true,
		},
	}
}

// ShowAuthorize displays the OAuth authorization/consent screen
func (c *OAuthController) ShowAuthorize(ctx http.Context) http.Response {
	// Get query parameters
	clientID := ctx.Request().Query("client_id")
	redirectURI := ctx.Request().Query("redirect_uri")
	responseType := ctx.Request().Query("response_type", "code")
	scope := ctx.Request().Query("scope")
	state := ctx.Request().Query("state")
	codeChallenge := ctx.Request().Query("code_challenge")
	codeChallengeMethod := ctx.Request().Query("code_challenge_method")

	// Validate required parameters
	if clientID == "" {
		return c.redirectWithError(ctx, redirectURI, "invalid_request", "Missing client_id parameter", state)
	}

	if redirectURI == "" {
		return ctx.Response().View().Make("oauth/error.tmpl", map[string]interface{}{
			"title":       "OAuth Error",
			"error":       "invalid_request",
			"description": "Missing redirect_uri parameter",
		})
	}

	// Validate client
	client, err := c.oauthService.GetClient(clientID)
	if err != nil {
		return c.redirectWithError(ctx, redirectURI, "invalid_client", "Invalid client_id", state)
	}

	if client.IsRevoked() {
		return c.redirectWithError(ctx, redirectURI, "invalid_client", "Client is revoked", state)
	}

	// Validate redirect URI
	if !c.validateRedirectURI(client, redirectURI) {
		return ctx.Response().View().Make("oauth/error.tmpl", map[string]interface{}{
			"title":       "OAuth Error",
			"error":       "invalid_request",
			"description": "Invalid redirect_uri",
		})
	}

	// Validate response type
	if responseType != "code" {
		return c.redirectWithError(ctx, redirectURI, "unsupported_response_type", "Only authorization code flow is supported", state)
	}

	// Check if user is authenticated
	user := ctx.Value("user")
	if user == nil {
		// Redirect to login with return URL
		loginURL := fmt.Sprintf("/login?return_url=%s", url.QueryEscape(ctx.Request().FullUrl()))
		return ctx.Response().Redirect(302, loginURL)
	}

	authenticatedUser, ok := user.(*models.User)
	if !ok {
		return c.redirectWithError(ctx, redirectURI, "server_error", "Invalid user context", state)
	}

	// Parse and validate scopes
	requestedScopes := c.oauthService.ParseScopes(scope)
	if len(requestedScopes) == 0 {
		requestedScopes = facades.Config().Get("oauth.default_scopes").([]string)
	}

	if !c.oauthService.ValidateScopes(requestedScopes) {
		return c.redirectWithError(ctx, redirectURI, "invalid_scope", "One or more requested scopes are not allowed", state)
	}

	// Prepare scope information for display
	scopeInfoMap := c.GetScopeInfoMap()
	var scopeInfos []ScopeInfo
	hasSensitiveScopes := false

	for _, scopeName := range requestedScopes {
		if info, exists := scopeInfoMap[scopeName]; exists {
			scopeInfos = append(scopeInfos, info)
			if info.Sensitive {
				hasSensitiveScopes = true
			}
		} else {
			// Unknown scope, create basic info
			scopeInfos = append(scopeInfos, ScopeInfo{
				Name:        scopeName,
				Title:       fmt.Sprintf("Access %s", scopeName),
				Description: fmt.Sprintf("Permission to access %s resources", scopeName),
				Sensitive:   false,
			})
		}
	}

	// Load client user relationship
	var clientUser *models.User
	if client.UserID != nil {
		facades.Orm().Query().Where("id", *client.UserID).First(&clientUser)
		client.User = clientUser
	}

	return ctx.Response().View().Make("oauth/authorize.tmpl", map[string]interface{}{
		"title":                 "Authorize Application",
		"user":                  authenticatedUser,
		"client":                client,
		"scopes":                scopeInfos,
		"hasSensitiveScopes":    hasSensitiveScopes,
		"client_id":             clientID,
		"redirect_uri":          redirectURI,
		"response_type":         responseType,
		"scope":                 scope,
		"state":                 state,
		"code_challenge":        codeChallenge,
		"code_challenge_method": codeChallengeMethod,
	})
}

// HandleAuthorize processes the OAuth authorization request
func (c *OAuthController) HandleAuthorize(ctx http.Context) http.Response {
	// Get form data
	clientID := ctx.Request().Input("client_id")
	redirectURI := ctx.Request().Input("redirect_uri")
	scope := ctx.Request().Input("scope")
	state := ctx.Request().Input("state")
	codeChallenge := ctx.Request().Input("code_challenge")
	codeChallengeMethod := ctx.Request().Input("code_challenge_method")
	authorized := ctx.Request().Input("authorized") == "true"

	// Validate client
	client, err := c.oauthService.GetClient(clientID)
	if err != nil {
		return c.redirectWithError(ctx, redirectURI, "invalid_client", "Invalid client_id", state)
	}

	// Validate redirect URI
	if !c.validateRedirectURI(client, redirectURI) {
		return ctx.Response().View().Make("oauth/error.tmpl", map[string]interface{}{
			"title":       "OAuth Error",
			"error":       "invalid_request",
			"description": "Invalid redirect_uri",
		})
	}

	// Check if user denied authorization
	if !authorized {
		return c.redirectWithError(ctx, redirectURI, "access_denied", "User denied the request", state)
	}

	// Get authenticated user
	user := ctx.Value("user")
	if user == nil {
		return c.redirectWithError(ctx, redirectURI, "access_denied", "User not authenticated", state)
	}

	authenticatedUser, ok := user.(*models.User)
	if !ok {
		return c.redirectWithError(ctx, redirectURI, "server_error", "Invalid user context", state)
	}

	// Parse scopes
	requestedScopes := c.oauthService.ParseScopes(scope)
	if len(requestedScopes) == 0 {
		requestedScopes = facades.Config().Get("oauth.default_scopes").([]string)
	}

	// Validate scopes
	if !c.oauthService.ValidateScopes(requestedScopes) {
		return c.redirectWithError(ctx, redirectURI, "invalid_scope", "One or more requested scopes are not allowed", state)
	}

	// Create authorization code
	var authCode *models.OAuthAuthCode
	expiresAt := time.Now().Add(time.Duration(facades.Config().GetInt("oauth.auth_code_ttl", 10)) * time.Minute)

	if codeChallenge != "" && codeChallengeMethod != "" {
		// Validate PKCE parameters
		if codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
			return c.redirectWithError(ctx, redirectURI, "invalid_request", "Invalid code_challenge_method", state)
		}

		authCode, err = c.oauthService.CreateAuthCodeWithPKCE(
			authenticatedUser.ID,
			client.ID,
			requestedScopes,
			expiresAt,
			codeChallenge,
			codeChallengeMethod,
		)
	} else {
		authCode, err = c.oauthService.CreateAuthCode(
			authenticatedUser.ID,
			client.ID,
			requestedScopes,
			expiresAt,
		)
	}

	if err != nil {
		return c.redirectWithError(ctx, redirectURI, "server_error", "Failed to create authorization code", state)
	}

	// Log OAuth event
	c.oauthService.LogOAuthEvent("authorization_granted", client.ID, authenticatedUser.ID, map[string]interface{}{
		"scopes":       requestedScopes,
		"redirect_uri": redirectURI,
	})

	// Build redirect URL with authorization code
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		return c.redirectWithError(ctx, redirectURI, "server_error", "Invalid redirect URI format", state)
	}

	query := redirectURL.Query()
	query.Set("code", authCode.ID)
	if state != "" {
		query.Set("state", state)
	}
	redirectURL.RawQuery = query.Encode()

	return ctx.Response().Redirect(302, redirectURL.String())
}

// validateRedirectURI validates if the redirect URI matches the client's registered URIs
func (c *OAuthController) validateRedirectURI(client *models.OAuthClient, redirectURI string) bool {
	if !facades.Config().GetBool("oauth.enable_redirect_uri_validation", true) {
		return true
	}

	registeredURIs := client.GetRedirectURIs()
	if len(registeredURIs) == 0 {
		return false
	}

	for _, registeredURI := range registeredURIs {
		if registeredURI == redirectURI {
			return true
		}
	}

	return false
}

// redirectWithError creates an error redirect response
func (c *OAuthController) redirectWithError(ctx http.Context, redirectURI, errorCode, errorDescription, state string) http.Response {
	if redirectURI == "" {
		return ctx.Response().View().Make("oauth/error.tmpl", map[string]interface{}{
			"title":       "OAuth Error",
			"error":       errorCode,
			"description": errorDescription,
		})
	}

	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		return ctx.Response().View().Make("oauth/error.tmpl", map[string]interface{}{
			"title":       "OAuth Error",
			"error":       "invalid_request",
			"description": "Invalid redirect_uri format",
		})
	}

	query := redirectURL.Query()
	query.Set("error", errorCode)
	query.Set("error_description", errorDescription)
	if state != "" {
		query.Set("state", state)
	}
	redirectURL.RawQuery = query.Encode()

	return ctx.Response().Redirect(302, redirectURL.String())
}
