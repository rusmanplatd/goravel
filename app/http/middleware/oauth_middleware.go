package middleware

import (
	"strings"

	"goravel/app/services"

	"github.com/goravel/framework/contracts/http"
)

type OAuthMiddleware struct {
	oauthService *services.OAuthService
}

func NewOAuthMiddleware() *OAuthMiddleware {
	return &OAuthMiddleware{
		oauthService: services.NewOAuthService(),
	}
}

// Handle validates OAuth2 access tokens
func (m *OAuthMiddleware) Handle(ctx http.Context) http.Response {
	// Get Authorization header
	authHeader := ctx.Request().Header("Authorization", "")
	if authHeader == "" {
		return ctx.Response().Status(401).Json(http.Json{
			"error":             "invalid_request",
			"error_description": "Authorization header required",
		})
	}

	// Check if it's a Bearer token
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return ctx.Response().Status(401).Json(http.Json{
			"error":             "invalid_request",
			"error_description": "Invalid authorization format",
		})
	}

	// Extract token
	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Validate access token
	accessToken, err := m.oauthService.ValidateAccessToken(token)
	if err != nil {
		return ctx.Response().Status(401).Json(http.Json{
			"error":             "invalid_token",
			"error_description": "Invalid access token",
		})
	}

	// Get user from token
	user := accessToken.GetUser()
	if user == nil {
		return ctx.Response().Status(401).Json(http.Json{
			"error":             "invalid_token",
			"error_description": "Token does not have associated user",
		})
	}

	// Check if user is active
	if !user.IsActive {
		return ctx.Response().Status(401).Json(http.Json{
			"error":             "invalid_token",
			"error_description": "User account is deactivated",
		})
	}

	// Add user and token to context
	ctx.WithValue("user", user)
	ctx.WithValue("user_id", user.ID)
	ctx.WithValue("access_token", accessToken)
	ctx.WithValue("scopes", accessToken.GetScopes())

	ctx.Request().Next()
	return nil
}

// RequireScope middleware that requires specific scopes
func (m *OAuthMiddleware) RequireScope(requiredScope string) func(ctx http.Context) http.Response {
	return func(ctx http.Context) http.Response {
		// Get scopes from context (set by OAuth middleware)
		scopesInterface := ctx.Value("scopes")
		if scopesInterface == nil {
			return ctx.Response().Status(403).Json(http.Json{
				"error":             "insufficient_scope",
				"error_description": "Required scope not found in token",
			})
		}

		scopes, ok := scopesInterface.([]string)
		if !ok {
			return ctx.Response().Status(403).Json(http.Json{
				"error":             "insufficient_scope",
				"error_description": "Invalid scope format",
			})
		}

		// Check if required scope is present
		hasScope := false
		for _, scope := range scopes {
			if scope == requiredScope {
				hasScope = true
				break
			}
		}

		if !hasScope {
			return ctx.Response().Status(403).Json(http.Json{
				"error":             "insufficient_scope",
				"error_description": "Required scope not granted",
				"required_scope":    requiredScope,
			})
		}

		ctx.Request().Next()
		return nil
	}
}

// RequireAnyScope middleware that requires any of the specified scopes
func (m *OAuthMiddleware) RequireAnyScope(requiredScopes []string) func(ctx http.Context) http.Response {
	return func(ctx http.Context) http.Response {
		// Get scopes from context (set by OAuth middleware)
		scopesInterface := ctx.Value("scopes")
		if scopesInterface == nil {
			return ctx.Response().Status(403).Json(http.Json{
				"error":             "insufficient_scope",
				"error_description": "Required scope not found in token",
			})
		}

		scopes, ok := scopesInterface.([]string)
		if !ok {
			return ctx.Response().Status(403).Json(http.Json{
				"error":             "insufficient_scope",
				"error_description": "Invalid scope format",
			})
		}

		// Check if any required scope is present
		hasScope := false
		for _, requiredScope := range requiredScopes {
			for _, scope := range scopes {
				if scope == requiredScope {
					hasScope = true
					break
				}
			}
			if hasScope {
				break
			}
		}

		if !hasScope {
			return ctx.Response().Status(403).Json(http.Json{
				"error":             "insufficient_scope",
				"error_description": "Required scope not granted",
				"required_scopes":   requiredScopes,
			})
		}

		ctx.Request().Next()
		return nil
	}
}

// RequireAllScopes middleware that requires all of the specified scopes
func (m *OAuthMiddleware) RequireAllScopes(requiredScopes []string) func(ctx http.Context) http.Response {
	return func(ctx http.Context) http.Response {
		// Get scopes from context (set by OAuth middleware)
		scopesInterface := ctx.Value("scopes")
		if scopesInterface == nil {
			return ctx.Response().Status(403).Json(http.Json{
				"error":             "insufficient_scope",
				"error_description": "Required scope not found in token",
			})
		}

		scopes, ok := scopesInterface.([]string)
		if !ok {
			return ctx.Response().Status(403).Json(http.Json{
				"error":             "insufficient_scope",
				"error_description": "Invalid scope format",
			})
		}

		// Check if all required scopes are present
		for _, requiredScope := range requiredScopes {
			hasScope := false
			for _, scope := range scopes {
				if scope == requiredScope {
					hasScope = true
					break
				}
			}
			if !hasScope {
				return ctx.Response().Status(403).Json(http.Json{
					"error":             "insufficient_scope",
					"error_description": "Required scope not granted",
					"required_scopes":   requiredScopes,
					"missing_scope":     requiredScope,
				})
			}
		}

		ctx.Request().Next()
		return nil
	}
}
