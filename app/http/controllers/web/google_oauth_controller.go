package web

import (
	"context"
	"net/url"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
	"goravel/app/services"
)

type GoogleOAuthController struct {
	googleOAuthService  *services.GoogleOAuthService
	authService         *services.AuthService
	jwtService          *services.JWTService
	multiAccountService *services.MultiAccountService
}

// NewGoogleOAuthController creates a new Google OAuth controller
func NewGoogleOAuthController() *GoogleOAuthController {
	return &GoogleOAuthController{
		googleOAuthService:  services.NewGoogleOAuthService(),
		authService:         services.NewAuthService(),
		jwtService:          services.NewJWTService(),
		multiAccountService: services.NewMultiAccountService(),
	}
}

// Redirect redirects the user to Google's OAuth consent screen
func (c *GoogleOAuthController) Redirect(ctx http.Context) http.Response {
	// Check if Google OAuth is enabled
	if !c.googleOAuthService.IsEnabled() {
		return ctx.Response().Redirect(302, "/login?message=Google OAuth is not enabled")
	}

	// Store any intended URL for after authentication
	intendedURL := ctx.Request().Query("redirect")
	if intendedURL != "" && c.isValidRedirectURL(intendedURL) {
		ctx.Request().Session().Put("intended_url", intendedURL)
	}

	// Generate and store state parameter in session for CSRF protection
	state := c.googleOAuthService.GenerateState()
	ctx.Request().Session().Put("google_oauth_state", state)

	// Get the authorization URL
	authURL := c.googleOAuthService.GetAuthURL(state)

	// Redirect to Google's OAuth consent screen
	return ctx.Response().Redirect(302, authURL)
}

// Callback handles the OAuth callback from Google
func (c *GoogleOAuthController) Callback(ctx http.Context) http.Response {
	// Check if Google OAuth is enabled
	if !c.googleOAuthService.IsEnabled() {
		return ctx.Response().Redirect(302, "/login?message=Google OAuth is not enabled")
	}

	// Get state and code from query parameters
	state := ctx.Request().Query("state")
	code := ctx.Request().Query("code")
	errorParam := ctx.Request().Query("error")

	// Check for OAuth errors
	if errorParam != "" {
		errorDescription := ctx.Request().Query("error_description", "OAuth authorization failed")
		return ctx.Response().Redirect(302, "/login?message=OAuth authorization failed: "+errorDescription)
	}

	// Validate state parameter to prevent CSRF attacks
	sessionState := ctx.Request().Session().Get("google_oauth_state")
	if sessionState == nil || !c.googleOAuthService.ValidateState(sessionState.(string), state) {
		return ctx.Response().Redirect(302, "/login?message=Invalid state parameter. Please try again.")
	}

	// Clear the state from session
	ctx.Request().Session().Remove("google_oauth_state")

	// Check if authorization code is present
	if code == "" {
		return ctx.Response().Redirect(302, "/login?message=Authorization code is missing")
	}

	// Handle the OAuth callback
	user, err := c.googleOAuthService.HandleCallback(context.Background(), code)
	if err != nil {
		facades.Log().Error("Google OAuth callback error", map[string]interface{}{
			"error": err.Error(),
			"code":  code,
		})
		return ctx.Response().Redirect(302, "/login?message=Failed to authenticate with Google. Please try again.")
	}

	// Generate JWT token for the user
	accessToken, refreshToken, err := c.jwtService.GenerateTokenPair(user.ID, user.Email, false)
	if err != nil {
		facades.Log().Error("Failed to generate JWT tokens", map[string]interface{}{
			"error":   err.Error(),
			"user_id": user.ID,
		})
		return ctx.Response().Redirect(302, "/login?message=Failed to generate authentication tokens")
	}

	// Store tokens in session or cookies
	ctx.Request().Session().Put("access_token", accessToken)
	if refreshToken != "" {
		ctx.Request().Session().Put("refresh_token", refreshToken)
	}

	// Add account to multi-account session
	err = c.multiAccountService.AddAccount(ctx, user, "google_oauth")
	if err != nil {
		facades.Log().Error("Failed to add account to multi-account session", map[string]interface{}{
			"error":   err.Error(),
			"user_id": user.ID,
		})
	}

	// Set session data for web authentication (backward compatibility)
	ctx.Request().Session().Put("user_id", user.ID)
	ctx.Request().Session().Put("user_email", user.Email)

	// Log successful login
	facades.Log().Info("Successful Google OAuth login", map[string]interface{}{
		"user_id": user.ID,
		"email":   user.Email,
		"name":    user.Name,
	})

	// Redirect to dashboard or intended page
	redirectTo := ctx.Request().Session().Get("intended_url", "/dashboard")
	ctx.Request().Session().Remove("intended_url")

	return ctx.Response().Redirect(302, redirectTo.(string))
}

// Unlink removes the Google account link from the user
func (c *GoogleOAuthController) Unlink(ctx http.Context) http.Response {
	// Get authenticated user
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"error":   "unauthorized",
			"message": "Authentication required",
		})
	}

	authenticatedUser := user.(*models.User)

	// Unlink Google account
	err := c.googleOAuthService.UnlinkGoogleAccount(authenticatedUser.ID)
	if err != nil {
		facades.Log().Error("Failed to unlink Google account", map[string]interface{}{
			"error":   err.Error(),
			"user_id": authenticatedUser.ID,
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"error":   "unlink_failed",
			"message": "Failed to unlink Google account",
		})
	}

	facades.Log().Info("Google account unlinked", map[string]interface{}{
		"user_id": authenticatedUser.ID,
	})

	return ctx.Response().Json(200, map[string]interface{}{
		"message": "Google account unlinked successfully",
	})
}

// isValidRedirectURL validates redirect URLs to prevent open redirect attacks
func (c *GoogleOAuthController) isValidRedirectURL(redirectURL string) bool {
	if redirectURL == "" {
		return false
	}

	// Parse the URL
	parsedURL, err := url.Parse(redirectURL)
	if err != nil {
		return false
	}

	// Allow relative URLs (same domain)
	if parsedURL.Host == "" {
		return true
	}

	// Get allowed hosts from config
	allowedHosts := facades.Config().Get("auth.allowed_redirect_hosts", []string{}).([]string)

	// Check if host is in allowed list
	for _, allowedHost := range allowedHosts {
		if parsedURL.Host == allowedHost {
			return true
		}
	}

	// Allow same host as current request
	// Note: You might want to implement this based on your specific needs
	return false
}
