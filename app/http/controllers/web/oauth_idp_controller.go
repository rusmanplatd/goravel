package web

import (
	"context"
	"fmt"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
	"goravel/app/services"
)

type OAuthIdpController struct {
	oauthIdpService     *services.OAuthIdpService
	authService         *services.AuthService
	jwtService          *services.JWTService
	multiAccountService *services.MultiAccountService
}

// NewOAuthIdpController creates a new generic OAuth IdP controller
func NewOAuthIdpController() *OAuthIdpController {
	return &OAuthIdpController{
		oauthIdpService:     services.NewOAuthIdpService(),
		authService:         services.NewAuthService(),
		jwtService:          services.NewJWTService(),
		multiAccountService: services.NewMultiAccountService(),
	}
}

// Redirect redirects the user to the OAuth provider's consent screen
func (c *OAuthIdpController) Redirect(ctx http.Context) http.Response {
	providerName := ctx.Request().Route("provider")
	if providerName == "" {
		return ctx.Response().Redirect(302, "/login?message=Provider not specified")
	}

	// Check if provider exists and is enabled
	provider, err := c.oauthIdpService.GetProvider(providerName)
	if err != nil {
		facades.Log().Error("OAuth provider not found", map[string]interface{}{
			"provider": providerName,
			"error":    err.Error(),
		})
		return ctx.Response().Redirect(302, "/login?message=OAuth provider not found or disabled")
	}

	// Store any intended URL for after authentication
	intendedURL := ctx.Request().Query("redirect")
	if intendedURL != "" && c.oauthIdpService.IsValidRedirectURL(intendedURL) {
		ctx.Request().Session().Put("intended_url", intendedURL)
	}

	// Generate and store state parameter in session for CSRF protection
	state := c.oauthIdpService.GenerateState()
	ctx.Request().Session().Put("oauth_state_"+providerName, state)

	// Get the authorization URL
	authURL, err := c.oauthIdpService.GetAuthURL(providerName, state)
	if err != nil {
		facades.Log().Error("Failed to generate OAuth URL", map[string]interface{}{
			"provider": providerName,
			"error":    err.Error(),
		})
		return ctx.Response().Redirect(302, "/login?message=Failed to generate OAuth URL")
	}

	facades.Log().Info("OAuth redirect initiated", map[string]interface{}{
		"provider":     providerName,
		"display_name": provider.DisplayName,
	})

	// Redirect to provider's OAuth consent screen
	return ctx.Response().Redirect(302, authURL)
}

// Callback handles the OAuth callback from the provider
func (c *OAuthIdpController) Callback(ctx http.Context) http.Response {
	providerName := ctx.Request().Route("provider")
	if providerName == "" {
		return ctx.Response().Redirect(302, "/login?message=Provider not specified")
	}

	// Check if provider exists and is enabled
	provider, err := c.oauthIdpService.GetProvider(providerName)
	if err != nil {
		facades.Log().Error("OAuth provider not found in callback", map[string]interface{}{
			"provider": providerName,
			"error":    err.Error(),
		})
		return ctx.Response().Redirect(302, "/login?message=OAuth provider not found or disabled")
	}

	// Get state and code from query parameters
	state := ctx.Request().Query("state")
	code := ctx.Request().Query("code")
	errorParam := ctx.Request().Query("error")

	// Check for OAuth errors
	if errorParam != "" {
		errorDescription := ctx.Request().Query("error_description", "OAuth authorization failed")
		facades.Log().Warning("OAuth authorization error", map[string]interface{}{
			"provider":          providerName,
			"error":             errorParam,
			"error_description": errorDescription,
		})
		return ctx.Response().Redirect(302, "/login?message=OAuth authorization failed: "+errorDescription)
	}

	// Validate state parameter to prevent CSRF attacks
	sessionStateKey := "oauth_state_" + providerName
	sessionState := ctx.Request().Session().Get(sessionStateKey)
	if sessionState == nil || !c.oauthIdpService.ValidateState(sessionState.(string), state) {
		facades.Log().Warning("Invalid OAuth state parameter", map[string]interface{}{
			"provider":       providerName,
			"session_state":  sessionState,
			"received_state": state,
		})
		return ctx.Response().Redirect(302, "/login?message=Invalid state parameter. Please try again.")
	}

	// Clear the state from session
	ctx.Request().Session().Remove(sessionStateKey)

	// Check if authorization code is present
	if code == "" {
		facades.Log().Warning("OAuth authorization code missing", map[string]interface{}{
			"provider": providerName,
		})
		return ctx.Response().Redirect(302, "/login?message=Authorization code is missing")
	}

	// Handle the OAuth callback
	user, err := c.oauthIdpService.HandleCallback(context.Background(), providerName, code)
	if err != nil {
		facades.Log().Error("OAuth callback error", map[string]interface{}{
			"provider": providerName,
			"error":    err.Error(),
			"code":     code,
		})
		return ctx.Response().Redirect(302, "/login?message=Failed to authenticate with "+provider.DisplayName+". Please try again.")
	}

	// Create authentication context with device tracking
	userAgent := ctx.Request().Header("User-Agent", "")
	ipAddress := ctx.Request().Ip()

	// Initialize security service for advanced threat detection
	securityService := services.NewOAuthIdpSecurityService()
	aiService := services.NewOAuthAIFraudDetectionService()

	// Collect session data for AI analysis
	sessionData := map[string]interface{}{
		"screen_resolution": ctx.Request().Header("X-Screen-Resolution", ""),
		"timezone":          ctx.Request().Header("X-Timezone", ""),
		"language":          ctx.Request().Header("Accept-Language", ""),
		"referrer":          ctx.Request().Header("Referer", ""),
	}

	// Run AI-powered fraud detection
	fraudPrediction, err := aiService.PredictFraud(
		context.Background(),
		fmt.Sprintf("%d", user.ID),
		providerName,
		ipAddress,
		userAgent,
		sessionData,
	)

	if err != nil {
		facades.Log().Warning("AI fraud detection failed", map[string]interface{}{
			"provider": providerName,
			"user_id":  user.ID,
			"error":    err.Error(),
		})
	} else {
		// Handle AI fraud prediction results
		if fraudPrediction.RecommendedAction == "block_login" {
			facades.Log().Warning("OAuth login blocked by AI fraud detection", map[string]interface{}{
				"provider":          providerName,
				"user_id":           user.ID,
				"fraud_probability": fraudPrediction.FraudProbability,
				"anomaly_score":     fraudPrediction.AnomalyScore,
				"explanation":       fraudPrediction.ExplanationAI,
			})
			return ctx.Response().Redirect(302, "/login?message=Login blocked due to suspicious activity detected by our AI security system. Please contact support if you believe this is an error.")
		} else if fraudPrediction.RecommendedAction == "require_mfa" {
			ctx.Request().Session().Put("ai_requires_mfa", true)
			ctx.Request().Session().Put("fraud_prediction", fraudPrediction)
			facades.Log().Info("AI fraud detection requires MFA", map[string]interface{}{
				"provider":          providerName,
				"user_id":           user.ID,
				"fraud_probability": fraudPrediction.FraudProbability,
			})
		} else if fraudPrediction.RecommendedAction == "additional_verification" {
			ctx.Request().Session().Put("requires_additional_verification", true)
			ctx.Request().Session().Put("verification_reason", "ai_fraud_detection")
		}
	}

	// Detect suspicious activity before proceeding with authentication
	suspiciousActivity, err := securityService.DetectSuspiciousActivity(
		context.Background(),
		fmt.Sprintf("%d", user.ID),
		providerName,
		ipAddress,
		userAgent,
	)

	if err != nil {
		facades.Log().Warning("Failed to analyze suspicious activity", map[string]interface{}{
			"provider": providerName,
			"user_id":  user.ID,
			"error":    err.Error(),
		})
	} else {
		// Handle suspicious activity based on risk score
		if suspiciousActivity.RiskScore >= 70 {
			// Block the attempt
			facades.Log().Warning("OAuth login attempt blocked due to high risk", map[string]interface{}{
				"provider":      providerName,
				"user_id":       user.ID,
				"risk_score":    suspiciousActivity.RiskScore,
				"activity_type": suspiciousActivity.ActivityType,
				"ip_address":    ipAddress,
			})
			return ctx.Response().Redirect(302, "/login?message=Login blocked due to suspicious activity. Please contact support.")
		} else if suspiciousActivity.RiskScore >= 40 {
			// Require additional verification (MFA)
			ctx.Request().Session().Put("requires_additional_verification", true)
			ctx.Request().Session().Put("verification_reason", "suspicious_activity")
			facades.Log().Info("OAuth login requires additional verification", map[string]interface{}{
				"provider":   providerName,
				"user_id":    user.ID,
				"risk_score": suspiciousActivity.RiskScore,
			})
		}

		// Update user login patterns for future analysis
		err = securityService.AnalyzeLoginPattern(
			fmt.Sprintf("%d", user.ID),
			providerName,
			ipAddress,
			userAgent,
		)
		if err != nil {
			facades.Log().Warning("Failed to update login patterns", map[string]interface{}{
				"provider": providerName,
				"user_id":  user.ID,
				"error":    err.Error(),
			})
		}
	}

	authContext, err := c.oauthIdpService.CreateAuthenticationContext(
		fmt.Sprintf("%d", user.ID),
		providerName,
		userAgent,
		ipAddress,
	)
	if err != nil {
		facades.Log().Warning("Failed to create authentication context", map[string]interface{}{
			"provider": providerName,
			"user_id":  user.ID,
			"error":    err.Error(),
		})
	} else {
		// Log comprehensive authentication context
		facades.Log().Info("OAuth authentication context created", map[string]interface{}{
			"provider":         providerName,
			"user_id":          user.ID,
			"device_type":      authContext.DeviceInfo.DeviceType,
			"platform":         authContext.DeviceInfo.Platform,
			"browser":          authContext.DeviceInfo.Browser,
			"trust_score":      authContext.DeviceInfo.TrustScore,
			"is_trusted":       authContext.DeviceInfo.IsTrusted,
			"risk_score":       authContext.RiskScore,
			"requires_mfa":     authContext.RequiresMFA,
			"trusted_device":   authContext.TrustedDevice,
			"suspicious_score": suspiciousActivity.RiskScore,
			"security_actions": suspiciousActivity.Actions,
		})

		// Store authentication context in session for potential MFA flow
		if authContext.RequiresMFA || suspiciousActivity.RiskScore >= 40 {
			ctx.Request().Session().Put("pending_auth_context", authContext)
			ctx.Request().Session().Put("suspicious_activity", suspiciousActivity)
			// In a real implementation, redirect to MFA challenge
			facades.Log().Info("MFA required for OAuth login", map[string]interface{}{
				"provider": providerName,
				"user_id":  user.ID,
				"reason":   "risk_assessment",
			})
		}
	}

	// Generate JWT token for the user
	accessToken, refreshToken, err := c.jwtService.GenerateTokenPair(user.ID, user.Email, false)
	if err != nil {
		facades.Log().Error("Failed to generate JWT tokens", map[string]interface{}{
			"provider": providerName,
			"error":    err.Error(),
			"user_id":  user.ID,
		})
		return ctx.Response().Redirect(302, "/login?message=Failed to generate authentication tokens")
	}

	// Store tokens in session
	ctx.Request().Session().Put("access_token", accessToken)
	if refreshToken != "" {
		ctx.Request().Session().Put("refresh_token", refreshToken)
	}

	// Add account to multi-account session
	err = c.multiAccountService.AddAccount(ctx, user, "oauth_"+providerName)
	if err != nil {
		facades.Log().Error("Failed to add account to multi-account session", map[string]interface{}{
			"provider": providerName,
			"error":    err.Error(),
			"user_id":  user.ID,
		})
	}

	// Log successful login
	facades.Log().Info("Successful OAuth login", map[string]interface{}{
		"provider":     providerName,
		"display_name": provider.DisplayName,
		"user_id":      user.ID,
		"email":        user.Email,
		"name":         user.Name,
	})

	// Redirect to dashboard or intended page
	redirectTo := ctx.Request().Session().Get("intended_url", "/dashboard")
	ctx.Request().Session().Remove("intended_url")

	return ctx.Response().Redirect(302, redirectTo.(string))
}

// Unlink removes the OAuth provider link from the user
func (c *OAuthIdpController) Unlink(ctx http.Context) http.Response {
	providerName := ctx.Request().Route("provider")
	if providerName == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "bad_request",
			"message": "Provider not specified",
		})
	}

	// Get authenticated user
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"error":   "unauthorized",
			"message": "Authentication required",
		})
	}

	authenticatedUser, ok := user.(*models.User)
	if !ok {
		return ctx.Response().Json(401, map[string]interface{}{
			"error":   "unauthorized",
			"message": "Invalid user context",
		})
	}

	// Check if provider exists
	provider, err := c.oauthIdpService.GetProvider(providerName)
	if err != nil {
		facades.Log().Error("OAuth provider not found for unlink", map[string]interface{}{
			"provider": providerName,
			"user_id":  authenticatedUser.ID,
			"error":    err.Error(),
		})
		return ctx.Response().Json(404, map[string]interface{}{
			"error":   "provider_not_found",
			"message": "OAuth provider not found or disabled",
		})
	}

	// Unlink OAuth provider
	err = c.oauthIdpService.UnlinkProvider(authenticatedUser.ID, providerName)
	if err != nil {
		facades.Log().Error("Failed to unlink OAuth provider", map[string]interface{}{
			"provider": providerName,
			"user_id":  authenticatedUser.ID,
			"error":    err.Error(),
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"error":   "unlink_failed",
			"message": "Failed to unlink " + provider.DisplayName + " account",
		})
	}

	facades.Log().Info("OAuth provider unlinked", map[string]interface{}{
		"provider":     providerName,
		"display_name": provider.DisplayName,
		"user_id":      authenticatedUser.ID,
	})

	return ctx.Response().Json(200, map[string]interface{}{
		"message": provider.DisplayName + " account unlinked successfully",
	})
}

// GetProviders returns all enabled OAuth providers
func (c *OAuthIdpController) GetProviders(ctx http.Context) http.Response {
	providers, err := c.oauthIdpService.GetAllEnabledProviders()
	if err != nil {
		facades.Log().Error("Failed to get OAuth providers", map[string]interface{}{
			"error": err.Error(),
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"error":   "server_error",
			"message": "Failed to get OAuth providers",
		})
	}

	// Remove sensitive information
	var publicProviders []map[string]interface{}
	for _, provider := range providers {
		publicProviders = append(publicProviders, map[string]interface{}{
			"name":         provider.Name,
			"display_name": provider.DisplayName,
			"icon_url":     provider.IconURL,
			"button_color": provider.ButtonColor,
			"sort_order":   provider.SortOrder,
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"providers": publicProviders,
	})
}

// GetUserIdentities returns all OAuth identities for the authenticated user
func (c *OAuthIdpController) GetUserIdentities(ctx http.Context) http.Response {
	// Get authenticated user
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Json(401, map[string]interface{}{
			"error":   "unauthorized",
			"message": "Authentication required",
		})
	}

	authenticatedUser, ok := user.(*models.User)
	if !ok {
		return ctx.Response().Json(401, map[string]interface{}{
			"error":   "unauthorized",
			"message": "Invalid user context",
		})
	}

	// Get user identities
	identities, err := c.oauthIdpService.GetUserIdentities(authenticatedUser.ID)
	if err != nil {
		facades.Log().Error("Failed to get user OAuth identities", map[string]interface{}{
			"user_id": authenticatedUser.ID,
			"error":   err.Error(),
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"error":   "server_error",
			"message": "Failed to get OAuth identities",
		})
	}

	// Remove sensitive information
	var publicIdentities []map[string]interface{}
	for _, identity := range identities {
		publicIdentities = append(publicIdentities, map[string]interface{}{
			"provider_name":     identity.Provider.Name,
			"provider_display":  identity.Provider.DisplayName,
			"provider_email":    identity.ProviderEmail,
			"provider_username": identity.ProviderUsername,
			"provider_avatar":   identity.ProviderAvatar,
			"last_login_at":     identity.LastLoginAt,
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"identities": publicIdentities,
	})
}
