package v1

import (
	"fmt"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
)

type OAuthController struct {
	oauthService              *services.OAuthService
	authService               *services.AuthService
	consentService            *services.OAuthConsentService
	analyticsService          *services.OAuthAnalyticsService
	riskService               *services.OAuthRiskService
	attestationService        *services.OAuthClientAttestationService
	tokenBindingService       *services.OAuthTokenBindingService
	resourceIndicatorsService *services.OAuthResourceIndicatorsService
}

// NewOAuthController creates a new OAuth2 controller
func NewOAuthController() *OAuthController {
	oauthService, err := services.NewOAuthService()
	if err != nil {
		facades.Log().Error("Failed to create OAuth service", map[string]interface{}{
			"error": err.Error(),
		})
		return nil
	}

	authService, err := services.NewAuthService()
	if err != nil {
		facades.Log().Error("Failed to create auth service", map[string]interface{}{
			"error": err.Error(),
		})
		return nil
	}

	attestationService, err := services.NewOAuthClientAttestationService()
	if err != nil {
		facades.Log().Error("Failed to create OAuth client attestation service", map[string]interface{}{
			"error": err.Error(),
		})
		return nil
	}

	return &OAuthController{
		oauthService:              oauthService,
		authService:               authService,
		consentService:            services.NewOAuthConsentService(),
		analyticsService:          services.NewOAuthAnalyticsService(),
		riskService:               services.NewOAuthRiskService(),
		attestationService:        attestationService,
		tokenBindingService:       services.NewOAuthTokenBindingService(),
		resourceIndicatorsService: services.NewOAuthResourceIndicatorsService(),
	}
}

// CreateClient creates a new OAuth2 client
// @Summary Create OAuth2 client
// @Description Create a new OAuth2 client
// @Tags OAuth2
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body requests.OAuthClientRequest true "Client data"
// @Success 201 {object} responses.ApiResponse{data=models.OAuthClient}
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /oauth/clients [post]
func (c *OAuthController) CreateClient(ctx http.Context) http.Response {
	var req requests.OAuthClientRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// Get authenticated user
	_ = ctx.Value("user").(*models.User)

	client, err := c.oauthService.CreateClient(
		req.Name,
		req.UserID,
		req.RedirectURIs,
		req.PersonalAccessClient,
		req.PasswordClient,
	)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to create client", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Client created successfully", client)
}

// GetClients gets all OAuth2 clients for the authenticated user
// @Summary Get OAuth2 clients
// @Description Get all OAuth2 clients for the authenticated user
// @Tags OAuth2
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} responses.ApiResponse{data=[]models.OAuthClient}
// @Failure 401 {object} responses.ApiResponse
// @Router /oauth/clients [get]
func (c *OAuthController) GetClients(ctx http.Context) http.Response {
	// Get authenticated user
	user := ctx.Value("user").(*models.User)

	var clients []models.OAuthClient
	err := facades.Orm().Query().Where("user_id", user.ID).Find(&clients)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to retrieve clients", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Clients retrieved successfully", clients)
}

// GetClient gets a specific OAuth2 client
// @Summary Get OAuth2 client
// @Description Get a specific OAuth2 client by ID
// @Tags OAuth2
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Client ID"
// @Success 200 {object} responses.ApiResponse{data=models.OAuthClient}
// @Failure 401 {object} responses.ApiResponse
// @Failure 404 {object} responses.ApiResponse
// @Router /oauth/clients/{id} [get]
func (c *OAuthController) GetClient(ctx http.Context) http.Response {
	clientID := ctx.Request().Route("id")

	client, err := c.oauthService.GetClient(clientID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Client not found", err.Error(), 404)
	}

	return responses.SuccessResponse(ctx, "Client retrieved successfully", client)
}

// UpdateClient updates an OAuth2 client
// @Summary Update OAuth2 client
// @Description Update an OAuth2 client
// @Tags OAuth2
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Client ID"
// @Param request body requests.OAuthClientUpdateRequest true "Client update data"
// @Success 200 {object} responses.ApiResponse{data=models.OAuthClient}
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Failure 404 {object} responses.ApiResponse
// @Router /oauth/clients/{id} [put]
func (c *OAuthController) UpdateClient(ctx http.Context) http.Response {
	clientID := ctx.Request().Route("id")

	var req requests.OAuthClientUpdateRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	client, err := c.oauthService.GetClient(clientID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Client not found", err.Error(), 404)
	}

	client.Name = req.Name
	client.SetRedirectURIs(req.RedirectURIs)

	err = facades.Orm().Query().Save(client)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to update client", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Client updated successfully", client)
}

// DeleteClient deletes an OAuth2 client
// @Summary Delete OAuth2 client
// @Description Delete an OAuth2 client
// @Tags OAuth2
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Client ID"
// @Success 200 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Failure 404 {object} responses.ApiResponse
// @Router /oauth/clients/{id} [delete]
func (c *OAuthController) DeleteClient(ctx http.Context) http.Response {
	clientID := ctx.Request().Route("id")

	client, err := c.oauthService.GetClient(clientID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Client not found", err.Error(), 404)
	}

	// Revoke the client
	err = client.Revoke()
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to delete client", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Client deleted successfully", nil)
}

// Token handles OAuth2 token requests
// @Summary OAuth2 token endpoint
// @Description Handle OAuth2 token requests for various grant types
// @Tags OAuth2
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param grant_type formData string true "Grant type"
// @Param client_id formData string false "Client ID"
// @Param client_secret formData string false "Client secret"
// @Param client_assertion formData string false "Client attestation JWT for mobile apps"
// @Param client_assertion_type formData string false "Client assertion type"
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /oauth/token [post]
func (c *OAuthController) Token(ctx http.Context) http.Response {
	var req requests.OAuthTokenRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// Handle client attestation for mobile apps (Google-like)
	if req.ClientAssertionType == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" && req.ClientAssertion != "" {
		// Validate client attestation
		attestationResult, err := c.attestationService.ValidateClientAttestation(req.ClientAssertion, req.ClientID)
		if err != nil {
			facades.Log().Warning("Client attestation validation failed", map[string]interface{}{
				"client_id": req.ClientID,
				"error":     err.Error(),
			})

			// Check if attestation is required
			if c.attestationService.IsClientAttestationRequired(req.ClientID) {
				return responses.CreateErrorResponse(ctx, "Client attestation required", "Valid client attestation is required for this client", 401)
			}
		} else {
			// Log successful attestation
			facades.Log().Info("Client attestation validated", map[string]interface{}{
				"client_id":        req.ClientID,
				"trust_level":      attestationResult.TrustLevel,
				"attestation_type": attestationResult.AttestationType,
			})

			// Handle low trust scenarios
			if attestationResult.TrustLevel == "UNTRUSTED" || attestationResult.TrustLevel == "LOW" {
				return responses.CreateErrorResponse(ctx, "Client attestation failed", "Client attestation indicates security concerns", 403)
			}
		}
	} else if c.attestationService.IsClientAttestationRequired(req.ClientID) {
		// Client attestation is required but not provided
		return responses.CreateErrorResponse(ctx, "Client attestation required", "This client requires valid attestation", 401)
	}

	var accessToken *models.OAuthAccessToken
	var refreshToken *models.OAuthRefreshToken
	var err error

	// Handle different grant types
	switch req.GrantType {
	case "password":
		accessToken, refreshToken, err = c.handlePasswordGrant(&req)
	case "client_credentials":
		accessToken, refreshToken, err = c.handleClientCredentialsGrant(&req)
	case "authorization_code":
		accessToken, refreshToken, err = c.handleAuthorizationCodeGrant(&req)
	case "urn:ietf:params:oauth:grant-type:device_code":
		accessToken, refreshToken, err = c.handleDeviceCodeGrant(&req)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		accessToken, refreshToken, err = c.handleTokenExchangeGrant(&req)
	case "refresh_token":
		accessToken, refreshToken, err = c.handleRefreshTokenGrant(&req)
	default:
		return responses.CreateErrorResponse(ctx, "Unsupported grant type", "Invalid grant_type", 400)
	}

	if err != nil {
		return responses.CreateErrorResponse(ctx, "Token generation failed", err.Error(), 401)
	}

	// Parse scopes
	scopes := c.oauthService.ParseScopes(req.Scope)
	if len(scopes) == 0 {
		scopes = facades.Config().Get("oauth.default_scopes").([]string)
	}

	// Prepare token response
	response := map[string]interface{}{
		"access_token":  accessToken.ID,
		"token_type":    "Bearer",
		"expires_in":    facades.Config().GetInt("oauth.access_token_ttl", 60) * 60, // Convert to seconds
		"scope":         c.oauthService.FormatScopes(scopes),
		"refresh_token": refreshToken.ID,
	}

	// Generate ID token for OpenID Connect if openid scope is requested
	if c.oauthService.HasScope(scopes, "openid") && accessToken.UserID != nil {
		idToken, err := c.oauthService.CreateIDToken(*accessToken.UserID, accessToken.ClientID, scopes, nil, nil)
		if err != nil {
			facades.Log().Warning("Failed to generate ID token", map[string]interface{}{
				"error":     err.Error(),
				"user_id":   *accessToken.UserID,
				"client_id": accessToken.ClientID,
			})
		} else {
			response["id_token"] = idToken
		}
	}

	return responses.SuccessResponse(ctx, "Token generated successfully", response)
}

// Authorize handles OAuth2 authorization requests
// @Summary OAuth2 authorization endpoint
// @Description Handle OAuth2 authorization requests
// @Tags OAuth2
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body requests.OAuthAuthorizationRequest true "Authorization request data"
// @Success 200 {object} responses.ApiResponse
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /oauth/authorize [post]
func (c *OAuthController) Authorize(ctx http.Context) http.Response {
	var req requests.OAuthAuthorizationRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// Validate client
	client, err := c.oauthService.GetClient(req.ClientID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid client", err.Error(), 400)
	}

	// Validate redirect URI
	if !c.validateRedirectURI(client, req.RedirectURI) {
		return responses.CreateErrorResponse(ctx, "Invalid redirect URI", "Redirect URI does not match client configuration", 400)
	}

	// Google-like PKCE enforcement for public clients
	if err := c.oauthService.ValidatePKCEForClient(client, req.CodeChallenge, req.CodeChallengeMethod); err != nil {
		return responses.CreateErrorResponse(ctx, "PKCE validation failed", err.Error(), 400)
	}

	// Parse scopes
	scopes := c.oauthService.ParseScopes(req.Scope)
	if len(scopes) == 0 {
		scopes = facades.Config().Get("oauth.default_scopes").([]string)
	}

	// Validate scopes
	if !c.oauthService.ValidateScopes(scopes) {
		return responses.CreateErrorResponse(ctx, "Invalid scopes", "One or more requested scopes are not allowed", 400)
	}

	// Get authenticated user
	user := ctx.Value("user").(*models.User)

	// Perform Google-like risk assessment
	authContext := &services.AuthContext{
		UserID:        user.ID,
		ClientID:      client.ID,
		IPAddress:     ctx.Request().Ip(),
		UserAgent:     ctx.Request().Header("User-Agent", ""),
		Scopes:        scopes,
		GrantType:     "authorization_code",
		Timestamp:     time.Now(),
		RefererURL:    ctx.Request().Header("Referer", ""),
		RequestOrigin: ctx.Request().Header("Origin", ""),
	}

	riskAssessment, err := c.riskService.AssessRisk(authContext)
	if err != nil {
		facades.Log().Warning("Risk assessment failed", map[string]interface{}{
			"error":     err.Error(),
			"user_id":   user.ID,
			"client_id": client.ID,
		})
		// Continue with authorization even if risk assessment fails
	} else {
		// Handle high-risk scenarios
		if riskAssessment.BlockAccess {
			return responses.CreateErrorResponse(ctx, "Access denied", "Authorization blocked due to security concerns", 403)
		}

		// Log risk assessment results
		facades.Log().Info("Authorization risk assessment", map[string]interface{}{
			"user_id":      user.ID,
			"client_id":    client.ID,
			"risk_score":   riskAssessment.Score,
			"risk_level":   riskAssessment.Level,
			"risk_factors": riskAssessment.Factors,
			"require_mfa":  riskAssessment.RequireMFA,
		})

		// In a real implementation, you would check MFA status here
		// if riskAssessment.RequireMFA && !user.HasValidMFA() {
		//     return responses.CreateErrorResponse(ctx, "MFA required", "Multi-factor authentication is required", 401)
		// }
	}

	// Create authorization code with PKCE support if provided
	var authCode *models.OAuthAuthCode
	expiresAt := time.Now().Add(time.Duration(facades.Config().GetInt("oauth.auth_code_ttl", 10)) * time.Minute)

	if req.CodeChallenge != "" && req.CodeChallengeMethod != "" {
		authCode, err = c.oauthService.CreateAuthCodeWithPKCE(user.ID, client.ID, scopes, expiresAt, req.CodeChallenge, req.CodeChallengeMethod)
	} else {
		// For backward compatibility, but this should be rare now with PKCE enforcement
		authCode, err = c.oauthService.CreateAuthCode(user.ID, client.ID, scopes, expiresAt)
	}

	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to create authorization code", err.Error(), 500)
	}

	// Build redirect URL
	redirectURL := fmt.Sprintf("%s?code=%s&state=%s", req.RedirectURI, authCode.ID, req.State)

	response := map[string]interface{}{
		"redirect_uri": redirectURL,
		"code":         authCode.ID,
		"state":        req.State,
		"expires_in":   facades.Config().GetInt("oauth.auth_code_ttl", 10) * 60, // Convert to seconds
	}

	return responses.SuccessResponse(ctx, "Authorization successful", response)
}

// IntrospectToken handles OAuth2 token introspection with Google-like features
// @Summary OAuth2 token introspection
// @Description Introspect an OAuth2 token with detailed metadata
// @Tags OAuth2
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body requests.OAuthTokenIntrospectionRequest true "Token introspection data"
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /oauth/introspect [post]
func (c *OAuthController) IntrospectToken(ctx http.Context) http.Response {
	var req requests.OAuthTokenIntrospectionRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// Record analytics for introspection request
	c.analyticsService.RecordAPIRequest(
		"/oauth/introspect", "POST", "", "",
		0, 200, ctx.Request().Ip(), ctx.Request().Header("User-Agent"),
	)

	// Try to validate as access token first
	accessToken, err := c.oauthService.ValidateAccessToken(req.Token)
	if err == nil {
		user := accessToken.GetUser()
		client, _ := c.oauthService.GetClient(accessToken.ClientID)

		response := map[string]interface{}{
			// RFC 7662 standard fields
			"active":     true,
			"scope":      c.oauthService.FormatScopes(accessToken.GetScopes()),
			"client_id":  accessToken.ClientID,
			"username":   user.Email,
			"token_type": "access_token",
			"exp":        time.Now().Add(time.Hour).Unix(), // Use configured TTL
			"iat":        accessToken.CreatedAt.Unix(),
			"nbf":        accessToken.CreatedAt.Unix(),
			"sub":        *accessToken.UserID,
			"aud":        accessToken.ClientID,
			"iss":        facades.Config().GetString("app.url"),
			"jti":        accessToken.ID,

			// Google-like extensions
			"email":          user.Email,
			"email_verified": user.EmailVerifiedAt != nil,
			"name":           user.Name,
			"picture":        user.Avatar,
			"locale":         "en",
			"client_name":    client.Name,
			"azp":            accessToken.ClientID, // Authorized party

			// Security and metadata
			"token_use":  "access_token",
			"auth_time":  accessToken.CreatedAt.Unix(),
			"device_id":  c.getTokenDeviceID(accessToken.ID),
			"session_id": c.getTokenSessionID(accessToken.ID),
			"ip_address": c.getTokenIPAddress(accessToken.ID),
			"user_agent": c.getTokenUserAgent(accessToken.ID),

			// Token health
			"revoked":       accessToken.Revoked,
			"expires_in":    3600, // Use configured TTL
			"refresh_count": c.getTokenRefreshCount(accessToken.ID),
			"usage_count":   c.getTokenUsageCount(accessToken.ID),
			"last_used":     c.getTokenLastUsed(accessToken.ID),

			// Scopes with descriptions
			"scope_details": c.getScopeDetails(accessToken.GetScopes()),
		}

		// Add DPoP information if available
		if dpopProof := ctx.Request().Header("DPoP"); dpopProof != "" {
			response["dpop_bound"] = true
			response["dpop_jkt"] = c.getDPoPKeyThumbprint(dpopProof)
		}

		return responses.SuccessResponse(ctx, "Token introspection successful", response)
	}

	// Try to validate as refresh token
	refreshToken, err := c.oauthService.ValidateRefreshToken(req.Token)
	if err == nil {
		accessToken := refreshToken.GetAccessToken()
		user := refreshToken.GetUser()
		client, _ := c.oauthService.GetClient(accessToken.ClientID)

		response := map[string]interface{}{
			// RFC 7662 standard fields
			"active":     true,
			"scope":      c.oauthService.FormatScopes(accessToken.GetScopes()),
			"client_id":  accessToken.ClientID,
			"username":   user.Email,
			"token_type": "refresh_token",
			"exp":        time.Now().Add(24 * time.Hour).Unix(), // Use configured refresh TTL
			"iat":        time.Now().Unix(),
			"nbf":        time.Now().Unix(),
			"sub":        *accessToken.UserID,
			"aud":        accessToken.ClientID,
			"iss":        facades.Config().GetString("app.url"),
			"jti":        refreshToken.ID,

			// Google-like extensions
			"email":          user.Email,
			"email_verified": user.EmailVerifiedAt != nil,
			"name":           user.Name,
			"client_name":    client.Name,
			"azp":            accessToken.ClientID,

			// Security and metadata
			"token_use":       "refresh_token",
			"access_token_id": refreshToken.AccessTokenID,
			"revoked":         refreshToken.Revoked,
			"expires_in":      int(time.Until(refreshToken.ExpiresAt).Seconds()),
			"last_refreshed":  c.getRefreshTokenLastUsed(refreshToken.ID),
		}

		return responses.SuccessResponse(ctx, "Token introspection successful", response)
	}

	// Token is invalid - return minimal response
	response := map[string]interface{}{
		"active":            false,
		"error":             "invalid_token",
		"error_description": "The provided token is invalid, expired, or revoked",
	}

	return responses.SuccessResponse(ctx, "Token introspection completed", response)
}

// Helper methods for token introspection

func (c *OAuthController) getTokenDeviceID(tokenID string) string {
	// Implementation would retrieve device ID associated with token
	return ""
}

func (c *OAuthController) getTokenSessionID(tokenID string) string {
	// Implementation would retrieve session ID associated with token
	return ""
}

func (c *OAuthController) getTokenIPAddress(tokenID string) string {
	// Implementation would retrieve IP address from token creation
	return ""
}

func (c *OAuthController) getTokenUserAgent(tokenID string) string {
	// Implementation would retrieve user agent from token creation
	return ""
}

func (c *OAuthController) getTokenRefreshCount(tokenID string) int {
	// Implementation would count how many times token was refreshed
	return 0
}

func (c *OAuthController) getTokenUsageCount(tokenID string) int {
	// Implementation would count token usage
	return 0
}

func (c *OAuthController) getTokenLastUsed(tokenID string) int64 {
	// Implementation would get last usage timestamp
	return 0
}

func (c *OAuthController) getRefreshTokenUsageCount(tokenID string) int {
	// Implementation would count refresh token usage
	return 0
}

func (c *OAuthController) getRefreshTokenLastUsed(tokenID string) int64 {
	// Implementation would get last refresh timestamp
	return 0
}

func (c *OAuthController) getScopeDetails(scopes []string) []map[string]interface{} {
	var details []map[string]interface{}
	descriptions := facades.Config().Get("oauth.scope_descriptions").(map[string]map[string]string)

	for _, scope := range scopes {
		detail := map[string]interface{}{
			"scope": scope,
		}

		if desc, exists := descriptions[scope]; exists {
			detail["title"] = desc["title"]
			detail["description"] = desc["description"]
			detail["sensitive"] = desc["sensitive"] == "true"
		}

		details = append(details, detail)
	}

	return details
}

func (c *OAuthController) getDPoPKeyThumbprint(dpopProof string) string {
	// Implementation would extract JWK thumbprint from DPoP proof
	return ""
}

func (c *OAuthController) getJWTKeyID(token string) string {
	// Implementation would extract key ID from JWT header
	return ""
}

// RevokeToken handles OAuth2 token revocation
// @Summary OAuth2 token revocation
// @Description Revoke an OAuth2 token
// @Tags OAuth2
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body requests.OAuthTokenRevocationRequest true "Token revocation data"
// @Success 200 {object} responses.ApiResponse
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /oauth/revoke [post]
func (c *OAuthController) RevokeToken(ctx http.Context) http.Response {
	var req requests.OAuthTokenRevocationRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// Try to revoke as access token first
	err := c.oauthService.RevokeAccessToken(req.Token)
	if err == nil {
		return responses.SuccessResponse(ctx, "Token revoked successfully", nil)
	}

	// Try to revoke as refresh token
	err = c.oauthService.RevokeRefreshToken(req.Token)
	if err == nil {
		return responses.SuccessResponse(ctx, "Token revoked successfully", nil)
	}

	return responses.CreateErrorResponse(ctx, "Token not found", "Token could not be revoked", 400)
}

// CreatePersonalAccessToken creates a personal access token
// @Summary Create personal access token
// @Description Create a personal access token for the authenticated user
// @Tags OAuth2
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body requests.OAuthPersonalAccessTokenRequest true "Personal access token data"
// @Success 201 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /oauth/personal-access-tokens [post]
func (c *OAuthController) CreatePersonalAccessToken(ctx http.Context) http.Response {
	var req requests.OAuthPersonalAccessTokenRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// Get authenticated user
	user := ctx.Value("user").(*models.User)

	// Get or create personal access client
	client, err := c.oauthService.CreatePersonalAccessClient()
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to create personal access client", err.Error(), 500)
	}

	// Parse scopes
	scopes := c.oauthService.ParseScopes(req.Scope)
	if len(scopes) == 0 {
		scopes = facades.Config().Get("oauth.default_scopes").([]string)
	}

	// Validate scopes
	if !c.oauthService.ValidateScopes(scopes) {
		return responses.CreateErrorResponse(ctx, "Invalid scopes", "One or more requested scopes are not allowed", 400)
	}

	// Create access token
	accessToken, err := c.oauthService.CreateAccessToken(&user.ID, client.ID, scopes, &req.Name)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to create access token", err.Error(), 500)
	}

	response := map[string]interface{}{
		"access_token": accessToken.ID,
		"token_type":   "Bearer",
		"expires_in":   facades.Config().GetInt("oauth.personal_access_token_ttl", 60) * 60, // Convert to seconds
		"scope":        c.oauthService.FormatScopes(scopes),
		"name":         req.Name,
	}

	return responses.SuccessResponse(ctx, "Personal access token created successfully", response)
}

// GetPersonalAccessTokens gets all personal access tokens for the authenticated user
// @Summary Get personal access tokens
// @Description Get all personal access tokens for the authenticated user
// @Tags OAuth2
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} responses.ApiResponse{data=[]models.OAuthAccessToken}
// @Failure 401 {object} responses.ApiResponse
// @Router /oauth/personal-access-tokens [get]
func (c *OAuthController) GetPersonalAccessTokens(ctx http.Context) http.Response {
	// Get authenticated user
	user := ctx.Value("user").(*models.User)

	tokens, err := c.oauthService.GetUserTokens(user.ID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to retrieve tokens", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Personal access tokens retrieved successfully", tokens)
}

// RevokePersonalAccessToken revokes a personal access token
// @Summary Revoke personal access token
// @Description Revoke a personal access token
// @Tags OAuth2
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Token ID"
// @Success 200 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Failure 404 {object} responses.ApiResponse
// @Router /oauth/personal-access-tokens/{id} [delete]
func (c *OAuthController) RevokePersonalAccessToken(ctx http.Context) http.Response {
	tokenID := ctx.Request().Route("id")

	err := c.oauthService.RevokeAccessToken(tokenID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Token not found", err.Error(), 404)
	}

	return responses.SuccessResponse(ctx, "Personal access token revoked successfully", nil)
}

// Grant type handlers

func (c *OAuthController) handlePasswordGrant(req *requests.OAuthTokenRequest) (*models.OAuthAccessToken, *models.OAuthRefreshToken, error) {
	// Validate client
	client, err := c.oauthService.ValidateClient(req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, nil, err
	}

	// Check if client supports password grant
	if !client.IsPasswordClient() {
		return nil, nil, fmt.Errorf("client does not support password grant")
	}

	// Authenticate user
	loginReq := &requests.LoginRequest{
		Email:    req.Username,
		Password: req.Password,
	}

	user, _, err := c.authService.Login(nil, loginReq)
	if err != nil {
		return nil, nil, err
	}

	// Parse scopes
	scopes := c.oauthService.ParseScopes(req.Scope)
	if len(scopes) == 0 {
		scopes = facades.Config().Get("oauth.default_scopes").([]string)
	}

	// Generate token pair
	return c.oauthService.GenerateTokenPair(&user.ID, client.ID, scopes, nil)
}

func (c *OAuthController) handleClientCredentialsGrant(req *requests.OAuthTokenRequest) (*models.OAuthAccessToken, *models.OAuthRefreshToken, error) {
	// Validate client
	client, err := c.oauthService.ValidateClient(req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, nil, err
	}

	// Parse scopes
	scopes := c.oauthService.ParseScopes(req.Scope)
	if len(scopes) == 0 {
		scopes = facades.Config().Get("oauth.default_scopes").([]string)
	}

	// Generate token pair (no user for client credentials)
	return c.oauthService.GenerateTokenPair(nil, client.ID, scopes, nil)
}

func (c *OAuthController) handleAuthorizationCodeGrant(req *requests.OAuthTokenRequest) (*models.OAuthAccessToken, *models.OAuthRefreshToken, error) {
	// Validate client
	client, err := c.oauthService.ValidateClient(req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, nil, err
	}

	// Validate authorization code
	authCode, err := c.oauthService.ValidateAuthCode(req.Code)
	if err != nil {
		return nil, nil, err
	}

	// Check if auth code belongs to the client
	if authCode.ClientID != client.ID {
		return nil, nil, fmt.Errorf("authorization code does not belong to client")
	}

	// Validate redirect URI
	if authCode.GetClient().GetRedirectURIs()[0] != req.RedirectURI {
		return nil, nil, fmt.Errorf("redirect URI mismatch")
	}

	// Validate PKCE if code challenge is present
	if authCode.CodeChallenge != nil && *authCode.CodeChallenge != "" {
		if req.CodeVerifier == "" {
			return nil, nil, fmt.Errorf("code_verifier required for PKCE")
		}

		if !c.oauthService.ValidatePKCE(req.CodeVerifier, *authCode.CodeChallenge, *authCode.CodeChallengeMethod) {
			return nil, nil, fmt.Errorf("invalid code verifier")
		}
	}

	// Revoke the authorization code
	c.oauthService.RevokeAuthCode(authCode.ID)

	// Generate token pair
	return c.oauthService.GenerateTokenPair(&authCode.UserID, client.ID, authCode.GetScopes(), nil)
}

func (c *OAuthController) handleRefreshTokenGrant(req *requests.OAuthTokenRequest) (*models.OAuthAccessToken, *models.OAuthRefreshToken, error) {
	// Validate client
	client, err := c.oauthService.ValidateClient(req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, nil, err
	}

	// Validate refresh token
	refreshToken, err := c.oauthService.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, nil, err
	}

	// Check if refresh token belongs to the client
	if refreshToken.GetAccessToken().ClientID != client.ID {
		return nil, nil, fmt.Errorf("refresh token does not belong to client")
	}

	// Revoke the old refresh token
	c.oauthService.RevokeRefreshToken(refreshToken.ID)

	// Generate new token pair
	userID := refreshToken.GetUser().ID
	return c.oauthService.GenerateTokenPair(&userID, client.ID, refreshToken.GetAccessToken().GetScopes(), nil)
}

// Helper methods

func (c *OAuthController) handleDeviceCodeGrant(req *requests.OAuthTokenRequest) (*models.OAuthAccessToken, *models.OAuthRefreshToken, error) {
	// Validate device code
	deviceCode, err := c.oauthService.ValidateDeviceCode(req.DeviceCode)
	if err != nil {
		return nil, nil, err
	}

	// Check if device authorization is complete
	if !deviceCode.IsAuthorized() {
		return nil, nil, fmt.Errorf("authorization pending")
	}

	// Generate token pair
	accessToken, refreshToken, err := c.oauthService.GenerateTokenPair(
		deviceCode.UserID,
		deviceCode.ClientID,
		deviceCode.GetScopes(),
		nil,
	)
	if err != nil {
		return nil, nil, err
	}

	// Revoke the device code
	c.oauthService.RevokeDeviceCode(deviceCode.ID)

	return accessToken, refreshToken, nil
}

func (c *OAuthController) handleTokenExchangeGrant(req *requests.OAuthTokenRequest) (*models.OAuthAccessToken, *models.OAuthRefreshToken, error) {
	// Validate client
	client, err := c.oauthService.ValidateClient(req.ClientID, req.ClientSecret)
	if err != nil {
		return nil, nil, err
	}

	// Parse scopes
	scopes := c.oauthService.ParseScopes(req.Scope)
	if len(scopes) == 0 {
		scopes = facades.Config().Get("oauth.default_scopes").([]string)
	}

	// Validate scopes
	if !c.oauthService.ValidateScopes(scopes) {
		return nil, nil, fmt.Errorf("invalid scopes")
	}

	// Exchange token
	accessToken, err := c.oauthService.ExchangeToken(
		req.SubjectToken,
		req.SubjectTokenType,
		req.RequestedTokenType,
		client.ID,
		scopes,
	)
	if err != nil {
		return nil, nil, err
	}

	// For token exchange, we don't return a refresh token
	return accessToken, nil, nil
}

func (c *OAuthController) validateRedirectURI(client *models.OAuthClient, redirectURI string) bool {
	allowedURIs := client.GetRedirectURIs()
	for _, uri := range allowedURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}

// DeviceAuthorization handles OAuth2 device authorization requests
// @Summary OAuth2 device authorization endpoint
// @Description Handle OAuth2 device authorization requests
// @Tags OAuth2
// @Accept json
// @Produce json
// @Param request body requests.OAuthDeviceAuthorizationRequest true "Device authorization request data"
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Router /oauth/device [post]
func (c *OAuthController) DeviceAuthorization(ctx http.Context) http.Response {
	var req requests.OAuthDeviceAuthorizationRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// Validate client
	client, err := c.oauthService.GetClient(req.ClientID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid client", err.Error(), 400)
	}

	// Parse scopes
	scopes := c.oauthService.ParseScopes(req.Scope)
	if len(scopes) == 0 {
		scopes = facades.Config().Get("oauth.default_scopes").([]string)
	}

	// Validate scopes
	if !c.oauthService.ValidateScopes(scopes) {
		return responses.CreateErrorResponse(ctx, "Invalid scopes", "One or more requested scopes are not allowed", 400)
	}

	// Create device code
	deviceCodeExpiry := time.Now().Add(time.Duration(facades.Config().GetInt("oauth.device_code_ttl", 600)) * time.Second)
	deviceCode, err := c.oauthService.CreateDeviceCode(client.ID, scopes, deviceCodeExpiry)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to create device code", err.Error(), 500)
	}

	// Log OAuth event
	c.oauthService.LogOAuthEvent("device_authorization_requested", client.ID, "", map[string]interface{}{
		"scopes": scopes,
	})

	response := map[string]interface{}{
		"device_code":               deviceCode.ID,
		"user_code":                 deviceCode.UserCode,
		"verification_uri":          facades.Config().GetString("oauth.device_verification_uri", "https://example.com/device"),
		"verification_uri_complete": fmt.Sprintf("%s?user_code=%s", facades.Config().GetString("oauth.device_verification_uri", "https://example.com/device"), deviceCode.UserCode),
		"expires_in":                facades.Config().GetInt("oauth.device_code_ttl", 600),
		"interval":                  facades.Config().GetInt("oauth.device_polling_interval", 5),
	}

	return responses.SuccessResponse(ctx, "Device authorization initiated", response)
}

// DeviceToken handles OAuth2 device token requests
// @Summary OAuth2 device token endpoint
// @Description Handle OAuth2 device token requests
// @Tags OAuth2
// @Accept json
// @Produce json
// @Param request body requests.OAuthDeviceTokenRequest true "Device token request data"
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /oauth/device/token [post]
func (c *OAuthController) DeviceToken(ctx http.Context) http.Response {
	var req requests.OAuthDeviceTokenRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// Validate device code
	deviceCode, err := c.oauthService.ValidateDeviceCode(req.DeviceCode)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid device code", err.Error(), 400)
	}

	// Check if device authorization is complete
	if !deviceCode.IsAuthorized() {
		return responses.CreateErrorResponse(ctx, "Authorization pending", "User has not yet authorized the device", 400)
	}

	// Generate token pair
	accessToken, refreshToken, err := c.oauthService.GenerateTokenPair(
		deviceCode.UserID,
		deviceCode.ClientID,
		deviceCode.GetScopes(),
		nil,
	)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to generate tokens", err.Error(), 500)
	}

	// Revoke the device code
	c.oauthService.RevokeDeviceCode(deviceCode.ID)

	// Log OAuth event
	c.oauthService.LogOAuthEvent("device_token_generated", deviceCode.ClientID, *deviceCode.UserID, map[string]interface{}{
		"scopes": deviceCode.GetScopes(),
	})

	response := map[string]interface{}{
		"access_token":  accessToken.ID,
		"token_type":    "Bearer",
		"expires_in":    facades.Config().GetInt("oauth.access_token_ttl", 60) * 60,
		"scope":         c.oauthService.FormatScopes(deviceCode.GetScopes()),
		"refresh_token": refreshToken.ID,
	}

	return responses.SuccessResponse(ctx, "Device token generated successfully", response)
}

// CompleteDeviceAuthorization completes device authorization
// @Summary Complete device authorization
// @Description Complete device authorization by providing user credentials
// @Tags OAuth2
// @Accept json
// @Produce json
// @Param request body requests.OAuthCompleteDeviceAuthorizationRequest true "Device authorization completion data"
// @Success 200 {object} responses.ApiResponse
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /oauth/device/complete [post]
func (c *OAuthController) CompleteDeviceAuthorization(ctx http.Context) http.Response {
	var req requests.OAuthCompleteDeviceAuthorizationRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// Validate user code
	deviceCode, err := c.oauthService.ValidateUserCode(req.UserCode)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid user code", err.Error(), 400)
	}

	// Find user by email
	var user models.User
	err = facades.Orm().Query().Where("email", req.Email).First(&user)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid credentials", err.Error(), 401)
	}

	// Check if user is active
	if !user.IsActive {
		return responses.CreateErrorResponse(ctx, "Account is deactivated", "User account is not active", 401)
	}

	// Verify password
	if !facades.Hash().Check(req.Password, user.Password) {
		return responses.CreateErrorResponse(ctx, "Invalid credentials", "Invalid email or password", 401)
	}

	// Complete device authorization
	err = c.oauthService.CompleteDeviceAuthorization(deviceCode.ID, user.ID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to complete authorization", err.Error(), 500)
	}

	// Log OAuth event
	c.oauthService.LogOAuthEvent("device_authorization_completed", deviceCode.ClientID, user.ID, map[string]interface{}{
		"scopes": deviceCode.GetScopes(),
	})

	return responses.SuccessResponse(ctx, "Device authorization completed successfully", nil)
}

// TokenExchange handles OAuth2 token exchange requests
// @Summary OAuth2 token exchange endpoint
// @Description Handle OAuth2 token exchange requests
// @Tags OAuth2
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body requests.OAuthTokenExchangeRequest true "Token exchange request data"
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /oauth/token/exchange [post]
func (c *OAuthController) TokenExchange(ctx http.Context) http.Response {
	var req requests.OAuthTokenExchangeRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// Validate client
	client, err := c.oauthService.ValidateClient(req.ClientID, req.ClientSecret)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid client", err.Error(), 401)
	}

	// Parse scopes
	scopes := c.oauthService.ParseScopes(req.Scope)
	if len(scopes) == 0 {
		scopes = facades.Config().Get("oauth.default_scopes").([]string)
	}

	// Validate scopes
	if !c.oauthService.ValidateScopes(scopes) {
		return responses.CreateErrorResponse(ctx, "Invalid scopes", "One or more requested scopes are not allowed", 400)
	}

	// Exchange token
	accessToken, err := c.oauthService.ExchangeToken(
		req.SubjectToken,
		req.SubjectTokenType,
		req.RequestedTokenType,
		client.ID,
		scopes,
	)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Token exchange failed", err.Error(), 400)
	}

	// Log OAuth event
	c.oauthService.LogOAuthEvent("token_exchanged", client.ID, "", map[string]interface{}{
		"subject_token_type":   req.SubjectTokenType,
		"requested_token_type": req.RequestedTokenType,
		"scopes":               scopes,
	})

	response := map[string]interface{}{
		"access_token": accessToken.ID,
		"token_type":   "Bearer",
		"expires_in":   facades.Config().GetInt("oauth.access_token_ttl", 60) * 60,
		"scope":        c.oauthService.FormatScopes(scopes),
	}

	return responses.SuccessResponse(ctx, "Token exchanged successfully", response)
}

// Discovery provides OAuth2 server metadata according to RFC 8414
// @Summary OAuth2 Authorization Server Metadata
// @Description Provides OAuth2/OIDC discovery information with Google-like features
// @Tags OAuth2
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /.well-known/oauth-authorization-server [get]
func (c *OAuthController) Discovery(ctx http.Context) http.Response {
	baseURL := facades.Config().GetString("app.url")

	metadata := map[string]interface{}{
		// Core OAuth2/OIDC endpoints
		"issuer":                        baseURL,
		"authorization_endpoint":        baseURL + "/oauth/authorize",
		"token_endpoint":                baseURL + "/api/v1/oauth/token",
		"userinfo_endpoint":             baseURL + "/api/v1/oauth/userinfo",
		"jwks_uri":                      baseURL + "/api/v1/oauth/jwks",
		"introspection_endpoint":        baseURL + "/api/v1/oauth/introspect",
		"revocation_endpoint":           baseURL + "/api/v1/oauth/revoke",
		"device_authorization_endpoint": baseURL + "/api/v1/oauth/device",
		"registration_endpoint":         baseURL + "/api/v1/oauth/clients",

		// Google-like additional endpoints

		// Supported response types (Google-compatible)
		"response_types_supported": []string{
			"code",
			"token",
			"id_token",
			"code token",
			"code id_token",
			"token id_token",
			"code token id_token",
			"none",
		},

		// Supported grant types (including latest standards)
		"grant_types_supported": []string{
			"authorization_code",
			"client_credentials",
			"password",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code",
			"urn:ietf:params:oauth:grant-type:token-exchange",
			"urn:ietf:params:oauth:grant-type:jwt-bearer",
		},

		// Supported scopes (hierarchical like Google)
		"scopes_supported": facades.Config().Get("oauth.allowed_scopes"),

		// Client authentication methods (Google-compatible)
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
			"client_secret_jwt",
			"private_key_jwt",
			"none",
		},

		// Token endpoint auth signing algorithms
		"token_endpoint_auth_signing_alg_values_supported": []string{
			"RS256", "RS384", "RS512",
			"ES256", "ES384", "ES512",
			"HS256", "HS384", "HS512",
		},

		// Supported subject types
		"subject_types_supported": []string{"public", "pairwise"},

		// ID token signing algorithms
		"id_token_signing_alg_values_supported": []string{
			"RS256", "RS384", "RS512",
			"ES256", "ES384", "ES512",
		},

		// ID token encryption algorithms (optional)
		"id_token_encryption_alg_values_supported": []string{
			"RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
			"A128KW", "A192KW", "A256KW",
			"dir", "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW",
		},

		// ID token encryption encoding
		"id_token_encryption_enc_values_supported": []string{
			"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
			"A128GCM", "A192GCM", "A256GCM",
		},

		// UserInfo signing algorithms
		"userinfo_signing_alg_values_supported": []string{
			"RS256", "RS384", "RS512",
			"ES256", "ES384", "ES512",
			"none",
		},

		// Request object support
		"request_object_signing_alg_values_supported": []string{
			"RS256", "RS384", "RS512",
			"ES256", "ES384", "ES512",
		},

		// Response modes supported
		"response_modes_supported": []string{
			"query",
			"fragment",
			"form_post",
			"query.jwt",
			"fragment.jwt",
			"form_post.jwt",
		},

		// Code challenge methods (PKCE)
		"code_challenge_methods_supported": []string{"S256", "plain"},

		// Claims supported (Google-like comprehensive list)
		"claims_supported": []string{
			"iss", "sub", "aud", "exp", "iat", "auth_time", "nonce",
			"name", "given_name", "family_name", "middle_name", "nickname",
			"preferred_username", "profile", "picture", "website",
			"email", "email_verified", "gender", "birthdate", "zoneinfo",
			"locale", "phone_number", "phone_number_verified",
			"address", "updated_at",
			// Custom claims
			"tenant_id", "organization_id", "roles", "permissions",
			"session_state", "acr", "amr",
		},

		// Claims parameter supported
		"claims_parameter_supported": true,

		// Request parameter supported
		"request_parameter_supported": true,

		// Request URI parameter supported
		"request_uri_parameter_supported": true,

		// Require request URI registration
		"require_request_uri_registration": false,

		// ACR values supported (Authentication Context Class Reference)
		"acr_values_supported": []string{
			"0", "1", "2", "3", // Basic levels
			"password", "mfa", "webauthn", "biometric",
		},

		// Display values supported
		"display_values_supported": []string{"page", "popup", "touch", "wap"},

		// Claim types supported
		"claim_types_supported": []string{"normal", "aggregated", "distributed"},

		// Service documentation
		"service_documentation": baseURL + "/docs",

		// Claims locales supported
		"claims_locales_supported": []string{"en", "en-US", "es", "fr", "de", "zh"},

		// UI locales supported
		"ui_locales_supported": []string{"en", "en-US", "es", "fr", "de", "zh"},

		// Google-like security and compliance features
		"tls_client_certificate_bound_access_tokens": true,
		"mtls_endpoint_aliases": map[string]string{
			"token_endpoint":         baseURL + "/api/v1/oauth/token",
			"revocation_endpoint":    baseURL + "/api/v1/oauth/revoke",
			"introspection_endpoint": baseURL + "/api/v1/oauth/introspect",
		},

		// Device authorization endpoint auth methods
		"device_authorization_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
			"none",
		},

		// Pushed Authorization Request support
		"pushed_authorization_request_endpoint": baseURL + "/api/v1/oauth/par",
		"require_pushed_authorization_requests": facades.Config().GetBool("oauth.par.require_par", false),
		"pushed_authorization_request_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
			"client_secret_jwt",
			"private_key_jwt",
		},

		// Client attestation support (Google-like mobile security)
		"client_attestation_supported": facades.Config().GetBool("oauth.client_attestation.enabled", false),
		"client_attestation_types_supported": []string{
			"android-safetynet",
			"android-play-integrity",
			"apple-app-attest",
			"custom",
		},

		// DPoP support
		"dpop_signing_alg_values_supported": []string{
			"RS256", "RS384", "RS512",
			"ES256", "ES384", "ES512",
		},

		// Token exchange support
		"token_exchange_endpoint": baseURL + "/api/v1/oauth/token",
		"token_types_supported": []string{
			"access_token",
			"refresh_token",
			"id_token",
			"saml1",
			"saml2",
		},

		// JARM (JWT Secured Authorization Response Mode) support
		"authorization_response_iss_parameter_supported": true,
		"authorization_signing_alg_values_supported": []string{
			"RS256", "RS384", "RS512",
			"ES256", "ES384", "ES512",
		},
		"authorization_encryption_alg_values_supported": []string{
			"RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
			"A128KW", "A192KW", "A256KW",
		},
		"authorization_encryption_enc_values_supported": []string{
			"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
			"A128GCM", "A192GCM", "A256GCM",
		},

		// Risk assessment and adaptive authentication
		"risk_assessment_supported":         facades.Config().GetBool("oauth.security.enable_risk_assessment", true),
		"adaptive_authentication_supported": true,

		// Session management
		"session_management_supported": true,
		"check_session_iframe":         baseURL + "/oauth/check_session",

		// Logout support
		"end_session_endpoint":                  baseURL + "/oauth/logout",
		"frontchannel_logout_supported":         true,
		"frontchannel_logout_session_supported": true,
		"backchannel_logout_supported":          true,
		"backchannel_logout_session_supported":  true,

		// Additional Google-like metadata
		"issuer_metadata_version":      "1.0",
		"authorization_server_version": facades.Config().GetString("app.version", "1.0.0"),
		"supported_standards": []string{
			"RFC 6749", // OAuth 2.0
			"RFC 6750", // Bearer Token Usage
			"RFC 7009", // Token Revocation
			"RFC 7519", // JWT
			"RFC 7523", // JWT Bearer Token
			"RFC 7636", // PKCE
			"RFC 7662", // Token Introspection
			"RFC 8414", // Authorization Server Metadata
			"RFC 8628", // Device Authorization Grant
			"RFC 8693", // Token Exchange
			"RFC 9126", // Pushed Authorization Requests
			"RFC 9449", // DPoP
			"OpenID Connect 1.0",
		},
	}

	return responses.SuccessResponse(ctx, "OAuth2 server metadata", metadata)
}

// UserInfo provides user information for OpenID Connect
// @Summary OpenID Connect UserInfo endpoint
// @Description Get user information using access token with Google-like claim handling
// @Tags OAuth2
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} responses.ApiResponse
// @Router /oauth/userinfo [get]
func (c *OAuthController) UserInfo(ctx http.Context) http.Response {
	// Get the access token from Authorization header
	authHeader := ctx.Request().Header("Authorization")
	if authHeader == "" {
		return responses.UserInfoErrorResponse(ctx, "invalid_token", "Bearer token required")
	}

	// Extract token from "Bearer <token>"
	tokenParts := strings.Fields(authHeader)
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		return responses.UserInfoErrorResponse(ctx, "invalid_token", "Invalid Bearer token format")
	}

	tokenID := tokenParts[1]

	// Validate the access token
	var accessToken models.OAuthAccessToken
	err := facades.Orm().Query().Where("id", tokenID).Where("revoked", false).First(&accessToken)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid access token", "Token not found or revoked", 401)
	}

	// Check if token is expired
	tokenTTL := time.Duration(facades.Config().GetInt("oauth.access_token_ttl", 60)) * time.Minute
	if time.Since(accessToken.CreatedAt) > tokenTTL {
		return responses.CreateErrorResponse(ctx, "Token expired", "Access token has expired", 401)
	}

	// Get the user associated with the token
	if accessToken.UserID == nil {
		return responses.CreateErrorResponse(ctx, "Invalid token", "Token not associated with a user", 401)
	}

	var user models.User
	err = facades.Orm().Query().Where("id", *accessToken.UserID).First(&user)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "User not found", "Associated user not found", 401)
	}

	// Get token scopes
	scopes := accessToken.GetScopes()

	// Build user info response based on granted scopes (Google-like claim handling)
	userInfo := map[string]interface{}{
		"sub": user.ID,
		"iss": facades.Config().GetString("app.url"),
		"aud": accessToken.ClientID,
	}

	// Add claims based on scopes with hierarchical support
	for _, scope := range scopes {
		switch scope {
		case "profile", "openid":
			userInfo["name"] = user.Name
			if user.Avatar != "" {
				userInfo["picture"] = user.Avatar
			}
			userInfo["locale"] = "en"
			userInfo["updated_at"] = user.UpdatedAt.Unix()

			// Parse name into components if available
			nameParts := strings.Fields(user.Name)
			if len(nameParts) >= 1 {
				userInfo["given_name"] = nameParts[0]
			}
			if len(nameParts) >= 2 {
				userInfo["family_name"] = strings.Join(nameParts[1:], " ")
			}

		case "email":
			userInfo["email"] = user.Email
			userInfo["email_verified"] = user.EmailVerifiedAt != nil

		case "phone":
			if user.Phone != "" {
				userInfo["phone_number"] = user.Phone
				userInfo["phone_number_verified"] = false // Default to false since we don't have a verified field
			}

		case "address":
			// Add address information if available (placeholder for future implementation)
			// Note: User model doesn't currently have address fields
			// This is where you would add address handling when the fields are added to the User model

		// Hierarchical scope support (Google-like)
		case "user:read", "user:profile":
			userInfo["name"] = user.Name
			if user.Avatar != "" {
				userInfo["picture"] = user.Avatar
			}
			userInfo["locale"] = "en"

		case "user:email":
			userInfo["email"] = user.Email
			userInfo["email_verified"] = user.EmailVerifiedAt != nil

		// Organization scopes
		case "org:read":
			// Add organization information if user belongs to any
			organizations := c.getUserOrganizations(user.ID)
			if len(organizations) > 0 {
				userInfo["organizations"] = organizations
			}

		// Custom claims based on roles and permissions
		case "admin":
			userInfo["role"] = "admin"
			userInfo["permissions"] = c.getUserPermissions(user.ID)
		}
	}

	// Add standard OIDC claims
	userInfo["auth_time"] = accessToken.CreatedAt.Unix()

	// Add custom claims if configured
	customClaims := c.getCustomClaims(user.ID)
	for key, value := range customClaims {
		userInfo[key] = value
	}

	// Set content type for JSON response
	ctx.Response().Header("Content-Type", "application/json")
	ctx.Response().Header("Cache-Control", "no-store")
	ctx.Response().Header("Pragma", "no-cache")

	return ctx.Response().Json(200, userInfo)
}

// Helper method to get user organizations
func (c *OAuthController) getUserOrganizations(userID string) []map[string]interface{} {
	var organizations []map[string]interface{}

	// Query user organizations (implementation depends on your schema)
	var userOrgs []models.UserOrganization
	facades.Orm().Query().Where("user_id", userID).Find(&userOrgs)

	for _, userOrg := range userOrgs {
		var org models.Organization
		if facades.Orm().Query().Where("id", userOrg.OrganizationID).First(&org) == nil {
			organizations = append(organizations, map[string]interface{}{
				"id":   org.ID,
				"name": org.Name,
				"role": userOrg.Role,
			})
		}
	}

	return organizations
}

// Helper method to get user permissions
func (c *OAuthController) getUserPermissions(userID string) []string {
	var permissions []string

	// Query user permissions through roles (implementation depends on your schema)
	var userRoles []models.UserRole
	facades.Orm().Query().Where("user_id", userID).Find(&userRoles)

	for _, userRole := range userRoles {
		var rolePermissions []models.RolePermission
		facades.Orm().Query().Where("role_id", userRole.RoleID).Find(&rolePermissions)

		for _, rolePerm := range rolePermissions {
			var permission models.Permission
			if facades.Orm().Query().Where("id", rolePerm.PermissionID).First(&permission) == nil {
				permissions = append(permissions, permission.Name)
			}
		}
	}

	return permissions
}

// Helper method to get custom claims
func (c *OAuthController) getCustomClaims(userID string) map[string]interface{} {
	customClaims := make(map[string]interface{})

	// Add any custom claims based on user attributes or external systems
	// This is where you can integrate with external identity providers or add custom logic

	return customClaims
}

// JWKS provides JSON Web Key Set for token verification
// @Summary JSON Web Key Set endpoint
// @Description Get public keys for token verification
// @Tags OAuth2
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /oauth/jwks [get]
func (c *OAuthController) JWKS(ctx http.Context) http.Response {
	// Get JWKS from OAuth service
	jwks := c.oauthService.GetJWKS()
	return ctx.Response().Json(200, jwks)
}

// TokenInfo provides token information (Google-like endpoint)
// @Summary OAuth2 Token Info endpoint
// @Description Get information about an access token
// @Tags OAuth2
// @Accept json
// @Produce json
// @Param access_token query string true "Access token to inspect"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /oauth/tokeninfo [get]
func (c *OAuthController) TokenInfo(ctx http.Context) http.Response {
	// Get token from query parameter (Google-style)
	tokenID := ctx.Request().Query("access_token")
	if tokenID == "" {
		// Also check Authorization header as fallback
		authHeader := ctx.Request().Header("Authorization")
		if authHeader != "" {
			tokenParts := strings.Fields(authHeader)
			if len(tokenParts) == 2 && tokenParts[0] == "Bearer" {
				tokenID = tokenParts[1]
			}
		}
	}

	if tokenID == "" {
		return responses.OAuth2ErrorResponse(ctx, "invalid_request", "Missing access_token parameter or Authorization header", 400)
	}

	// Validate the access token
	var accessToken models.OAuthAccessToken
	err := facades.Orm().Query().Where("id", tokenID).Where("revoked", false).First(&accessToken)
	if err != nil {
		return responses.OAuth2ErrorResponse(ctx, "invalid_token", "Token not found or revoked", 401)
	}

	// Check if token is expired
	tokenTTL := time.Duration(facades.Config().GetInt("oauth.access_token_ttl", 60)) * time.Minute
	if time.Since(accessToken.CreatedAt) > tokenTTL {
		return responses.OAuth2ErrorResponse(ctx, "invalid_token", "Access token has expired", 401)
	}

	// Get client information
	client, err := c.oauthService.GetClient(accessToken.ClientID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid client", "Client not found", 401)
	}

	// Build token info response (Google-compatible)
	tokenInfo := map[string]interface{}{
		"issued_to":   accessToken.ClientID,
		"audience":    accessToken.ClientID,
		"scope":       c.oauthService.FormatScopes(accessToken.GetScopes()),
		"expires_in":  int64(tokenTTL.Seconds()) - int64(time.Since(accessToken.CreatedAt).Seconds()),
		"access_type": "online",
	}

	// Add user information if token is associated with a user
	if accessToken.UserID != nil {
		var user models.User
		if facades.Orm().Query().Where("id", *accessToken.UserID).First(&user) == nil {
			tokenInfo["user_id"] = user.ID
			tokenInfo["email"] = user.Email
			tokenInfo["verified_email"] = user.EmailVerifiedAt != nil
		}
	}

	// Add client information
	if client.Name != "" {
		tokenInfo["issued_to_name"] = client.Name
	}

	return ctx.Response().Json(200, tokenInfo)
}

// Logout handles OAuth2 logout (Google-like endpoint)
// @Summary OAuth2 Logout endpoint
// @Description Revoke access token and perform logout
// @Tags OAuth2
// @Accept json
// @Produce json
// @Param token formData string false "Token to revoke"
// @Success 200 {object} responses.ApiResponse
// @Failure 400 {object} responses.ApiResponse
// @Router /oauth/logout [post]
func (c *OAuthController) Logout(ctx http.Context) http.Response {
	// Get token from form data or Authorization header
	token := ctx.Request().Input("token")
	if token == "" {
		authHeader := ctx.Request().Header("Authorization")
		if authHeader != "" {
			tokenParts := strings.Fields(authHeader)
			if len(tokenParts) == 2 && tokenParts[0] == "Bearer" {
				token = tokenParts[1]
			}
		}
	}

	if token != "" {
		// Revoke the access token
		var accessToken models.OAuthAccessToken
		err := facades.Orm().Query().Where("id", token).First(&accessToken)
		if err == nil {
			accessToken.Revoked = true
			facades.Orm().Query().Save(&accessToken)

			// Also revoke associated refresh token
			var refreshToken models.OAuthRefreshToken
			err = facades.Orm().Query().Where("access_token_id", accessToken.ID).First(&refreshToken)
			if err == nil {
				refreshToken.Revoked = true
				facades.Orm().Query().Save(&refreshToken)
			}

			// Log logout event
			c.oauthService.LogOAuthEvent("logout", accessToken.ClientID,
				func() string {
					if accessToken.UserID != nil {
						return *accessToken.UserID
					}
					return ""
				}(), map[string]interface{}{
					"token_revoked": true,
				})
		}
	}

	// Always return success for security (don't reveal token validity)
	return responses.SuccessResponse(ctx, "Logout successful", map[string]interface{}{
		"message": "Successfully logged out",
	})
}

// CheckSession provides session check iframe support (Google-like)
// @Summary OAuth2 Check Session endpoint
// @Description Check session status for iframe
// @Tags OAuth2
// @Accept json
// @Produce text/html
// @Success 200 {string} string "HTML iframe content"
// @Router /oauth/check_session [get]
func (c *OAuthController) CheckSession(ctx http.Context) http.Response {
	// Return a simple HTML page for session checking
	// This is used by OpenID Connect session management
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Session Check</title>
    <script>
        window.addEventListener('message', function(e) {
            var origin = e.origin;
            var message = e.data;
            
            // Simple session check logic
            // In a real implementation, you would check the actual session state
            var sessionState = 'unchanged';
            
            // Send response back to parent
            e.source.postMessage(sessionState, origin);
        });
    </script>
</head>
<body>
    <p>Session check iframe</p>
</body>
</html>`

	ctx.Response().Header("Content-Type", "text/html")
	ctx.Response().Header("X-Frame-Options", "SAMEORIGIN")
	return ctx.Response().String(200, html)
}

// CreateJWTToken creates a JWT access token (enhanced version)
func (c *OAuthController) CreateJWTToken(ctx http.Context) http.Response {
	var req requests.OAuthTokenRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// Validate client
	client, err := c.oauthService.ValidateClient(req.ClientID, req.ClientSecret)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid client", err.Error(), 401)
	}

	// Parse scopes
	scopes := c.oauthService.ParseScopes(req.Scope)
	if len(scopes) == 0 {
		scopes = facades.Config().Get("oauth.default_scopes").([]string)
	}

	// Create JWT access token
	var userID *string
	if req.GrantType == "client_credentials" {
		// For client credentials, no user context
		userID = nil
	} else {
		// For other flows, get user from context or request
		if user := ctx.Value("user"); user != nil {
			u := user.(*models.User)
			userID = &u.ID
		}
	}

	jwtToken, err := c.oauthService.CreateJWTAccessToken(userID, client.ID, scopes, nil)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to create JWT token", err.Error(), 500)
	}

	response := map[string]interface{}{
		"access_token": jwtToken,
		"token_type":   "Bearer",
		"expires_in":   facades.Config().GetInt("oauth.access_token_ttl", 60) * 60,
		"scope":        c.oauthService.FormatScopes(scopes),
	}

	return responses.SuccessResponse(ctx, "JWT token created successfully", response)
}

// SecurityReport provides security analysis for OAuth2 requests
func (c *OAuthController) SecurityReport(ctx http.Context) http.Response {
	userID := ctx.Request().Input("user_id")
	clientID := ctx.Request().Input("client_id")
	ipAddress := ctx.Request().Ip()
	userAgent := ctx.Request().Header("User-Agent")

	if userID == "" || clientID == "" {
		return responses.CreateErrorResponse(ctx, "Missing parameters", "user_id and client_id are required", 400)
	}

	// Generate security report
	report := c.oauthService.DetectSuspiciousActivity(userID, clientID, ipAddress, userAgent)

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"report":  report,
	})
}

// PrepareConsent prepares the consent screen for OAuth2 authorization
// @Summary Prepare OAuth2 consent screen
// @Description Prepare consent screen with detailed scope information
// @Tags OAuth2
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param client_id query string true "Client ID"
// @Param scopes query string true "Requested scopes (space-separated)"
// @Param redirect_uri query string true "Redirect URI"
// @Param state query string false "State parameter"
// @Param nonce query string false "Nonce parameter"
// @Success 200 {object} responses.ApiResponse{data=services.ConsentScreen}
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /oauth/consent/prepare [get]
func (c *OAuthController) PrepareConsent(ctx http.Context) http.Response {
	// Get authenticated user
	user := ctx.Value("user").(*models.User)

	clientID := ctx.Request().Input("client_id")
	scopesStr := ctx.Request().Input("scopes")
	redirectURI := ctx.Request().Input("redirect_uri")
	state := ctx.Request().Input("state")
	nonce := ctx.Request().Input("nonce")

	if clientID == "" || scopesStr == "" || redirectURI == "" {
		return responses.CreateErrorResponse(ctx, "Missing parameters", "client_id, scopes, and redirect_uri are required", 400)
	}

	// Parse scopes
	scopes := c.oauthService.ParseScopes(scopesStr)

	// Prepare consent screen
	consentScreen, err := c.consentService.PrepareConsentScreen(
		user.ID, clientID, scopes, redirectURI, state, nonce,
	)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to prepare consent screen", err.Error(), 500)
	}

	// Record analytics
	c.analyticsService.RecordAuthorizationEvent(
		"consent_prepared", clientID, user.ID, false, scopes,
		ctx.Request().Ip(), ctx.Request().Header("User-Agent"),
	)

	return responses.SuccessResponse(ctx, "Consent screen prepared", consentScreen)
}

// ProcessConsent processes the user's consent response
// @Summary Process OAuth2 consent response
// @Description Process user's consent decision for OAuth2 authorization
// @Tags OAuth2
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body requests.OAuthConsentRequest true "Consent response data"
// @Success 200 {object} responses.ApiResponse{data=services.ConsentResponse}
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /oauth/consent/process [post]
func (c *OAuthController) ProcessConsent(ctx http.Context) http.Response {
	var req requests.OAuthConsentRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// Get authenticated user
	user := ctx.Value("user").(*models.User)

	// Process consent response
	consentResponse, err := c.consentService.ProcessConsentResponse(
		req.ConsentID, req.Granted, req.GrantedScopes,
		ctx.Request().Ip(), ctx.Request().Header("User-Agent"),
	)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to process consent", err.Error(), 500)
	}

	// Record analytics
	action := "consent_denied"
	if consentResponse.Granted {
		action = "consent_granted"
	}

	c.analyticsService.RecordAuthorizationEvent(
		action, "", user.ID, consentResponse.Granted, consentResponse.GrantedScopes,
		ctx.Request().Ip(), ctx.Request().Header("User-Agent"),
	)

	return responses.SuccessResponse(ctx, "Consent processed successfully", consentResponse)
}

// GetUserConsents retrieves all user consents for the authenticated user
// @Summary Get user OAuth2 consents
// @Description Get all OAuth2 consents for the authenticated user
// @Tags OAuth2
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} responses.ApiResponse{data=[]services.UserConsent}
// @Failure 401 {object} responses.ApiResponse
// @Router /oauth/consents [get]
func (c *OAuthController) GetUserConsents(ctx http.Context) http.Response {
	// Get authenticated user
	user := ctx.Value("user").(*models.User)

	consents, err := c.consentService.GetUserConsents(user.ID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to retrieve consents", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "User consents retrieved successfully", consents)
}

// RevokeConsent revokes a user's consent for a specific client
// @Summary Revoke OAuth2 consent
// @Description Revoke user's consent for a specific OAuth2 client
// @Tags OAuth2
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param client_id path string true "Client ID"
// @Success 200 {object} responses.ApiResponse
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /oauth/consents/{client_id} [delete]
func (c *OAuthController) RevokeConsent(ctx http.Context) http.Response {
	// Get authenticated user
	user := ctx.Value("user").(*models.User)

	clientID := ctx.Request().Input("client_id")
	if clientID == "" {
		return responses.CreateErrorResponse(ctx, "Missing parameter", "client_id is required", 400)
	}

	err := c.consentService.RevokeUserConsent(user.ID, clientID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to revoke consent", err.Error(), 500)
	}

	// Record analytics
	c.analyticsService.RecordAuthorizationEvent(
		"consent_revoked", clientID, user.ID, false, []string{},
		ctx.Request().Ip(), ctx.Request().Header("User-Agent"),
	)

	return responses.SuccessResponse(ctx, "Consent revoked successfully", nil)
}

// GetAnalytics returns OAuth2 analytics data
// @Summary Get OAuth2 analytics
// @Description Get comprehensive OAuth2 analytics and metrics
// @Tags OAuth2
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param type query string false "Analytics type (token, client, user, system)" default(token)
// @Param range query string false "Time range (1h, 24h, 7d, 30d, 90d)" default(24h)
// @Param id query string false "Specific ID for client or user analytics"
// @Success 200 {object} responses.ApiResponse
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /oauth/analytics [get]
func (c *OAuthController) GetAnalytics(ctx http.Context) http.Response {
	analyticsType := ctx.Request().Input("type", "token")
	timeRange := ctx.Request().Input("range", "24h")
	id := ctx.Request().Input("id")

	var data interface{}
	var err error

	switch analyticsType {
	case "token":
		data, err = c.analyticsService.GetTokenUsageMetrics(timeRange)
	case "client":
		if id == "" {
			return responses.CreateErrorResponse(ctx, "Missing parameter", "id is required for client analytics", 400)
		}
		data, err = c.analyticsService.GetClientMetrics(id, timeRange)
	case "user":
		if id == "" {
			return responses.CreateErrorResponse(ctx, "Missing parameter", "id is required for user analytics", 400)
		}
		data, err = c.analyticsService.GetUserMetrics(id, timeRange)
	case "system":
		data, err = c.analyticsService.GetSystemMetrics()
	default:
		return responses.CreateErrorResponse(ctx, "Invalid analytics type", "Supported types: token, client, user, system", 400)
	}

	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to retrieve analytics", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Analytics retrieved successfully", data)
}

// PushedAuthorizationRequest handles PAR requests (RFC 9126)
// @Summary Pushed Authorization Request endpoint
// @Description Handle Pushed Authorization Requests according to RFC 9126
// @Tags OAuth2
// @Accept application/x-www-form-urlencoded
// @Produce json
// @Param client_id formData string true "OAuth client ID"
// @Param client_secret formData string false "OAuth client secret (for confidential clients)"
// @Param response_type formData string true "OAuth response type"
// @Param redirect_uri formData string true "Redirect URI"
// @Param scope formData string false "Requested scopes"
// @Param state formData string false "State parameter"
// @Param code_challenge formData string false "PKCE code challenge"
// @Param code_challenge_method formData string false "PKCE code challenge method"
// @Success 201 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /oauth/par [post]
func (c *OAuthController) PushedAuthorizationRequest(ctx http.Context) http.Response {
	// Parse form data
	clientID := ctx.Request().Input("client_id")
	clientSecret := ctx.Request().Input("client_secret", "")

	if clientID == "" {
		return responses.CreateErrorResponse(ctx, "Invalid request", "client_id is required", 400)
	}

	// Validate client authentication
	client, err := c.oauthService.GetClient(clientID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid client", err.Error(), 401)
	}

	// For confidential clients, validate the secret
	if client.IsConfidential() {
		if clientSecret == "" || client.Secret == nil || *client.Secret != clientSecret {
			return responses.CreateErrorResponse(ctx, "Invalid client", "Client authentication failed", 401)
		}
	}

	// Collect all authorization parameters
	params := map[string]string{
		"client_id":     clientID,
		"response_type": ctx.Request().Input("response_type"),
		"redirect_uri":  ctx.Request().Input("redirect_uri"),
		"scope":         ctx.Request().Input("scope", ""),
		"state":         ctx.Request().Input("state", ""),
	}

	// Add PKCE parameters if present
	if codeChallenge := ctx.Request().Input("code_challenge"); codeChallenge != "" {
		params["code_challenge"] = codeChallenge
		params["code_challenge_method"] = ctx.Request().Input("code_challenge_method", "S256")
	}

	// Add any additional parameters
	for key, value := range ctx.Request().All() {
		if stringValue, ok := value.(string); ok && params[key] == "" {
			// Only add if not already set and has a value
			params[key] = stringValue
		}
	}

	// Create PAR request
	parRequest, err := c.oauthService.CreatePushedAuthorizationRequest(clientID, params)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "PAR request failed", err.Error(), 400)
	}

	// Return response according to RFC 9126
	response := map[string]interface{}{
		"request_uri": parRequest.RequestURI,
		"expires_in":  int(parRequest.ExpiresAt.Sub(time.Now()).Seconds()),
	}

	return responses.SuccessResponse(ctx, "PAR request created successfully", response)
}

// GetResourceServers returns registered resource servers
// @Summary Get registered resource servers
// @Description Returns list of registered OAuth2 resource servers for Resource Indicators
// @Tags OAuth2
// @Accept json
// @Produce json
// @Success 200 {object} responses.ApiResponse{data=[]services.ResourceServer}
// @Failure 500 {object} responses.ApiResponse
// @Router /oauth/resources [get]
func (c *OAuthController) GetResourceServers(ctx http.Context) http.Response {
	resourceServers, err := c.resourceIndicatorsService.GetResourceServers()
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to get resource servers", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Resource servers retrieved successfully", resourceServers)
}

// RegisterResourceServer registers a new resource server
// @Summary Register OAuth2 resource server
// @Description Register a new OAuth2 resource server for Resource Indicators
// @Tags OAuth2
// @Accept json
// @Produce json
// @Param request body services.ResourceServer true "Resource server data"
// @Success 201 {object} responses.ApiResponse
// @Failure 400 {object} responses.ApiResponse
// @Failure 500 {object} responses.ApiResponse
// @Router /oauth/resources [post]
func (c *OAuthController) RegisterResourceServer(ctx http.Context) http.Response {
	var resourceServer services.ResourceServer
	if err := ctx.Request().Bind(&resourceServer); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	if err := c.resourceIndicatorsService.RegisterResourceServer(&resourceServer); err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to register resource server", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Resource server registered successfully", map[string]interface{}{
		"id":  resourceServer.ID,
		"uri": resourceServer.URI,
	})
}

// ProcessResourceAuthorization processes authorization with resource indicators
// @Summary Process resource authorization
// @Description Process OAuth2 authorization request with resource indicators (RFC 8707)
// @Tags OAuth2
// @Accept json
// @Produce json
// @Param request body services.ResourceAuthorizationRequest true "Resource authorization request"
// @Success 200 {object} responses.ApiResponse{data=services.ResourceAuthorizationResult}
// @Failure 400 {object} responses.ApiResponse
// @Failure 500 {object} responses.ApiResponse
// @Router /oauth/authorize/resources [post]
func (c *OAuthController) ProcessResourceAuthorization(ctx http.Context) http.Response {
	var request services.ResourceAuthorizationRequest
	if err := ctx.Request().Bind(&request); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// Set request timestamp
	request.RequestedAt = time.Now()

	// Add request context
	request.Context = map[string]interface{}{
		"ip_address": ctx.Request().Ip(),
		"user_agent": ctx.Request().Header("User-Agent", ""),
		"origin":     ctx.Request().Header("Origin", ""),
	}

	result, err := c.resourceIndicatorsService.ProcessResourceAuthorizationRequest(&request)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Resource authorization failed", err.Error(), 400)
	}

	return responses.SuccessResponse(ctx, "Resource authorization processed", result)
}

// ValidateTokenBinding validates token binding for a request
// @Summary Validate token binding
// @Description Validate token binding according to RFC 8473
// @Tags OAuth2
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Success 200 {object} responses.ApiResponse{data=services.TokenBindingValidationResult}
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /oauth/token-binding/validate [post]
func (c *OAuthController) ValidateTokenBinding(ctx http.Context) http.Response {
	// Extract token from Authorization header
	authHeader := ctx.Request().Header("Authorization", "")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return responses.CreateErrorResponse(ctx, "Invalid authorization header", "Bearer token required", 401)
	}

	tokenID := strings.TrimPrefix(authHeader, "Bearer ")

	// Extract token binding information from request
	bindingInfo, err := c.tokenBindingService.ExtractTokenBindingInfo(ctx.Request().Origin())
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to extract token binding info", err.Error(), 400)
	}

	// Validate token binding
	result, err := c.tokenBindingService.ValidateTokenBinding(tokenID, bindingInfo)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Token binding validation failed", err.Error(), 400)
	}

	return responses.SuccessResponse(ctx, "Token binding validation completed", result)
}

// GetTokenBindingInfo extracts token binding information from request
// @Summary Get token binding information
// @Description Extract token binding information from HTTP request
// @Tags OAuth2
// @Accept json
// @Produce json
// @Success 200 {object} responses.ApiResponse{data=services.TokenBindingInfo}
// @Failure 500 {object} responses.ApiResponse
// @Router /oauth/token-binding/info [get]
func (c *OAuthController) GetTokenBindingInfo(ctx http.Context) http.Response {
	bindingInfo, err := c.tokenBindingService.ExtractTokenBindingInfo(ctx.Request().Origin())
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to extract token binding info", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Token binding information extracted", bindingInfo)
}
