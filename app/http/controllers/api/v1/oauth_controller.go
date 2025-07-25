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
	oauthService *services.OAuthService
	authService  *services.AuthService
}

// NewOAuthController creates a new OAuth2 controller
func NewOAuthController() *OAuthController {
	return &OAuthController{
		oauthService: services.NewOAuthService(),
		authService:  services.NewAuthService(),
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
// @Description Handle OAuth2 token requests (password, client_credentials, authorization_code, refresh_token grants)
// @Tags OAuth2
// @Accept json
// @Produce json
// @Param request body requests.OAuthTokenRequest true "Token request data"
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /oauth/token [post]
func (c *OAuthController) Token(ctx http.Context) http.Response {
	var req requests.OAuthTokenRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	var accessToken *models.OAuthAccessToken
	var refreshToken *models.OAuthRefreshToken
	var err error

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

	response := map[string]interface{}{
		"access_token":  accessToken.ID,
		"token_type":    "Bearer",
		"expires_in":    facades.Config().GetInt("oauth.access_token_ttl", 60) * 60, // Convert to seconds
		"scope":         c.oauthService.FormatScopes(scopes),
		"refresh_token": refreshToken.ID,
	}

	return responses.SuccessResponse(ctx, "Token generated successfully", response)
}

// Authorize handles OAuth2 authorization requests
// @Summary OAuth2 authorization endpoint
// @Description Handle OAuth2 authorization requests
// @Tags OAuth2
// @Accept json
// @Produce json
// @Param request body requests.OAuthAuthorizationRequest true "Authorization request data"
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
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

	// Create authorization code with PKCE support if provided
	var authCode *models.OAuthAuthCode
	expiresAt := time.Now().Add(time.Duration(facades.Config().GetInt("oauth.auth_code_ttl", 10)) * time.Minute)

	if req.CodeChallenge != "" && req.CodeChallengeMethod != "" {
		// Validate PKCE parameters
		if req.CodeChallengeMethod != "S256" && req.CodeChallengeMethod != "plain" {
			return responses.CreateErrorResponse(ctx, "Invalid code challenge method", "Only S256 and plain methods are supported", 400)
		}

		authCode, err = c.oauthService.CreateAuthCodeWithPKCE(user.ID, client.ID, scopes, expiresAt, req.CodeChallenge, req.CodeChallengeMethod)
	} else {
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

// IntrospectToken handles OAuth2 token introspection
// @Summary OAuth2 token introspection
// @Description Introspect an OAuth2 token
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

	// Try to validate as access token first
	accessToken, err := c.oauthService.ValidateAccessToken(req.Token)
	if err == nil {
		user := accessToken.GetUser()
		response := map[string]interface{}{
			"active":     true,
			"scope":      c.oauthService.FormatScopes(accessToken.GetScopes()),
			"client_id":  accessToken.ClientID,
			"username":   user.Email,
			"token_type": "access_token",
		}
		return responses.SuccessResponse(ctx, "Token introspection successful", response)
	}

	// Try to validate as refresh token
	refreshToken, err := c.oauthService.ValidateRefreshToken(req.Token)
	if err == nil {
		user := refreshToken.GetUser()
		response := map[string]interface{}{
			"active":     true,
			"scope":      c.oauthService.FormatScopes(refreshToken.GetAccessToken().GetScopes()),
			"client_id":  refreshToken.GetAccessToken().ClientID,
			"username":   user.Email,
			"token_type": "refresh_token",
		}
		return responses.SuccessResponse(ctx, "Token introspection successful", response)
	}

	// Token is invalid
	response := map[string]interface{}{
		"active": false,
	}

	return responses.SuccessResponse(ctx, "Token introspection successful", response)
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
// @Description Provides OAuth2/OIDC discovery information
// @Tags OAuth2
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /.well-known/oauth-authorization-server [get]
func (c *OAuthController) Discovery(ctx http.Context) http.Response {
	baseURL := facades.Config().GetString("app.url")

	metadata := map[string]interface{}{
		"issuer":                        baseURL,
		"authorization_endpoint":        baseURL + "/oauth/authorize",
		"token_endpoint":                baseURL + "/api/v1/oauth/token",
		"userinfo_endpoint":             baseURL + "/api/v1/oauth/userinfo",
		"jwks_uri":                      baseURL + "/api/v1/oauth/jwks",
		"introspection_endpoint":        baseURL + "/api/v1/oauth/introspect",
		"revocation_endpoint":           baseURL + "/api/v1/oauth/revoke",
		"device_authorization_endpoint": baseURL + "/api/v1/oauth/device",
		"registration_endpoint":         baseURL + "/api/v1/oauth/clients",

		// Supported response types
		"response_types_supported": []string{
			"code",
			"token",
			"id_token",
			"code token",
			"code id_token",
			"token id_token",
			"code token id_token",
		},

		// Supported grant types
		"grant_types_supported": []string{
			"authorization_code",
			"client_credentials",
			"password",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code",
			"urn:ietf:params:oauth:grant-type:token-exchange",
		},

		// Supported scopes
		"scopes_supported": facades.Config().Get("oauth.allowed_scopes"),

		// Supported client authentication methods
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
			"none",
		},

		// PKCE support
		"code_challenge_methods_supported": []string{
			"S256",
			"plain",
		},

		// OpenID Connect specific
		"subject_types_supported": []string{
			"public",
		},

		"id_token_signing_alg_values_supported": []string{
			"RS256",
			"HS256",
		},

		"claims_supported": []string{
			"sub",
			"iss",
			"aud",
			"exp",
			"iat",
			"name",
			"email",
			"email_verified",
			"picture",
			"locale",
		},

		// Additional metadata
		"service_documentation": baseURL + "/docs/oauth2",
		"ui_locales_supported":  []string{"en"},
		"op_policy_uri":         baseURL + "/privacy",
		"op_tos_uri":            baseURL + "/terms",

		// Security features
		"require_request_uri_registration": false,
		"request_parameter_supported":      true,
		"request_uri_parameter_supported":  true,
		"require_signed_request_object":    false,

		// Token endpoint configuration
		"token_endpoint_auth_signing_alg_values_supported": []string{
			"RS256",
			"HS256",
		},

		// Revocation endpoint configuration
		"revocation_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
			"none",
		},

		// Introspection endpoint configuration
		"introspection_endpoint_auth_methods_supported": []string{
			"client_secret_basic",
			"client_secret_post",
		},
	}

	return ctx.Response().Json(200, metadata)
}

// UserInfo provides user information for OpenID Connect
// @Summary OpenID Connect UserInfo endpoint
// @Description Get user information using access token
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
		return responses.CreateErrorResponse(ctx, "Missing authorization header", "Bearer token required", 401)
	}

	// Extract token from "Bearer <token>"
	tokenParts := strings.Fields(authHeader)
	if len(tokenParts) != 2 || tokenParts[0] != "Bearer" {
		return responses.CreateErrorResponse(ctx, "Invalid authorization header", "Bearer token required", 401)
	}

	tokenID := tokenParts[1]

	// Validate the access token
	var accessToken models.OAuthAccessToken
	err := facades.Orm().Query().Where("id", tokenID).Where("revoked", false).First(&accessToken)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid access token", "Token not found or revoked", 401)
	}

	// Check if token is expired (tokens expire based on TTL configuration)
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

	// Build user info response based on granted scopes
	userInfo := map[string]interface{}{
		"sub": user.ID,
	}

	// Add claims based on scopes
	for _, scope := range scopes {
		switch scope {
		case "profile", "openid":
			userInfo["name"] = user.Name
			if user.Avatar != "" {
				userInfo["picture"] = user.Avatar
			}
			userInfo["locale"] = "en"
		case "email":
			userInfo["email"] = user.Email
			userInfo["email_verified"] = true
		}
	}

	return ctx.Response().Json(200, userInfo)
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
	// For now, return empty key set - implement when JWT signing is added
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{},
	}

	// TODO: Add actual public keys when JWT signing is implemented
	// This would include RSA/ECDSA public keys used for signing tokens

	return ctx.Response().Json(200, jwks)
}
