package v1

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
)

type OIDCController struct {
	oidcService  *services.OIDCService
	oauthService *services.OAuthService
	authService  *services.AuthService
}

// NewOIDCController creates a new OIDC controller
func NewOIDCController() *OIDCController {
	return &OIDCController{
		oidcService:  services.NewOIDCService(),
		oauthService: services.NewOAuthService(),
		authService:  services.NewAuthService(),
	}
}

// Discovery handles OpenID Connect discovery endpoint
// @Summary OpenID Connect discovery endpoint
// @Description Returns the OpenID Connect discovery document
// @Tags OIDC
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /.well-known/openid_configuration [get]
func (c *OIDCController) Discovery(ctx http.Context) http.Response {
	discoveryDoc := c.oidcService.GetDiscoveryDocument()
	return ctx.Response().Success().Json(discoveryDoc)
}

// JWKS handles JSON Web Key Set endpoint
// @Summary JSON Web Key Set endpoint
// @Description Returns the JSON Web Key Set for token validation
// @Tags OIDC
// @Accept json
// @Produce json
// @Success 200 {object} services.JWKS
// @Router /.well-known/oauth2/jwks [get]
func (c *OIDCController) JWKS(ctx http.Context) http.Response {
	jwks := c.oidcService.GetJWKS()
	return ctx.Response().Success().Json(jwks)
}

// UserInfo handles userinfo endpoint
// @Summary Userinfo endpoint
// @Description Returns user information based on the access token
// @Tags OIDC
// @Accept json
// @Produce json
// @Security BearerAuth
// @Success 200 {object} services.UserInfoClaims
// @Failure 401 {object} responses.ApiResponse
// @Router /.well-known/oauth2/userinfo [get]
func (c *OIDCController) UserInfo(ctx http.Context) http.Response {
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
	accessToken, err := c.oauthService.ValidateAccessToken(token)
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

	// Generate userinfo token
	userinfoToken, err := c.oidcService.GenerateUserInfoToken(user, accessToken.GetScopes())
	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error":             "server_error",
			"error_description": "Failed to generate userinfo token",
		})
	}

	// Log OIDC event
	c.oidcService.LogOIDCEvent("userinfo_requested", accessToken.ClientID, user.ID, map[string]interface{}{
		"scopes": accessToken.GetScopes(),
	})

	// Return userinfo as JSON (not JWT)
	userinfoClaims := &services.UserInfoClaims{}
	// Parse the JWT to get claims
	parsedToken, err := c.oidcService.ValidateIDToken(userinfoToken, "")
	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error":             "server_error",
			"error_description": "Failed to parse userinfo token",
		})
	}

	// Convert IDTokenClaims to UserInfoClaims
	userinfoClaims.RegisteredClaims.Subject = parsedToken.Subject
	userinfoClaims.RegisteredClaims.Issuer = parsedToken.Issuer
	userinfoClaims.Name = parsedToken.Name
	userinfoClaims.GivenName = parsedToken.GivenName
	userinfoClaims.FamilyName = parsedToken.FamilyName
	userinfoClaims.MiddleName = parsedToken.MiddleName
	userinfoClaims.Nickname = parsedToken.Nickname
	userinfoClaims.PreferredUsername = parsedToken.PreferredUsername
	userinfoClaims.Profile = parsedToken.Profile
	userinfoClaims.Picture = parsedToken.Picture
	userinfoClaims.Website = parsedToken.Website
	userinfoClaims.Email = parsedToken.Email
	userinfoClaims.EmailVerified = parsedToken.EmailVerified
	userinfoClaims.Gender = parsedToken.Gender
	userinfoClaims.Birthdate = parsedToken.Birthdate
	userinfoClaims.Zoneinfo = parsedToken.Zoneinfo
	userinfoClaims.Locale = parsedToken.Locale
	userinfoClaims.PhoneNumber = parsedToken.PhoneNumber
	userinfoClaims.PhoneNumberVerified = parsedToken.PhoneNumberVerified
	userinfoClaims.Address = parsedToken.Address
	userinfoClaims.UpdatedAt = parsedToken.UpdatedAt

	return ctx.Response().Success().Json(userinfoClaims)
}

// EndSession handles end session endpoint
// @Summary End session endpoint
// @Description Handles OpenID Connect end session requests
// @Tags OIDC
// @Accept json
// @Produce json
// @Param id_token_hint query string false "ID token hint"
// @Param post_logout_redirect_uri query string false "Post logout redirect URI"
// @Param state query string false "State parameter"
// @Success 200 {object} responses.ApiResponse
// @Router /.well-known/oauth2/end_session [get]
func (c *OIDCController) EndSession(ctx http.Context) http.Response {
	idTokenHint := ctx.Request().Input("id_token_hint")
	postLogoutRedirectURI := ctx.Request().Input("post_logout_redirect_uri")
	state := ctx.Request().Input("state")

	// Validate ID token hint if provided
	if idTokenHint != "" {
		_, err := c.oidcService.ValidateIDToken(idTokenHint, "")
		if err != nil {
			return ctx.Response().Status(400).Json(http.Json{
				"error":             "invalid_request",
				"error_description": "Invalid id_token_hint",
			})
		}
	}

	// Log OIDC event
	c.oidcService.LogOIDCEvent("end_session_requested", "", "", map[string]interface{}{
		"post_logout_redirect_uri": postLogoutRedirectURI,
		"state":                    state,
	})

	// Build redirect URL if post_logout_redirect_uri is provided
	if postLogoutRedirectURI != "" {
		redirectURL := postLogoutRedirectURI
		if state != "" {
			if strings.Contains(redirectURL, "?") {
				redirectURL += "&state=" + state
			} else {
				redirectURL += "?state=" + state
			}
		}
		return ctx.Response().Redirect(302, redirectURL)
	}

	return responses.SuccessResponse(ctx, "Session ended successfully", nil)
}

// CheckSession handles check session iframe endpoint
// @Summary Check session iframe endpoint
// @Description Returns check session iframe content
// @Tags OIDC
// @Accept json
// @Produce html
// @Success 200 {string} string
// @Router /.well-known/oauth2/check_session [get]
func (c *OIDCController) CheckSession(ctx http.Context) http.Response {
	// This endpoint is used for session management in SPAs
	// It returns an HTML iframe that can be used to check session status
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>Check Session</title>
</head>
<body>
    <script>
        // Check session implementation
        // This is a basic implementation - in production, you would implement
        // proper session checking logic
        window.parent.postMessage({
            type: 'session_check',
            timestamp: new Date().getTime()
        }, '*');
    </script>
</body>
</html>`

	return ctx.Response().Success().String(html)
}

// Authorize handles OIDC authorization endpoint
// @Summary OIDC authorization endpoint
// @Description Handles OpenID Connect authorization requests
// @Tags OIDC
// @Accept json
// @Produce json
// @Param response_type query string true "Response type"
// @Param client_id query string true "Client ID"
// @Param redirect_uri query string true "Redirect URI"
// @Param scope query string false "Scopes"
// @Param state query string false "State parameter"
// @Param nonce query string false "Nonce parameter"
// @Param code_challenge query string false "Code challenge (PKCE)"
// @Param code_challenge_method query string false "Code challenge method"
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Router /.well-known/oauth2/authorize [get]
func (c *OIDCController) Authorize(ctx http.Context) http.Response {
	responseType := ctx.Request().Input("response_type")
	clientID := ctx.Request().Input("client_id")
	redirectURI := ctx.Request().Input("redirect_uri")
	scope := ctx.Request().Input("scope")
	state := ctx.Request().Input("state")
	nonce := ctx.Request().Input("nonce")
	codeChallenge := ctx.Request().Input("code_challenge")
	codeChallengeMethod := ctx.Request().Input("code_challenge_method")

	// Validate required parameters
	if responseType == "" || clientID == "" || redirectURI == "" {
		return ctx.Response().Status(400).Json(http.Json{
			"error":             "invalid_request",
			"error_description": "Missing required parameters",
		})
	}

	// Validate response type
	if responseType != "code" && responseType != "token" && responseType != "id_token" {
		return ctx.Response().Status(400).Json(http.Json{
			"error":             "unsupported_response_type",
			"error_description": "Unsupported response type",
		})
	}

	// Validate client
	client, err := c.oauthService.GetClient(clientID)
	if err != nil {
		return ctx.Response().Status(400).Json(http.Json{
			"error":             "invalid_client",
			"error_description": "Invalid client",
		})
	}

	// Validate redirect URI
	if !c.validateRedirectURI(client, redirectURI) {
		return ctx.Response().Status(400).Json(http.Json{
			"error":             "invalid_request",
			"error_description": "Invalid redirect URI",
		})
	}

	// Parse scopes
	scopes := c.oauthService.ParseScopes(scope)
	if len(scopes) == 0 {
		scopes = facades.Config().Get("oauth.default_scopes").([]string)
	}

	// Validate scopes
	if !c.oidcService.ValidateScopes(scopes) {
		return ctx.Response().Status(400).Json(http.Json{
			"error":             "invalid_scope",
			"error_description": "Invalid scope",
		})
	}

	// Check if user is authenticated
	user := ctx.Value("user")
	if user == nil {
		// User is not authenticated, redirect to login
		loginURL := "/login?redirect_uri=" + redirectURI + "&client_id=" + clientID + "&response_type=" + responseType
		if scope != "" {
			loginURL += "&scope=" + scope
		}
		if state != "" {
			loginURL += "&state=" + state
		}
		if nonce != "" {
			loginURL += "&nonce=" + nonce
		}
		return ctx.Response().Redirect(302, loginURL)
	}

	userModel := user.(*models.User)

	// Generate authorization code
	authCode, err := c.oauthService.CreateAuthCodeWithPKCE(userModel.ID, client.ID, scopes, time.Now().Add(10*time.Minute), codeChallenge, codeChallengeMethod)
	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error":             "server_error",
			"error_description": "Failed to create authorization code",
		})
	}

	// Build redirect URL
	redirectURL := redirectURI
	if strings.Contains(redirectURL, "?") {
		redirectURL += "&code=" + authCode.ID
	} else {
		redirectURL += "?code=" + authCode.ID
	}

	if state != "" {
		redirectURL += "&state=" + state
	}

	// Log OIDC event
	c.oidcService.LogOIDCEvent("authorization_granted", client.ID, userModel.ID, map[string]interface{}{
		"response_type": responseType,
		"scopes":        scopes,
		"nonce":         nonce,
	})

	return ctx.Response().Redirect(302, redirectURL)
}

// Token handles OIDC token endpoint
// @Summary OIDC token endpoint
// @Description Handles OpenID Connect token requests
// @Tags OIDC
// @Accept json
// @Produce json
// @Param grant_type formData string true "Grant type"
// @Param client_id formData string true "Client ID"
// @Param client_secret formData string false "Client secret"
// @Param code formData string false "Authorization code"
// @Param redirect_uri formData string false "Redirect URI"
// @Param code_verifier formData string false "Code verifier (PKCE)"
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Router /.well-known/oauth2/token [post]
func (c *OIDCController) Token(ctx http.Context) http.Response {
	grantType := ctx.Request().Input("grant_type")
	clientID := ctx.Request().Input("client_id")
	clientSecret := ctx.Request().Input("client_secret")
	code := ctx.Request().Input("code")
	redirectURI := ctx.Request().Input("redirect_uri")
	codeVerifier := ctx.Request().Input("code_verifier")

	// Validate required parameters
	if grantType == "" || clientID == "" {
		return ctx.Response().Status(400).Json(http.Json{
			"error":             "invalid_request",
			"error_description": "Missing required parameters",
		})
	}

	// Handle authorization code grant
	if grantType == "authorization_code" {
		if code == "" {
			return ctx.Response().Status(400).Json(http.Json{
				"error":             "invalid_request",
				"error_description": "Missing authorization code",
			})
		}

		// Validate client
		client, err := c.oauthService.ValidateClient(clientID, clientSecret)
		if err != nil {
			return ctx.Response().Status(401).Json(http.Json{
				"error":             "invalid_client",
				"error_description": "Invalid client credentials",
			})
		}

		// Validate authorization code
		authCode, err := c.oauthService.ValidateAuthCode(code)
		if err != nil {
			return ctx.Response().Status(400).Json(http.Json{
				"error":             "invalid_grant",
				"error_description": "Invalid authorization code",
			})
		}

		// Check if auth code belongs to the client
		if authCode.ClientID != client.ID {
			return ctx.Response().Status(400).Json(http.Json{
				"error":             "invalid_grant",
				"error_description": "Authorization code does not belong to client",
			})
		}

		// Validate redirect URI
		if authCode.GetClient().GetRedirectURIs()[0] != redirectURI {
			return ctx.Response().Status(400).Json(http.Json{
				"error":             "invalid_grant",
				"error_description": "Redirect URI mismatch",
			})
		}

		// Validate PKCE if code challenge is present
		if authCode.CodeChallenge != nil && *authCode.CodeChallenge != "" {
			if codeVerifier == "" {
				return ctx.Response().Status(400).Json(http.Json{
					"error":             "invalid_request",
					"error_description": "Code verifier required for PKCE",
				})
			}

			if !c.oauthService.ValidatePKCE(codeVerifier, *authCode.CodeChallenge, *authCode.CodeChallengeMethod) {
				return ctx.Response().Status(400).Json(http.Json{
					"error":             "invalid_grant",
					"error_description": "Invalid code verifier",
				})
			}
		}

		// Get user
		user := authCode.GetUser()
		if user == nil {
			return ctx.Response().Status(400).Json(http.Json{
				"error":             "invalid_grant",
				"error_description": "Invalid authorization code",
			})
		}

		// Generate token pair
		accessToken, refreshToken, err := c.oauthService.GenerateTokenPair(&user.ID, client.ID, authCode.GetScopes(), nil)
		if err != nil {
			return ctx.Response().Status(500).Json(http.Json{
				"error":             "server_error",
				"error_description": "Failed to generate tokens",
			})
		}

		// Generate ID token
		idToken, err := c.oidcService.GenerateIDToken(user, client.ID, authCode.GetScopes(), "", accessToken.ID, authCode.ID, time.Now().Unix())
		if err != nil {
			return ctx.Response().Status(500).Json(http.Json{
				"error":             "server_error",
				"error_description": "Failed to generate ID token",
			})
		}

		// Revoke the authorization code
		c.oauthService.RevokeAuthCode(authCode.ID)

		// Log OIDC event
		c.oidcService.LogOIDCEvent("token_issued", client.ID, user.ID, map[string]interface{}{
			"grant_type": "authorization_code",
			"scopes":     authCode.GetScopes(),
		})

		response := map[string]interface{}{
			"access_token":  accessToken.ID,
			"token_type":    "Bearer",
			"expires_in":    facades.Config().GetInt("oauth.access_token_ttl", 60) * 60,
			"scope":         c.oauthService.FormatScopes(authCode.GetScopes()),
			"refresh_token": refreshToken.ID,
			"id_token":      idToken,
		}

		return ctx.Response().Success().Json(response)
	}

	return ctx.Response().Status(400).Json(http.Json{
		"error":             "unsupported_grant_type",
		"error_description": "Unsupported grant type",
	})
}

// validateRedirectURI validates that the redirect URI is allowed for the client
func (c *OIDCController) validateRedirectURI(client *models.OAuthClient, redirectURI string) bool {
	allowedURIs := client.GetRedirectURIs()
	for _, uri := range allowedURIs {
		if uri == redirectURI {
			return true
		}
	}
	return false
}

// IntrospectToken handles token introspection endpoint
// @Summary Token introspection endpoint
// @Description Introspects a token and returns its details
// @Tags OIDC
// @Accept json
// @Produce json
// @Param token formData string true "Token to introspect"
// @Param token_type_hint formData string false "Token type hint"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} responses.ApiResponse
// @Router /.well-known/oauth2/introspect [post]
func (c *OIDCController) IntrospectToken(ctx http.Context) http.Response {
	token := ctx.Request().Input("token")
	tokenTypeHint := ctx.Request().Input("token_type_hint")

	if token == "" {
		return ctx.Response().Status(400).Json(http.Json{
			"error":             "invalid_request",
			"error_description": "Token parameter is required",
		})
	}

	// Get client credentials from Authorization header
	authHeader := ctx.Request().Header("Authorization", "")
	clientID := ""
	clientSecret := ""

	if authHeader != "" && strings.HasPrefix(authHeader, "Basic ") {
		// Decode Basic auth
		encoded := strings.TrimPrefix(authHeader, "Basic ")
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				clientID = parts[0]
				clientSecret = parts[1]
			}
		}
	}

	if clientID == "" {
		clientID = ctx.Request().Input("client_id")
		clientSecret = ctx.Request().Input("client_secret")
	}

	if clientID == "" {
		return ctx.Response().Status(401).Json(http.Json{
			"error":             "invalid_client",
			"error_description": "Client authentication required",
		})
	}

	// Validate client
	_, err := c.oauthService.ValidateClient(clientID, clientSecret)
	if err != nil {
		return ctx.Response().Status(401).Json(http.Json{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
	}

	// Introspect token
	introspection, err := c.oidcService.IntrospectToken(token, clientID)
	if err != nil {
		return ctx.Response().Status(400).Json(http.Json{
			"error":             "invalid_request",
			"error_description": "Failed to introspect token",
		})
	}

	// Log OIDC event
	c.oidcService.LogOIDCEvent("token_introspected", clientID, "", map[string]interface{}{
		"token_type_hint": tokenTypeHint,
		"active":          introspection["active"],
	})

	return ctx.Response().Success().Json(introspection)
}

// RevokeToken handles token revocation endpoint
// @Summary Token revocation endpoint
// @Description Revokes a token
// @Tags OIDC
// @Accept json
// @Produce json
// @Param token formData string true "Token to revoke"
// @Param token_type_hint formData string false "Token type hint"
// @Success 200 {object} responses.ApiResponse
// @Failure 400 {object} responses.ApiResponse
// @Router /.well-known/oauth2/revoke [post]
func (c *OIDCController) RevokeToken(ctx http.Context) http.Response {
	token := ctx.Request().Input("token")
	tokenTypeHint := ctx.Request().Input("token_type_hint")

	if token == "" {
		return ctx.Response().Status(400).Json(http.Json{
			"error":             "invalid_request",
			"error_description": "Token parameter is required",
		})
	}

	// Get client credentials from Authorization header
	authHeader := ctx.Request().Header("Authorization", "")
	clientID := ""
	clientSecret := ""

	if authHeader != "" && strings.HasPrefix(authHeader, "Basic ") {
		// Decode Basic auth
		encoded := strings.TrimPrefix(authHeader, "Basic ")
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err == nil {
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) == 2 {
				clientID = parts[0]
				clientSecret = parts[1]
			}
		}
	}

	if clientID == "" {
		clientID = ctx.Request().Input("client_id")
		clientSecret = ctx.Request().Input("client_secret")
	}

	if clientID == "" {
		return ctx.Response().Status(401).Json(http.Json{
			"error":             "invalid_client",
			"error_description": "Client authentication required",
		})
	}

	// Validate client
	_, err := c.oauthService.ValidateClient(clientID, clientSecret)
	if err != nil {
		return ctx.Response().Status(401).Json(http.Json{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
	}

	// Revoke token
	err = c.oidcService.RevokeToken(token, clientID)
	if err != nil {
		// RFC 7009 says we should return 200 even if token doesn't exist
		// This prevents token enumeration attacks
	}

	// Log OIDC event
	c.oidcService.LogOIDCEvent("token_revoked", clientID, "", map[string]interface{}{
		"token_type_hint": tokenTypeHint,
	})

	return responses.SuccessResponse(ctx, "Token revoked successfully", nil)
}

// DeviceAuthorization handles device authorization endpoint
// @Summary Device authorization endpoint
// @Description Initiates device authorization flow
// @Tags OIDC
// @Accept json
// @Produce json
// @Param client_id formData string true "Client ID"
// @Param scope formData string false "Scopes"
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Router /.well-known/oauth2/device [post]
func (c *OIDCController) DeviceAuthorization(ctx http.Context) http.Response {
	clientID := ctx.Request().Input("client_id")
	scope := ctx.Request().Input("scope")

	if clientID == "" {
		return ctx.Response().Status(400).Json(http.Json{
			"error":             "invalid_request",
			"error_description": "Client ID is required",
		})
	}

	// Validate client
	client, err := c.oauthService.GetClient(clientID)
	if err != nil {
		return ctx.Response().Status(400).Json(http.Json{
			"error":             "invalid_client",
			"error_description": "Invalid client",
		})
	}

	// Parse scopes
	scopes := c.oauthService.ParseScopes(scope)
	if len(scopes) == 0 {
		scopes = c.oidcService.GetSupportedScopes()
	}

	// Validate scopes
	if !c.oidcService.ValidateScopes(scopes) {
		return ctx.Response().Status(400).Json(http.Json{
			"error":             "invalid_scope",
			"error_description": "Invalid scope",
		})
	}

	// Create device code
	deviceCodeExpiry := time.Now().Add(time.Duration(facades.Config().GetInt("oauth.device_code_ttl", 600)) * time.Second)
	deviceCode, err := c.oauthService.CreateDeviceCode(client.ID, scopes, deviceCodeExpiry)
	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error":             "server_error",
			"error_description": "Failed to create device code",
		})
	}

	// Log OIDC event
	c.oidcService.LogOIDCEvent("device_authorization_requested", client.ID, "", map[string]interface{}{
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

// DeviceToken handles device token endpoint
// @Summary Device token endpoint
// @Description Exchanges device code for tokens
// @Tags OIDC
// @Accept json
// @Produce json
// @Param device_code formData string true "Device code"
// @Param client_id formData string true "Client ID"
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Router /.well-known/oauth2/device/token [post]
func (c *OIDCController) DeviceToken(ctx http.Context) http.Response {
	deviceCode := ctx.Request().Input("device_code")
	clientID := ctx.Request().Input("client_id")

	if deviceCode == "" || clientID == "" {
		return ctx.Response().Status(400).Json(http.Json{
			"error":             "invalid_request",
			"error_description": "Device code and client ID are required",
		})
	}

	// Validate device code
	deviceCodeModel, err := c.oauthService.ValidateDeviceCode(deviceCode)
	if err != nil {
		return ctx.Response().Status(400).Json(http.Json{
			"error":             "authorization_pending",
			"error_description": "Authorization pending",
		})
	}

	// Check if device authorization is complete
	if !deviceCodeModel.IsAuthorized() {
		return ctx.Response().Status(400).Json(http.Json{
			"error":             "authorization_pending",
			"error_description": "User has not yet authorized the device",
		})
	}

	// Generate token pair
	accessToken, refreshToken, err := c.oauthService.GenerateTokenPair(
		deviceCodeModel.UserID,
		deviceCodeModel.ClientID,
		deviceCodeModel.GetScopes(),
		nil,
	)
	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error":             "server_error",
			"error_description": "Failed to generate tokens",
		})
	}

	// Generate ID token if openid scope is requested
	var idToken string
	scopes := deviceCodeModel.GetScopes()
	hasOpenIDScope := false
	for _, scope := range scopes {
		if scope == "openid" {
			hasOpenIDScope = true
			break
		}
	}

	if hasOpenIDScope && deviceCodeModel.UserID != nil {
		user := deviceCodeModel.GetUser()
		if user != nil {
			idToken, err = c.oidcService.GenerateIDToken(user, deviceCodeModel.ClientID, scopes, "", accessToken.ID, "", time.Now().Unix())
			if err != nil {
				return ctx.Response().Status(500).Json(http.Json{
					"error":             "server_error",
					"error_description": "Failed to generate ID token",
				})
			}
		}
	}

	// Revoke the device code
	c.oauthService.RevokeDeviceCode(deviceCodeModel.ID)

	// Log OIDC event
	if deviceCodeModel.UserID != nil {
		c.oidcService.LogOIDCEvent("device_token_generated", deviceCodeModel.ClientID, *deviceCodeModel.UserID, map[string]interface{}{
			"scopes": scopes,
		})
	}

	response := map[string]interface{}{
		"access_token":  accessToken.ID,
		"token_type":    "Bearer",
		"expires_in":    facades.Config().GetInt("oauth.access_token_ttl", 60) * 60,
		"scope":         c.oauthService.FormatScopes(scopes),
		"refresh_token": refreshToken.ID,
	}

	if idToken != "" {
		response["id_token"] = idToken
	}

	return responses.SuccessResponse(ctx, "Device token generated successfully", response)
}

// CompleteDeviceAuthorization completes device authorization
// @Summary Complete device authorization
// @Description Completes device authorization by providing user credentials
// @Tags OIDC
// @Accept json
// @Produce json
// @Param user_code formData string true "User code"
// @Param email formData string true "User email"
// @Param password formData string true "User password"
// @Success 200 {object} responses.ApiResponse
// @Failure 400 {object} responses.ApiResponse
// @Router /.well-known/oauth2/device/complete [post]
func (c *OIDCController) CompleteDeviceAuthorization(ctx http.Context) http.Response {
	userCode := ctx.Request().Input("user_code")
	email := ctx.Request().Input("email")
	password := ctx.Request().Input("password")

	if userCode == "" || email == "" || password == "" {
		return ctx.Response().Status(400).Json(http.Json{
			"error":             "invalid_request",
			"error_description": "User code, email, and password are required",
		})
	}

	// Validate user code
	deviceCode, err := c.oauthService.ValidateUserCode(userCode)
	if err != nil {
		return ctx.Response().Status(400).Json(http.Json{
			"error":             "invalid_request",
			"error_description": "Invalid user code",
		})
	}

	// Find user by email
	var user models.User
	err = facades.Orm().Query().Where("email", email).First(&user)
	if err != nil {
		return ctx.Response().Status(401).Json(http.Json{
			"error":             "invalid_grant",
			"error_description": "Invalid credentials",
		})
	}

	// Check if user is active
	if !user.IsActive {
		return ctx.Response().Status(401).Json(http.Json{
			"error":             "invalid_grant",
			"error_description": "Account is deactivated",
		})
	}

	// Verify password
	if !facades.Hash().Check(password, user.Password) {
		return ctx.Response().Status(401).Json(http.Json{
			"error":             "invalid_grant",
			"error_description": "Invalid credentials",
		})
	}

	// Complete device authorization
	err = c.oauthService.CompleteDeviceAuthorization(deviceCode.ID, user.ID)
	if err != nil {
		return ctx.Response().Status(500).Json(http.Json{
			"error":             "server_error",
			"error_description": "Failed to complete authorization",
		})
	}

	// Log OIDC event
	c.oidcService.LogOIDCEvent("device_authorization_completed", deviceCode.ClientID, user.ID, map[string]interface{}{
		"scopes": deviceCode.GetScopes(),
	})

	return responses.SuccessResponse(ctx, "Device authorization completed successfully", nil)
}
