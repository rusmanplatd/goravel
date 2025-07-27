package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
	"goravel/app/services"
)

type OAuthPlaygroundController struct {
	oauthService *services.OAuthService
}

// NewOAuthPlaygroundController creates a new OAuth playground controller
func NewOAuthPlaygroundController() *OAuthPlaygroundController {
	oauthService, err := services.NewOAuthService()
	if err != nil {
		facades.Log().Error("Failed to create OAuth service", map[string]interface{}{
			"error": err.Error(),
		})
		return nil
	}

	return &OAuthPlaygroundController{
		oauthService: oauthService,
	}
}

// Index displays the OAuth2 playground
func (c *OAuthPlaygroundController) Index(ctx http.Context) http.Response {
	// Get available scopes
	allowedScopes := facades.Config().Get("oauth.allowed_scopes").([]string)

	// Get sample clients for testing
	var clients []models.OAuthClient
	facades.Orm().Query().
		Where("name", "LIKE", "%Playground%").
		OrWhere("name", "LIKE", "%Test%").
		OrWhere("personal_access_client", true).
		Limit(10).
		Get(&clients)

	// Create default playground client if none exists
	if len(clients) == 0 {
		playgroundClient, err := c.oauthService.CreateClient(
			"OAuth2 Playground",
			nil,
			[]string{"http://localhost:8080/oauth/playground/callback", "https://oauth.pstmn.io/v1/callback"},
			false,
			false,
		)
		if err == nil {
			clients = append(clients, *playgroundClient)
		}
	}

	data := map[string]interface{}{
		"title":             "OAuth2 Playground",
		"clients":           clients,
		"allowedScopes":     allowedScopes,
		"scopeDescriptions": c.getScopeDescriptions(),
		"timestamp":         time.Now().Unix(),
		"grantTypes": []map[string]interface{}{
			{
				"value":       "authorization_code",
				"name":        "Authorization Code",
				"description": "Most secure flow for web applications",
			},
			{
				"value":       "client_credentials",
				"name":        "Client Credentials",
				"description": "For server-to-server authentication",
			},
			{
				"value":       "password",
				"name":        "Resource Owner Password",
				"description": "Direct username/password exchange (deprecated)",
			},
			{
				"value":       "urn:ietf:params:oauth:grant-type:device_code",
				"name":        "Device Authorization",
				"description": "For devices with limited input capabilities",
			},
		},
		"endpoints": map[string]string{
			"authorization": "/oauth/authorize",
			"token":         "/api/v1/oauth/token",
			"introspect":    "/api/v1/oauth/introspect",
			"revoke":        "/api/v1/oauth/revoke",
			"device":        "/api/v1/oauth/device",
			"userinfo":      "/api/v1/oauth/userinfo",
			"jwks":          "/api/v1/oauth/jwks",
			"discovery":     "/.well-known/oauth-authorization-server",
		},
	}

	return ctx.Response().View().Make("oauth/playground/index.tmpl", data)
}

// BuildAuthorizationURL builds an authorization URL for testing
func (c *OAuthPlaygroundController) BuildAuthorizationURL(ctx http.Context) http.Response {
	clientID := ctx.Request().Input("client_id")
	redirectURI := ctx.Request().Input("redirect_uri")
	scopes := ctx.Request().Input("scopes")
	state := ctx.Request().Input("state", "playground-state-"+fmt.Sprintf("%d", time.Now().Unix()))
	responseType := ctx.Request().Input("response_type", "code")

	// Build authorization URL
	baseURL := facades.Config().GetString("app.url", "http://localhost") + "/oauth/authorize"
	params := url.Values{}
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", scopes)
	params.Set("state", state)
	params.Set("response_type", responseType)

	// Add PKCE if requested
	if ctx.Request().Input("use_pkce") == "true" {
		codeVerifier := c.generateCodeVerifier()
		codeChallenge := c.generateCodeChallenge(codeVerifier)
		params.Set("code_challenge", codeChallenge)
		params.Set("code_challenge_method", "S256")

		// Store code verifier for later use (in a real app, use secure storage)
		facades.Cache().Put("playground_code_verifier_"+state, codeVerifier, 10*time.Minute)
	}

	authURL := baseURL + "?" + params.Encode()

	return ctx.Response().Json(200, map[string]interface{}{
		"success":           true,
		"authorization_url": authURL,
		"state":             state,
		"parameters":        params,
	})
}

// ExchangeCode exchanges authorization code for tokens
func (c *OAuthPlaygroundController) ExchangeCode(ctx http.Context) http.Response {
	code := ctx.Request().Input("code")
	clientID := ctx.Request().Input("client_id")
	clientSecret := ctx.Request().Input("client_secret")
	redirectURI := ctx.Request().Input("redirect_uri")
	state := ctx.Request().Input("state")

	// Prepare token request
	tokenURL := facades.Config().GetString("app.url", "http://localhost") + "/api/v1/oauth/token"
	params := map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"client_id":     clientID,
		"client_secret": clientSecret,
		"redirect_uri":  redirectURI,
	}

	// Add PKCE code verifier if it was used
	if state != "" {
		codeVerifier := facades.Cache().Get("playground_code_verifier_" + state)
		if codeVerifier != nil {
			params["code_verifier"] = codeVerifier.(string)
			facades.Cache().Forget("playground_code_verifier_" + state)
		}
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success":      true,
		"token_url":    tokenURL,
		"parameters":   params,
		"curl_command": c.buildCurlCommand(tokenURL, params),
	})
}

// TestEndpoint tests various OAuth2 endpoints
func (c *OAuthPlaygroundController) TestEndpoint(ctx http.Context) http.Response {
	endpoint := ctx.Request().Input("endpoint")
	accessToken := ctx.Request().Input("access_token")

	baseURL := facades.Config().GetString("app.url", "http://localhost")

	var testURL string
	var method string = "GET"
	var headers map[string]string = map[string]string{}

	switch endpoint {
	case "userinfo":
		testURL = baseURL + "/api/v1/oauth/userinfo"
		headers["Authorization"] = "Bearer " + accessToken
	case "introspect":
		testURL = baseURL + "/api/v1/oauth/introspect"
		method = "POST"
		headers["Authorization"] = "Bearer " + accessToken
	case "jwks":
		testURL = baseURL + "/api/v1/oauth/jwks"
	case "discovery":
		testURL = baseURL + "/.well-known/oauth-authorization-server"
	default:
		return ctx.Response().Json(400, map[string]interface{}{
			"success": false,
			"error":   "Unknown endpoint",
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success":      true,
		"test_url":     testURL,
		"method":       method,
		"headers":      headers,
		"curl_command": c.buildCurlCommandForEndpoint(method, testURL, headers),
	})
}

// Callback handles OAuth2 callback for playground testing
func (c *OAuthPlaygroundController) Callback(ctx http.Context) http.Response {
	code := ctx.Request().Query("code")
	state := ctx.Request().Query("state")
	errorParam := ctx.Request().Query("error")
	errorDescription := ctx.Request().Query("error_description")

	data := map[string]interface{}{
		"title":             "OAuth2 Playground - Callback",
		"code":              code,
		"state":             state,
		"error":             errorParam,
		"error_description": errorDescription,
		"success":           code != "" && errorParam == "",
	}

	return ctx.Response().View().Make("oauth/playground/callback.tmpl", data)
}

// Helper methods

func (c *OAuthPlaygroundController) getScopeDescriptions() map[string]map[string]interface{} {
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
	}
}

func (c *OAuthPlaygroundController) generateCodeVerifier() string {
	// Generate a cryptographically random code verifier
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

func (c *OAuthPlaygroundController) generateCodeChallenge(verifier string) string {
	// Create SHA256 hash of the code verifier
	hasher := sha256.New()
	hasher.Write([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))
}

func (c *OAuthPlaygroundController) buildCurlCommand(url string, params map[string]string) string {
	var formData []string
	for key, value := range params {
		formData = append(formData, fmt.Sprintf("%s=%s", key, value))
	}

	return fmt.Sprintf("curl -X POST '%s' \\\n  -H 'Content-Type: application/x-www-form-urlencoded' \\\n  -d '%s'",
		url, strings.Join(formData, "&"))
}

func (c *OAuthPlaygroundController) buildCurlCommandForEndpoint(method, url string, headers map[string]string) string {
	cmd := fmt.Sprintf("curl -X %s '%s'", method, url)

	for key, value := range headers {
		cmd += fmt.Sprintf(" \\\n  -H '%s: %s'", key, value)
	}

	return cmd
}
