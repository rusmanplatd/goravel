package services

import (
	"fmt"
	"net/url"
	"strings"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type OAuthPlaygroundService struct {
	oauthService *OAuthService
}

type PlaygroundConfig struct {
	AuthorizationEndpoint  string            `json:"authorization_endpoint"`
	TokenEndpoint          string            `json:"token_endpoint"`
	UserInfoEndpoint       string            `json:"userinfo_endpoint"`
	JWKSEndpoint           string            `json:"jwks_endpoint"`
	IntrospectionEndpoint  string            `json:"introspection_endpoint"`
	RevocationEndpoint     string            `json:"revocation_endpoint"`
	SupportedGrantTypes    []string          `json:"supported_grant_types"`
	SupportedScopes        []string          `json:"supported_scopes"`
	SupportedResponseTypes []string          `json:"supported_response_types"`
	DefaultClient          *PlaygroundClient `json:"default_client,omitempty"`
}

type PlaygroundClient struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	RedirectURIs []string `json:"redirect_uris"`
	Name         string   `json:"name"`
	Description  string   `json:"description"`
}

type PlaygroundRequest struct {
	Flow                string            `json:"flow"` // "authorization_code", "client_credentials", "password", etc.
	ClientID            string            `json:"client_id"`
	ClientSecret        string            `json:"client_secret,omitempty"`
	RedirectURI         string            `json:"redirect_uri,omitempty"`
	Scopes              []string          `json:"scopes"`
	Username            string            `json:"username,omitempty"`
	Password            string            `json:"password,omitempty"`
	State               string            `json:"state,omitempty"`
	Nonce               string            `json:"nonce,omitempty"`
	CodeChallenge       string            `json:"code_challenge,omitempty"`
	CodeChallengeMethod string            `json:"code_challenge_method,omitempty"`
	CustomParams        map[string]string `json:"custom_params,omitempty"`
}

type PlaygroundResponse struct {
	Step         int                    `json:"step"`
	StepName     string                 `json:"step_name"`
	Success      bool                   `json:"success"`
	Request      map[string]interface{} `json:"request"`
	Response     map[string]interface{} `json:"response"`
	NextStep     string                 `json:"next_step,omitempty"`
	Instructions string                 `json:"instructions,omitempty"`
	Error        string                 `json:"error,omitempty"`
	Timestamp    time.Time              `json:"timestamp"`
}

type PlaygroundSession struct {
	ID          string                 `json:"id"`
	Flow        string                 `json:"flow"`
	ClientID    string                 `json:"client_id"`
	Steps       []PlaygroundResponse   `json:"steps"`
	CurrentStep int                    `json:"current_step"`
	State       map[string]interface{} `json:"state"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
	ExpiresAt   time.Time              `json:"expires_at"`
}

func NewOAuthPlaygroundService() *OAuthPlaygroundService {
	return &OAuthPlaygroundService{
		oauthService: NewOAuthService(),
	}
}

// GetPlaygroundConfig returns the configuration for the OAuth2 playground
func (s *OAuthPlaygroundService) GetPlaygroundConfig() (*PlaygroundConfig, error) {
	if !facades.Config().GetBool("oauth.playground.enabled", false) {
		return nil, fmt.Errorf("OAuth2 playground is disabled")
	}

	baseURL := facades.Config().GetString("app.url")

	config := &PlaygroundConfig{
		AuthorizationEndpoint: baseURL + "/oauth/authorize",
		TokenEndpoint:         baseURL + "/api/v1/oauth/token",
		UserInfoEndpoint:      baseURL + "/api/v1/oauth/userinfo",
		JWKSEndpoint:          baseURL + "/api/v1/oauth/jwks",
		IntrospectionEndpoint: baseURL + "/api/v1/oauth/introspect",
		RevocationEndpoint:    baseURL + "/api/v1/oauth/revoke",
		SupportedGrantTypes: []string{
			"authorization_code",
			"client_credentials",
			"password",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code",
			"urn:ietf:params:oauth:grant-type:token-exchange",
		},
		SupportedScopes: facades.Config().Get("oauth.allowed_scopes").([]string),
		SupportedResponseTypes: []string{
			"code",
			"token",
			"id_token",
			"code token",
			"code id_token",
			"token id_token",
			"code token id_token",
		},
	}

	// Create or get default playground client
	if facades.Config().GetBool("oauth.playground.auto_create_client", true) {
		defaultClient, err := s.getOrCreatePlaygroundClient()
		if err != nil {
			facades.Log().Warning("Failed to create playground client", map[string]interface{}{
				"error": err.Error(),
			})
		} else {
			config.DefaultClient = defaultClient
		}
	}

	return config, nil
}

// StartPlaygroundSession starts a new OAuth2 playground session
func (s *OAuthPlaygroundService) StartPlaygroundSession(request *PlaygroundRequest) (*PlaygroundSession, error) {
	if !facades.Config().GetBool("oauth.playground.enabled", false) {
		return nil, fmt.Errorf("OAuth2 playground is disabled")
	}

	// Validate request
	if err := s.validatePlaygroundRequest(request); err != nil {
		return nil, fmt.Errorf("invalid playground request: %w", err)
	}

	// Create session
	session := &PlaygroundSession{
		ID:          s.generateSessionID(),
		Flow:        request.Flow,
		ClientID:    request.ClientID,
		Steps:       []PlaygroundResponse{},
		CurrentStep: 0,
		State:       make(map[string]interface{}),
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
		ExpiresAt:   time.Now().Add(2 * time.Hour), // 2 hour expiry
	}

	// Store initial request in state
	session.State["initial_request"] = request

	// Execute first step based on flow
	var firstStep *PlaygroundResponse
	var err error

	switch request.Flow {
	case "authorization_code":
		firstStep, err = s.executeAuthorizationCodeStep1(session, request)
	case "client_credentials":
		firstStep, err = s.executeClientCredentialsFlow(session, request)
	case "password":
		firstStep, err = s.executePasswordFlow(session, request)
	case "device_code":
		firstStep, err = s.executeDeviceCodeStep1(session, request)
	default:
		return nil, fmt.Errorf("unsupported flow: %s", request.Flow)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to execute first step: %w", err)
	}

	session.Steps = append(session.Steps, *firstStep)
	session.CurrentStep = 1

	// Store session
	if err := s.storePlaygroundSession(session); err != nil {
		return nil, fmt.Errorf("failed to store session: %w", err)
	}

	return session, nil
}

// ContinuePlaygroundSession continues an existing playground session
func (s *OAuthPlaygroundService) ContinuePlaygroundSession(sessionID string, stepData map[string]interface{}) (*PlaygroundSession, error) {
	// Get session
	session, err := s.getPlaygroundSession(sessionID)
	if err != nil {
		return nil, fmt.Errorf("session not found: %w", err)
	}

	if session.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("session expired")
	}

	// Execute next step based on flow and current step
	var nextStep *PlaygroundResponse

	switch session.Flow {
	case "authorization_code":
		nextStep, err = s.executeAuthorizationCodeNextStep(session, stepData)
	case "device_code":
		nextStep, err = s.executeDeviceCodeNextStep(session, stepData)
	default:
		return nil, fmt.Errorf("flow %s does not support continuation", session.Flow)
	}

	if err != nil {
		nextStep = &PlaygroundResponse{
			Step:      session.CurrentStep + 1,
			StepName:  "Error",
			Success:   false,
			Error:     err.Error(),
			Timestamp: time.Now(),
		}
	}

	session.Steps = append(session.Steps, *nextStep)
	session.CurrentStep++
	session.UpdatedAt = time.Now()

	// Store updated session
	if err := s.storePlaygroundSession(session); err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	return session, nil
}

// GetPlaygroundSession retrieves a playground session
func (s *OAuthPlaygroundService) GetPlaygroundSession(sessionID string) (*PlaygroundSession, error) {
	return s.getPlaygroundSession(sessionID)
}

// Flow execution methods

func (s *OAuthPlaygroundService) executeAuthorizationCodeStep1(session *PlaygroundSession, request *PlaygroundRequest) (*PlaygroundResponse, error) {
	// Build authorization URL
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", request.ClientID)
	params.Set("redirect_uri", request.RedirectURI)
	params.Set("scope", strings.Join(request.Scopes, " "))

	if request.State != "" {
		params.Set("state", request.State)
	}
	if request.Nonce != "" {
		params.Set("nonce", request.Nonce)
	}
	if request.CodeChallenge != "" {
		params.Set("code_challenge", request.CodeChallenge)
		params.Set("code_challenge_method", request.CodeChallengeMethod)
	}

	// Add custom parameters
	for key, value := range request.CustomParams {
		params.Set(key, value)
	}

	baseURL := facades.Config().GetString("app.url")
	authURL := fmt.Sprintf("%s/oauth/authorize?%s", baseURL, params.Encode())

	// Store state for next step
	session.State["redirect_uri"] = request.RedirectURI
	session.State["state"] = request.State
	session.State["code_challenge"] = request.CodeChallenge
	session.State["code_challenge_method"] = request.CodeChallengeMethod

	return &PlaygroundResponse{
		Step:     1,
		StepName: "Authorization Request",
		Success:  true,
		Request: map[string]interface{}{
			"method": "GET",
			"url":    authURL,
			"params": params,
		},
		Response: map[string]interface{}{
			"authorization_url": authURL,
			"instructions":      "Visit the authorization URL to get the authorization code",
		},
		NextStep:     "authorization_code_step2",
		Instructions: "Visit the authorization URL in your browser, complete the authorization, and copy the authorization code from the callback URL.",
		Timestamp:    time.Now(),
	}, nil
}

func (s *OAuthPlaygroundService) executeAuthorizationCodeNextStep(session *PlaygroundSession, stepData map[string]interface{}) (*PlaygroundResponse, error) {
	if session.CurrentStep == 1 {
		// Step 2: Exchange authorization code for tokens
		code, ok := stepData["code"].(string)
		if !ok || code == "" {
			return nil, fmt.Errorf("authorization code is required")
		}

		// Get initial request
		initialRequest := session.State["initial_request"].(*PlaygroundRequest)

		// Build token request
		tokenParams := map[string]interface{}{
			"grant_type":   "authorization_code",
			"code":         code,
			"client_id":    initialRequest.ClientID,
			"redirect_uri": session.State["redirect_uri"],
		}

		if initialRequest.ClientSecret != "" {
			tokenParams["client_secret"] = initialRequest.ClientSecret
		}

		if codeVerifier, ok := stepData["code_verifier"].(string); ok && codeVerifier != "" {
			tokenParams["code_verifier"] = codeVerifier
		}

		// Make token request (simulate)
		baseURL := facades.Config().GetString("app.url")
		tokenURL := fmt.Sprintf("%s/api/v1/oauth/token", baseURL)

		// This would typically make an actual HTTP request
		// For playground purposes, we'll simulate the response
		tokenResponse := map[string]interface{}{
			"access_token":  "playground_access_token_" + s.generateRandomString(32),
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "playground_refresh_token_" + s.generateRandomString(32),
			"scope":         strings.Join(initialRequest.Scopes, " "),
		}

		// If OpenID Connect, add ID token
		if s.containsScope(initialRequest.Scopes, "openid") {
			tokenResponse["id_token"] = "playground_id_token_" + s.generateRandomString(64)
		}

		return &PlaygroundResponse{
			Step:     2,
			StepName: "Token Exchange",
			Success:  true,
			Request: map[string]interface{}{
				"method":  "POST",
				"url":     tokenURL,
				"params":  tokenParams,
				"headers": map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			},
			Response:     tokenResponse,
			Instructions: "Authorization code flow completed successfully. You can now use the access token to make API requests.",
			Timestamp:    time.Now(),
		}, nil
	}

	return nil, fmt.Errorf("invalid step for authorization code flow")
}

func (s *OAuthPlaygroundService) executeClientCredentialsFlow(session *PlaygroundSession, request *PlaygroundRequest) (*PlaygroundResponse, error) {
	// Build token request
	tokenParams := map[string]interface{}{
		"grant_type":    "client_credentials",
		"client_id":     request.ClientID,
		"client_secret": request.ClientSecret,
		"scope":         strings.Join(request.Scopes, " "),
	}

	baseURL := facades.Config().GetString("app.url")
	tokenURL := fmt.Sprintf("%s/api/v1/oauth/token", baseURL)

	// Simulate token response
	tokenResponse := map[string]interface{}{
		"access_token": "playground_client_token_" + s.generateRandomString(32),
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        strings.Join(request.Scopes, " "),
	}

	return &PlaygroundResponse{
		Step:     1,
		StepName: "Client Credentials Token",
		Success:  true,
		Request: map[string]interface{}{
			"method":  "POST",
			"url":     tokenURL,
			"params":  tokenParams,
			"headers": map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		},
		Response:     tokenResponse,
		Instructions: "Client credentials flow completed. Use the access token for API requests.",
		Timestamp:    time.Now(),
	}, nil
}

func (s *OAuthPlaygroundService) executePasswordFlow(session *PlaygroundSession, request *PlaygroundRequest) (*PlaygroundResponse, error) {
	if request.Username == "" || request.Password == "" {
		return nil, fmt.Errorf("username and password are required for password flow")
	}

	// Build token request
	tokenParams := map[string]interface{}{
		"grant_type":    "password",
		"username":      request.Username,
		"password":      request.Password,
		"client_id":     request.ClientID,
		"client_secret": request.ClientSecret,
		"scope":         strings.Join(request.Scopes, " "),
	}

	baseURL := facades.Config().GetString("app.url")
	tokenURL := fmt.Sprintf("%s/api/v1/oauth/token", baseURL)

	// Simulate token response
	tokenResponse := map[string]interface{}{
		"access_token":  "playground_password_token_" + s.generateRandomString(32),
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "playground_refresh_token_" + s.generateRandomString(32),
		"scope":         strings.Join(request.Scopes, " "),
	}

	return &PlaygroundResponse{
		Step:     1,
		StepName: "Password Grant Token",
		Success:  true,
		Request: map[string]interface{}{
			"method":  "POST",
			"url":     tokenURL,
			"params":  tokenParams,
			"headers": map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
		},
		Response:     tokenResponse,
		Instructions: "Password flow completed. Use the access token for API requests.",
		Timestamp:    time.Now(),
	}, nil
}

func (s *OAuthPlaygroundService) executeDeviceCodeStep1(session *PlaygroundSession, request *PlaygroundRequest) (*PlaygroundResponse, error) {
	// Build device authorization request
	deviceParams := map[string]interface{}{
		"client_id": request.ClientID,
		"scope":     strings.Join(request.Scopes, " "),
	}

	baseURL := facades.Config().GetString("app.url")
	deviceURL := fmt.Sprintf("%s/api/v1/oauth/device", baseURL)

	// Simulate device authorization response
	deviceCode := "playground_device_" + s.generateRandomString(8)
	userCode := s.generateUserCode()
	verificationURI := fmt.Sprintf("%s/device", baseURL)

	deviceResponse := map[string]interface{}{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": fmt.Sprintf("%s?user_code=%s", verificationURI, userCode),
		"expires_in":                600,
		"interval":                  5,
	}

	// Store device code for next step
	session.State["device_code"] = deviceCode
	session.State["user_code"] = userCode

	return &PlaygroundResponse{
		Step:     1,
		StepName: "Device Authorization",
		Success:  true,
		Request: map[string]interface{}{
			"method": "POST",
			"url":    deviceURL,
			"params": deviceParams,
		},
		Response:     deviceResponse,
		NextStep:     "device_code_step2",
		Instructions: fmt.Sprintf("Go to %s and enter the user code: %s", verificationURI, userCode),
		Timestamp:    time.Now(),
	}, nil
}

func (s *OAuthPlaygroundService) executeDeviceCodeNextStep(session *PlaygroundSession, stepData map[string]interface{}) (*PlaygroundResponse, error) {
	if session.CurrentStep == 1 {
		// Step 2: Poll for token
		initialRequest := session.State["initial_request"].(*PlaygroundRequest)
		deviceCode := session.State["device_code"].(string)

		tokenParams := map[string]interface{}{
			"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
			"device_code": deviceCode,
			"client_id":   initialRequest.ClientID,
		}

		baseURL := facades.Config().GetString("app.url")
		tokenURL := fmt.Sprintf("%s/api/v1/oauth/token", baseURL)

		// Simulate token response (in real implementation, this would poll)
		tokenResponse := map[string]interface{}{
			"access_token":  "playground_device_token_" + s.generateRandomString(32),
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": "playground_refresh_token_" + s.generateRandomString(32),
			"scope":         strings.Join(initialRequest.Scopes, " "),
		}

		return &PlaygroundResponse{
			Step:     2,
			StepName: "Device Token",
			Success:  true,
			Request: map[string]interface{}{
				"method": "POST",
				"url":    tokenURL,
				"params": tokenParams,
			},
			Response:     tokenResponse,
			Instructions: "Device flow completed. Use the access token for API requests.",
			Timestamp:    time.Now(),
		}, nil
	}

	return nil, fmt.Errorf("invalid step for device code flow")
}

// Helper methods

func (s *OAuthPlaygroundService) getOrCreatePlaygroundClient() (*PlaygroundClient, error) {
	clientID := "playground_client"

	// Check if client exists
	var existingClient models.OAuthClient
	err := facades.Orm().Query().Where("id", clientID).First(&existingClient)

	if err == nil {
		// Client exists, return it
		return &PlaygroundClient{
			ClientID:     existingClient.ID,
			ClientSecret: *existingClient.Secret,
			RedirectURIs: existingClient.GetRedirectURIs(),
			Name:         existingClient.Name,
			Description:  "OAuth2 Playground Testing Client",
		}, nil
	}

	// Create new playground client
	redirectURIs := []string{
		facades.Config().GetString("oauth.playground.default_redirect_uri", "http://localhost:8080/oauth/playground/callback"),
		facades.Config().GetString("app.url") + "/oauth/playground/callback",
	}

	client, err := s.oauthService.CreateClient(
		"OAuth2 Playground",
		nil, // No specific user
		redirectURIs,
		false, // Not personal access client
		false, // Not password client
	)
	if err != nil {
		return nil, err
	}

	return &PlaygroundClient{
		ClientID:     client.ID,
		ClientSecret: *client.Secret,
		RedirectURIs: redirectURIs,
		Name:         client.Name,
		Description:  "OAuth2 Playground Testing Client",
	}, nil
}

func (s *OAuthPlaygroundService) validatePlaygroundRequest(request *PlaygroundRequest) error {
	if request.Flow == "" {
		return fmt.Errorf("flow is required")
	}

	if request.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}

	switch request.Flow {
	case "authorization_code":
		if request.RedirectURI == "" {
			return fmt.Errorf("redirect_uri is required for authorization code flow")
		}
	case "client_credentials":
		if request.ClientSecret == "" {
			return fmt.Errorf("client_secret is required for client credentials flow")
		}
	case "password":
		if request.Username == "" || request.Password == "" {
			return fmt.Errorf("username and password are required for password flow")
		}
	}

	return nil
}

func (s *OAuthPlaygroundService) generateSessionID() string {
	return fmt.Sprintf("playground_%d_%s", time.Now().UnixNano(), s.generateRandomString(8))
}

func (s *OAuthPlaygroundService) generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

func (s *OAuthPlaygroundService) generateUserCode() string {
	// Generate a user-friendly code like Google's device flow
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	code := make([]byte, 8)
	for i := range code {
		code[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	// Format as XXXX-XXXX
	return fmt.Sprintf("%s-%s", string(code[:4]), string(code[4:]))
}

func (s *OAuthPlaygroundService) containsScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

func (s *OAuthPlaygroundService) storePlaygroundSession(session *PlaygroundSession) error {
	key := fmt.Sprintf("playground_session_%s", session.ID)
	return facades.Cache().Put(key, session, time.Until(session.ExpiresAt))
}

func (s *OAuthPlaygroundService) getPlaygroundSession(sessionID string) (*PlaygroundSession, error) {
	key := fmt.Sprintf("playground_session_%s", sessionID)

	var session PlaygroundSession
	if err := facades.Cache().Get(key, &session); err != nil {
		return nil, fmt.Errorf("session not found")
	}

	return &session, nil
}
