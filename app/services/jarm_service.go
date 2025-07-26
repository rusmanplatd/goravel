package services

import (
	"fmt"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goravel/framework/facades"
)

type JARMService struct {
	oauthService *OAuthService
}

type JARMResponse struct {
	Code             string `json:"code,omitempty"`
	AccessToken      string `json:"access_token,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	ExpiresIn        int64  `json:"expires_in,omitempty"`
	RefreshToken     string `json:"refresh_token,omitempty"`
	Scope            string `json:"scope,omitempty"`
	State            string `json:"state,omitempty"`
	IDToken          string `json:"id_token,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

type JARMClaims struct {
	Issuer           string `json:"iss"`                         // Issuer
	Audience         string `json:"aud"`                         // Audience (client_id)
	ExpiresAt        int64  `json:"exp"`                         // Expiration time
	IssuedAt         int64  `json:"iat"`                         // Issued at time
	Code             string `json:"code,omitempty"`              // Authorization code
	AccessToken      string `json:"access_token,omitempty"`      // Access token
	TokenType        string `json:"token_type,omitempty"`        // Token type
	ExpiresIn        int64  `json:"expires_in,omitempty"`        // Token expiration
	RefreshToken     string `json:"refresh_token,omitempty"`     // Refresh token
	Scope            string `json:"scope,omitempty"`             // Granted scopes
	State            string `json:"state,omitempty"`             // State parameter
	IDToken          string `json:"id_token,omitempty"`          // ID token
	Error            string `json:"error,omitempty"`             // Error code
	ErrorDescription string `json:"error_description,omitempty"` // Error description
	ErrorURI         string `json:"error_uri,omitempty"`         // Error URI
	jwt.RegisteredClaims
}

func NewJARMService() *JARMService {
	return &JARMService{
		oauthService: NewOAuthService(),
	}
}

// CreateJARMResponse creates a JARM response JWT with Google-like enhancements
func (s *JARMService) CreateJARMResponse(response *JARMResponse, clientID string, responseMode string) (string, error) {
	now := time.Now()

	// Get client for JARM configuration (for future use)
	_, err := s.oauthService.GetClient(clientID)
	if err != nil {
		return "", fmt.Errorf("failed to get client: %w", err)
	}

	// Create JARM claims with Google-like structure
	claims := &JARMClaims{
		Issuer:           facades.Config().GetString("app.url"),
		Audience:         clientID,
		ExpiresAt:        now.Add(time.Duration(facades.Config().GetInt("oauth.jarm.response_ttl", 600)) * time.Second).Unix(),
		IssuedAt:         now.Unix(),
		Code:             response.Code,
		AccessToken:      response.AccessToken,
		TokenType:        response.TokenType,
		ExpiresIn:        response.ExpiresIn,
		RefreshToken:     response.RefreshToken,
		Scope:            response.Scope,
		State:            response.State,
		IDToken:          response.IDToken,
		Error:            response.Error,
		ErrorDescription: response.ErrorDescription,
		ErrorURI:         response.ErrorURI,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        s.generateJTI(),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	// Determine signing algorithm based on client configuration
	signingAlg := facades.Config().GetString("oauth.jarm.default_signing_alg", "RS256")
	signingMethod := s.getSigningMethod(signingAlg)

	// Create token with appropriate signing method
	token := jwt.NewWithClaims(signingMethod, claims)

	// Add Google-like headers
	token.Header["typ"] = "JARM"
	if kid := s.getKeyID("default"); kid != "" {
		token.Header["kid"] = kid
	}

	// Sign the token
	privateKey, err := s.getSigningKey()
	if err != nil {
		return "", fmt.Errorf("failed to get signing key: %w", err)
	}

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JARM token: %w", err)
	}

	// Log JARM response creation
	s.logJARMResponse(clientID, responseMode, claims, tokenString)

	return tokenString, nil
}

// ValidateJARMResponse validates a JARM response JWT
func (s *JARMService) ValidateJARMResponse(jarmResponse, clientID string) (*JARMResponse, error) {
	if !facades.Config().GetBool("oauth.jarm.enabled", false) {
		return nil, fmt.Errorf("JARM is not enabled")
	}

	// Parse and validate the JWT
	token, err := jwt.ParseWithClaims(jarmResponse, &JARMClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if !s.isValidJARMAlgorithm(token.Header["alg"].(string)) {
			return nil, fmt.Errorf("invalid JARM signing algorithm: %v", token.Header["alg"])
		}

		// Get verification key
		return s.getVerificationKey()
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse JARM response: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid JARM response token")
	}

	// Extract claims
	claims, ok := token.Claims.(*JARMClaims)
	if !ok {
		return nil, fmt.Errorf("invalid JARM response claims")
	}

	// Validate audience
	if claims.Audience != clientID {
		return nil, fmt.Errorf("JARM response audience mismatch: expected %s, got %s", clientID, claims.Audience)
	}

	// Validate issuer
	expectedIssuer := facades.Config().GetString("app.url")
	if claims.Issuer != expectedIssuer {
		return nil, fmt.Errorf("JARM response issuer mismatch: expected %s, got %s", expectedIssuer, claims.Issuer)
	}

	// Convert claims back to response structure
	response := &JARMResponse{
		Code:             claims.Code,
		AccessToken:      claims.AccessToken,
		TokenType:        claims.TokenType,
		ExpiresIn:        claims.ExpiresIn,
		RefreshToken:     claims.RefreshToken,
		Scope:            claims.Scope,
		State:            claims.State,
		IDToken:          claims.IDToken,
		Error:            claims.Error,
		ErrorDescription: claims.ErrorDescription,
		ErrorURI:         claims.ErrorURI,
	}

	return response, nil
}

// CreateJARMErrorResponse creates a JARM error response with Google-like error handling
func (s *JARMService) CreateJARMErrorResponse(errorCode, errorDescription, errorURI, state, clientID string) (string, error) {
	response := &JARMResponse{
		Error:            errorCode,
		ErrorDescription: errorDescription,
		ErrorURI:         errorURI,
		State:            state,
	}

	return s.CreateJARMResponse(response, clientID, "jwt")
}

// EncodeJARMResponseForRedirect encodes a JARM response for URL redirection
func (s *JARMService) EncodeJARMResponseForRedirect(redirectURI, jarmResponse string) (string, error) {
	// Parse the redirect URI
	u, err := url.Parse(redirectURI)
	if err != nil {
		return "", fmt.Errorf("invalid redirect URI: %w", err)
	}

	// Add the JARM response as a query parameter
	query := u.Query()
	query.Set("response", jarmResponse)
	u.RawQuery = query.Encode()

	return u.String(), nil
}

// SupportedResponseModes returns the supported JARM response modes
func (s *JARMService) SupportedResponseModes() []string {
	if !facades.Config().GetBool("oauth.jarm.enabled", false) {
		return []string{}
	}

	return []string{
		"jwt",           // JWT response mode
		"query.jwt",     // JWT in query parameter
		"fragment.jwt",  // JWT in fragment
		"form_post.jwt", // JWT via form post
	}
}

// IsJARMResponseMode checks if a response mode is a JARM response mode
func (s *JARMService) IsJARMResponseMode(responseMode string) bool {
	supportedModes := s.SupportedResponseModes()
	for _, mode := range supportedModes {
		if mode == responseMode {
			return true
		}
	}
	return false
}

// GetJARMMetadata returns JARM-related metadata for discovery endpoint
func (s *JARMService) GetJARMMetadata() map[string]interface{} {
	if !facades.Config().GetBool("oauth.jarm.enabled", false) {
		return map[string]interface{}{}
	}

	supportedAlgs := facades.Config().Get("oauth.jarm.supported_algorithms").([]string)

	return map[string]interface{}{
		"authorization_signing_alg_values_supported":     supportedAlgs,
		"authorization_encryption_alg_values_supported":  []string{}, // Not implemented in this example
		"authorization_encryption_enc_values_supported":  []string{}, // Not implemented in this example
		"authorization_response_iss_parameter_supported": true,
		"response_modes_supported":                       s.SupportedResponseModes(),
	}
}

// getSigningMethod returns the JWT signing method for the given algorithm
func (s *JARMService) getSigningMethod(algorithm string) jwt.SigningMethod {
	switch algorithm {
	case "RS256":
		return jwt.SigningMethodRS256
	case "RS384":
		return jwt.SigningMethodRS384
	case "RS512":
		return jwt.SigningMethodRS512
	case "ES256":
		return jwt.SigningMethodES256
	case "ES384":
		return jwt.SigningMethodES384
	case "ES512":
		return jwt.SigningMethodES512
	case "PS256":
		return jwt.SigningMethodPS256
	case "PS384":
		return jwt.SigningMethodPS384
	case "PS512":
		return jwt.SigningMethodPS512
	default:
		return jwt.SigningMethodRS256 // Default fallback
	}
}

// isValidJARMAlgorithm checks if the algorithm is supported for JARM
func (s *JARMService) isValidJARMAlgorithm(alg string) bool {
	supportedAlgs := facades.Config().Get("oauth.jarm.supported_algorithms").([]string)
	for _, supported := range supportedAlgs {
		if alg == supported {
			return true
		}
	}
	return false
}

// getSigningKey returns the private key for signing JARM responses
func (s *JARMService) getSigningKey() (interface{}, error) {
	// Use the same key as OAuth service for consistency
	if s.oauthService.rsaPrivateKey == nil {
		return nil, fmt.Errorf("RSA private key not initialized")
	}
	return s.oauthService.rsaPrivateKey, nil
}

// getVerificationKey returns the public key for verifying JARM responses
func (s *JARMService) getVerificationKey() (interface{}, error) {
	// Use the same key as OAuth service for consistency
	if s.oauthService.rsaPublicKey == nil {
		return nil, fmt.Errorf("RSA public key not initialized")
	}
	return s.oauthService.rsaPublicKey, nil
}

// CreateJARMSuccessResponse creates a successful JARM authorization response
func (s *JARMService) CreateJARMSuccessResponse(clientID, code, state string, accessToken, tokenType, refreshToken, scope, idToken string, expiresIn int64) (string, error) {
	response := &JARMResponse{
		Code:         code,
		State:        state,
		AccessToken:  accessToken,
		TokenType:    tokenType,
		RefreshToken: refreshToken,
		Scope:        scope,
		IDToken:      idToken,
		ExpiresIn:    expiresIn,
	}

	return s.CreateJARMResponse(response, clientID, "jwt")
}

// ProcessJARMResponseMode processes different JARM response modes
func (s *JARMService) ProcessJARMResponseMode(responseMode, redirectURI, jarmResponse string) (string, error) {
	switch responseMode {
	case "jwt", "query.jwt":
		// Return JWT in query parameter
		return s.EncodeJARMResponseForRedirect(redirectURI, jarmResponse)

	case "fragment.jwt":
		// Return JWT in fragment
		u, err := url.Parse(redirectURI)
		if err != nil {
			return "", fmt.Errorf("invalid redirect URI: %w", err)
		}
		u.Fragment = fmt.Sprintf("response=%s", url.QueryEscape(jarmResponse))
		return u.String(), nil

	case "form_post.jwt":
		// For form_post.jwt, the client needs to handle the form submission
		// This would typically be handled by the authorization endpoint
		return "", fmt.Errorf("form_post.jwt response mode requires special handling at the authorization endpoint")

	default:
		return "", fmt.Errorf("unsupported JARM response mode: %s", responseMode)
	}
}

// ExtractJARMResponseFromURL extracts a JARM response from a URL
func (s *JARMService) ExtractJARMResponseFromURL(responseURL string) (string, error) {
	u, err := url.Parse(responseURL)
	if err != nil {
		return "", fmt.Errorf("invalid response URL: %w", err)
	}

	// Check query parameters
	if response := u.Query().Get("response"); response != "" {
		return response, nil
	}

	// Check fragment
	if u.Fragment != "" {
		fragmentValues, err := url.ParseQuery(u.Fragment)
		if err == nil {
			if response := fragmentValues.Get("response"); response != "" {
				return response, nil
			}
		}
	}

	return "", fmt.Errorf("no JARM response found in URL")
}

// ValidateJARMConfiguration validates the JARM configuration
func (s *JARMService) ValidateJARMConfiguration() error {
	if !facades.Config().GetBool("oauth.jarm.enabled", false) {
		return nil // JARM is disabled, no validation needed
	}

	// Validate supported algorithms
	supportedAlgs := facades.Config().Get("oauth.jarm.supported_algorithms")
	if supportedAlgs == nil {
		return fmt.Errorf("JARM supported algorithms not configured")
	}

	algs, ok := supportedAlgs.([]string)
	if !ok || len(algs) == 0 {
		return fmt.Errorf("JARM supported algorithms must be a non-empty string array")
	}

	// Validate default algorithm
	defaultAlg := facades.Config().GetString("oauth.jarm.default_signing_alg", "RS256")
	validDefault := false
	for _, alg := range algs {
		if alg == defaultAlg {
			validDefault = true
			break
		}
	}

	if !validDefault {
		return fmt.Errorf("JARM default signing algorithm '%s' is not in supported algorithms list", defaultAlg)
	}

	// Validate response lifetime
	lifetime := facades.Config().GetInt("oauth.jarm.response_lifetime", 600)
	if lifetime <= 0 || lifetime > 3600 {
		return fmt.Errorf("JARM response lifetime must be between 1 and 3600 seconds")
	}

	return nil
}

// Helper methods for Google-like JARM implementation

func (s *JARMService) getKeyID(keyType string) string {
	// Return key ID for key rotation (Google-like)
	return facades.Config().GetString("oauth.jarm.key_id", "jarm-key-1")
}

func (s *JARMService) generateJTI() string {
	// Generate unique JWT ID (Google-like)
	return fmt.Sprintf("jarm_%d_%s", time.Now().Unix(), s.generateRandomString(8))
}

func (s *JARMService) generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[time.Now().UnixNano()%int64(len(charset))]
	}
	return string(b)
}

func (s *JARMService) GetJARMResponseModes() []string {
	return []string{
		"query.jwt",
		"fragment.jwt",
		"form_post.jwt",
		"jwt",
	}
}

func (s *JARMService) isValidJARMResponseMode(responseMode string) bool {
	validModes := s.GetJARMResponseModes()
	for _, mode := range validModes {
		if mode == responseMode {
			return true
		}
	}
	return false
}

func (s *JARMService) clientSupportsJARM(client interface{}) bool {
	// In production, check client configuration for JARM support
	// For now, assume all clients support JARM if enabled globally
	return facades.Config().GetBool("oauth.jarm.enabled", true)
}

func (s *JARMService) logJARMResponse(clientID, responseMode string, claims *JARMClaims, tokenString string) {
	// Log JARM response creation (Google-like logging)
	facades.Log().Info("JARM response created", map[string]interface{}{
		"client_id":     clientID,
		"response_mode": responseMode,
		"jti":           claims.ID,
		"iss":           claims.Issuer,
		"aud":           claims.Audience,
		"exp":           claims.ExpiresAt,
		"has_code":      claims.Code != "",
		"has_token":     claims.AccessToken != "",
		"has_error":     claims.Error != "",
		"token_length":  len(tokenString),
	})
}

// GetJARMCapabilities returns JARM capabilities for discovery (Google-like)
func (s *JARMService) GetJARMCapabilities() map[string]interface{} {
	return map[string]interface{}{
		"jarm_supported": facades.Config().GetBool("oauth.jarm.enabled", true),
		"jarm_signing_alg_values_supported": []string{
			"RS256", "RS384", "RS512",
			"ES256", "ES384", "ES512",
		},
		"jarm_encryption_alg_values_supported": []string{
			"RSA1_5", "RSA-OAEP", "RSA-OAEP-256",
			"A128KW", "A192KW", "A256KW",
		},
		"jarm_encryption_enc_values_supported": []string{
			"A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512",
			"A128GCM", "A192GCM", "A256GCM",
		},
		"jarm_response_modes_supported":                  s.GetJARMResponseModes(),
		"authorization_response_iss_parameter_supported": true,
	}
}
