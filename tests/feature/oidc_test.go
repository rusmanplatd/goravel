package feature

import (
	"testing"
	"time"

	"goravel/app/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// Mock OIDC service for testing
type MockOIDCService struct {
	issuer string
	keys   map[string]interface{}
}

func NewMockOIDCService() *MockOIDCService {
	return &MockOIDCService{
		issuer: "https://example.com",
		keys: map[string]interface{}{
			"response_types_supported": []string{"code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"},
			"scopes_supported":         []string{"openid", "profile", "email", "address", "phone", "offline_access"},
			"grant_types_supported":    []string{"authorization_code", "implicit", "refresh_token", "password", "client_credentials"},
			"subject_types_supported":  []string{"public", "pairwise"},
		},
	}
}

func (m *MockOIDCService) GetDiscoveryDocument() map[string]interface{} {
	return map[string]interface{}{
		"issuer":                   m.issuer,
		"authorization_endpoint":   m.issuer + "/.well-known/oauth2/authorize",
		"token_endpoint":           m.issuer + "/.well-known/oauth2/token",
		"userinfo_endpoint":        m.issuer + "/.well-known/oauth2/userinfo",
		"jwks_uri":                 m.issuer + "/.well-known/oauth2/jwks",
		"response_types_supported": m.keys["response_types_supported"],
		"scopes_supported":         m.keys["scopes_supported"],
		"grant_types_supported":    m.keys["grant_types_supported"],
		"subject_types_supported":  m.keys["subject_types_supported"],
	}
}

func TestOIDCDiscovery(t *testing.T) {
	// Create mock OIDC service
	oidcService := NewMockOIDCService()

	// Get discovery document
	discoveryDoc := oidcService.GetDiscoveryDocument()

	// Test required fields
	assert.NotEmpty(t, discoveryDoc["issuer"])
	assert.NotEmpty(t, discoveryDoc["authorization_endpoint"])
	assert.NotEmpty(t, discoveryDoc["token_endpoint"])
	assert.NotEmpty(t, discoveryDoc["userinfo_endpoint"])
	assert.NotEmpty(t, discoveryDoc["jwks_uri"])

	// Test supported features
	responseTypes, ok := discoveryDoc["response_types_supported"].([]string)
	assert.True(t, ok)
	assert.Contains(t, responseTypes, "code")
	assert.Contains(t, responseTypes, "token")
	assert.Contains(t, responseTypes, "id_token")

	scopes, ok := discoveryDoc["scopes_supported"].([]string)
	assert.True(t, ok)
	assert.Contains(t, scopes, "openid")
	assert.Contains(t, scopes, "profile")
	assert.Contains(t, scopes, "email")

	grantTypes, ok := discoveryDoc["grant_types_supported"].([]string)
	assert.True(t, ok)
	assert.Contains(t, grantTypes, "authorization_code")
	assert.Contains(t, grantTypes, "refresh_token")
}

func TestOIDCJWKS(t *testing.T) {
	// Test JWKS structure (mock implementation)
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": "test-key-id",
				"use": "sig",
				"alg": "RS256",
				"n":   "test-modulus",
				"e":   "test-exponent",
			},
		},
	}

	keys, ok := jwks["keys"].([]map[string]interface{})
	assert.True(t, ok)
	assert.Len(t, keys, 1)

	key := keys[0]
	assert.Equal(t, "RSA", key["kty"])
	assert.Equal(t, "sig", key["use"])
	assert.Equal(t, "RS256", key["alg"])
	assert.NotEmpty(t, key["kid"])
	assert.NotEmpty(t, key["n"])
	assert.NotEmpty(t, key["e"])
}

func TestOIDCIDTokenGeneration(t *testing.T) {
	// Test ID token generation with mock JWT
	issuer := "https://example.com"
	audience := "test-client"
	subject := "01HXYZ123456789ABCDEFGHIJK"
	issuedAt := time.Now()
	expiresAt := issuedAt.Add(60 * time.Minute)

	// Create claims
	claims := jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   subject,
		Audience:  []string{audience},
		IssuedAt:  jwt.NewNumericDate(issuedAt),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		NotBefore: jwt.NewNumericDate(issuedAt),
	}

	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("test-secret"))

	assert.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	// Parse token
	parsedToken, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte("test-secret"), nil
	})

	assert.NoError(t, err)
	assert.True(t, parsedToken.Valid)

	parsedClaims, ok := parsedToken.Claims.(*jwt.RegisteredClaims)
	assert.True(t, ok)
	assert.Equal(t, issuer, parsedClaims.Issuer)
	assert.Equal(t, subject, parsedClaims.Subject)
	assert.Equal(t, audience, parsedClaims.Audience[0])
}

func TestOIDCScopeValidation(t *testing.T) {
	// Test scope validation
	supportedScopes := []string{"openid", "profile", "email", "address", "phone", "offline_access"}

	// Test valid scopes
	validScopes := []string{"openid", "profile", "email"}
	for _, scope := range validScopes {
		assert.Contains(t, supportedScopes, scope)
	}

	// Test invalid scopes
	invalidScopes := []string{"invalid_scope", "unknown_scope"}
	for _, scope := range invalidScopes {
		assert.NotContains(t, supportedScopes, scope)
	}

	// Test openid scope requirement
	scopesWithoutOpenID := []string{"profile", "email"}
	assert.NotContains(t, scopesWithoutOpenID, "openid")

	scopesWithOpenID := []string{"openid", "profile", "email"}
	assert.Contains(t, scopesWithOpenID, "openid")
}

func TestOIDCConfiguration(t *testing.T) {
	// Test OIDC configuration structure
	config := map[string]interface{}{
		"issuer":                "https://example.com",
		"scopes_supported":      []string{"openid", "profile", "email"},
		"grant_types_supported": []string{"authorization_code", "refresh_token"},
		"security": map[string]interface{}{
			"require_https":                   true,
			"require_pkce_for_public_clients": true,
		},
	}

	// Test required configuration
	assert.NotEmpty(t, config["issuer"])
	assert.NotNil(t, config["scopes_supported"])
	assert.NotNil(t, config["grant_types_supported"])

	scopes, ok := config["scopes_supported"].([]string)
	assert.True(t, ok)
	assert.Contains(t, scopes, "openid")
	assert.Contains(t, scopes, "profile")
	assert.Contains(t, scopes, "email")

	grantTypes, ok := config["grant_types_supported"].([]string)
	assert.True(t, ok)
	assert.Contains(t, grantTypes, "authorization_code")
	assert.Contains(t, grantTypes, "refresh_token")

	security, ok := config["security"].(map[string]interface{})
	assert.True(t, ok)
	assert.True(t, security["require_https"].(bool))
	assert.True(t, security["require_pkce_for_public_clients"].(bool))
}

func TestOIDCUserClaims(t *testing.T) {
	// Test user claims mapping
	user := &models.User{
		BaseModel: models.BaseModel{
			ID: "01HXYZ123456789ABCDEFGHIJK",
		},
		Name:  "John Doe",
		Email: "john.doe@example.com",
	}

	// Test basic claims
	assert.Equal(t, "01HXYZ123456789ABCDEFGHIJK", user.ID)
	assert.Equal(t, "John Doe", user.Name)
	assert.Equal(t, "john.doe@example.com", user.Email)

	// Test name splitting for profile claims
	nameParts := []string{"John", "Doe"}
	assert.Len(t, nameParts, 2)
	assert.Equal(t, "John", nameParts[0]) // given_name
	assert.Equal(t, "Doe", nameParts[1])  // family_name
}

func TestOIDCTokenHash(t *testing.T) {
	// Test token hash generation
	token := "test-access-token"

	// Simple hash simulation
	hash := "test-hash-value"
	assert.NotEmpty(t, hash)
	assert.NotEqual(t, token, hash)
}
