package services

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
	"time"

	"goravel/app/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goravel/framework/facades"
	"github.com/goravel/framework/http"
)

type OIDCService struct {
	oauthService *OAuthService
	jwtService   *JWTService
	privateKey   *rsa.PrivateKey
	publicKey    *rsa.PublicKey
	keyID        string
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type IDTokenClaims struct {
	jwt.RegisteredClaims
	Nonce               string                 `json:"nonce,omitempty"`
	AuthTime            int64                  `json:"auth_time,omitempty"`
	ACR                 string                 `json:"acr,omitempty"`
	AMR                 []string               `json:"amr,omitempty"`
	AccessTokenHash     string                 `json:"at_hash,omitempty"`
	CodeHash            string                 `json:"c_hash,omitempty"`
	Email               string                 `json:"email,omitempty"`
	EmailVerified       bool                   `json:"email_verified,omitempty"`
	Name                string                 `json:"name,omitempty"`
	GivenName           string                 `json:"given_name,omitempty"`
	FamilyName          string                 `json:"family_name,omitempty"`
	MiddleName          string                 `json:"middle_name,omitempty"`
	Nickname            string                 `json:"nickname,omitempty"`
	PreferredUsername   string                 `json:"preferred_username,omitempty"`
	Profile             string                 `json:"profile,omitempty"`
	Picture             string                 `json:"picture,omitempty"`
	Website             string                 `json:"website,omitempty"`
	Gender              string                 `json:"gender,omitempty"`
	Birthdate           string                 `json:"birthdate,omitempty"`
	Zoneinfo            string                 `json:"zoneinfo,omitempty"`
	Locale              string                 `json:"locale,omitempty"`
	PhoneNumber         string                 `json:"phone_number,omitempty"`
	PhoneNumberVerified bool                   `json:"phone_number_verified,omitempty"`
	Address             map[string]interface{} `json:"address,omitempty"`
	UpdatedAt           int64                  `json:"updated_at,omitempty"`
}

type UserInfoClaims struct {
	jwt.RegisteredClaims
	Name                string                 `json:"name,omitempty"`
	GivenName           string                 `json:"given_name,omitempty"`
	FamilyName          string                 `json:"family_name,omitempty"`
	MiddleName          string                 `json:"middle_name,omitempty"`
	Nickname            string                 `json:"nickname,omitempty"`
	PreferredUsername   string                 `json:"preferred_username,omitempty"`
	Profile             string                 `json:"profile,omitempty"`
	Picture             string                 `json:"picture,omitempty"`
	Website             string                 `json:"website,omitempty"`
	Email               string                 `json:"email,omitempty"`
	EmailVerified       bool                   `json:"email_verified,omitempty"`
	Gender              string                 `json:"gender,omitempty"`
	Birthdate           string                 `json:"birthdate,omitempty"`
	Zoneinfo            string                 `json:"zoneinfo,omitempty"`
	Locale              string                 `json:"locale,omitempty"`
	PhoneNumber         string                 `json:"phone_number,omitempty"`
	PhoneNumberVerified bool                   `json:"phone_number_verified,omitempty"`
	Address             map[string]interface{} `json:"address,omitempty"`
	UpdatedAt           int64                  `json:"updated_at,omitempty"`
}

func NewOIDCService() *OIDCService {
	service := &OIDCService{
		oauthService: NewOAuthService(),
		jwtService:   NewJWTService(),
	}

	// Generate or load RSA key pair
	service.generateOrLoadKeys()

	return service
}

// generateOrLoadKeys generates or loads RSA key pair for JWT signing
func (s *OIDCService) generateOrLoadKeys() {
	// In a production environment, you should load keys from secure storage
	// For now, we'll generate a new key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("Failed to generate RSA key pair: %v", err))
	}

	s.privateKey = privateKey
	s.publicKey = &privateKey.PublicKey
	s.keyID = s.generateKeyID()
}

// generateKeyID generates a unique key ID
func (s *OIDCService) generateKeyID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base64.RawURLEncoding.EncodeToString(bytes)
}

// GetDiscoveryDocument returns the OpenID Connect discovery document
func (s *OIDCService) GetDiscoveryDocument() map[string]interface{} {
	issuer := facades.Config().GetString("oidc.issuer")
	baseURL := strings.TrimSuffix(issuer, "/")

	return map[string]interface{}{
		"issuer":                                            issuer,
		"authorization_endpoint":                            baseURL + facades.Config().GetString("oidc.authorization_endpoint"),
		"token_endpoint":                                    baseURL + facades.Config().GetString("oidc.token_endpoint"),
		"userinfo_endpoint":                                 baseURL + facades.Config().GetString("oidc.userinfo_endpoint"),
		"jwks_uri":                                          baseURL + facades.Config().GetString("oidc.jwks_endpoint"),
		"end_session_endpoint":                              baseURL + facades.Config().GetString("oidc.end_session_endpoint"),
		"check_session_iframe":                              baseURL + facades.Config().GetString("oidc.check_session_iframe"),
		"revocation_endpoint":                               baseURL + facades.Config().GetString("oidc.revocation_endpoint"),
		"introspection_endpoint":                            baseURL + facades.Config().GetString("oidc.introspection_endpoint"),
		"device_authorization_endpoint":                     baseURL + facades.Config().GetString("oidc.device_authorization_endpoint"),
		"response_types_supported":                          facades.Config().Get("oidc.response_types_supported"),
		"subject_types_supported":                           facades.Config().Get("oidc.subject_types_supported"),
		"id_token_signing_alg_values_supported":             facades.Config().Get("oidc.id_token_signing_alg_values_supported"),
		"id_token_encryption_alg_values_supported":          facades.Config().Get("oidc.id_token_encryption_alg_values_supported"),
		"id_token_encryption_enc_values_supported":          facades.Config().Get("oidc.id_token_encryption_enc_values_supported"),
		"userinfo_signing_alg_values_supported":             facades.Config().Get("oidc.userinfo_signing_alg_values_supported"),
		"userinfo_encryption_alg_values_supported":          facades.Config().Get("oidc.userinfo_encryption_alg_values_supported"),
		"userinfo_encryption_enc_values_supported":          facades.Config().Get("oidc.userinfo_encryption_enc_values_supported"),
		"request_object_signing_alg_values_supported":       facades.Config().Get("oidc.request_object_signing_alg_values_supported"),
		"request_object_encryption_alg_values_supported":    facades.Config().Get("oidc.request_object_encryption_alg_values_supported"),
		"request_object_encryption_enc_values_supported":    facades.Config().Get("oidc.request_object_encryption_enc_values_supported"),
		"token_endpoint_auth_methods_supported":             facades.Config().Get("oidc.token_endpoint_auth_methods_supported"),
		"token_endpoint_auth_signing_alg_values_supported":  facades.Config().Get("oidc.token_endpoint_auth_signing_alg_values_supported"),
		"display_values_supported":                          facades.Config().Get("oidc.display_values_supported"),
		"claim_types_supported":                             facades.Config().Get("oidc.claim_types_supported"),
		"claims_supported":                                  facades.Config().Get("oidc.claims_supported"),
		"scopes_supported":                                  facades.Config().Get("oidc.scopes_supported"),
		"grant_types_supported":                             facades.Config().Get("oidc.grant_types_supported"),
		"response_modes_supported":                          facades.Config().Get("oidc.response_modes_supported"),
		"code_challenge_methods_supported":                  facades.Config().Get("oidc.code_challenge_methods_supported"),
		"request_parameter_encryption_alg_values_supported": facades.Config().Get("oidc.request_parameter_encryption_alg_values_supported"),
		"request_parameter_encryption_enc_values_supported": facades.Config().Get("oidc.request_parameter_encryption_enc_values_supported"),
		"service_documentation":                             facades.Config().GetString("oidc.service_documentation"),
		"claims_locales_supported":                          facades.Config().Get("oidc.claims_locales_supported"),
		"ui_locales_supported":                              facades.Config().Get("oidc.ui_locales_supported"),
		"claims_parameter_supported":                        facades.Config().GetBool("oidc.claims_parameter_supported"),
		"request_parameter_supported":                       facades.Config().GetBool("oidc.request_parameter_supported"),
		"request_uri_parameter_supported":                   facades.Config().GetBool("oidc.request_uri_parameter_supported"),
		"require_request_uri_registration":                  facades.Config().GetBool("oidc.require_request_uri_registration"),
		"op_policy_uri":                                     facades.Config().GetString("oidc.op_policy_uri"),
		"op_terms_of_service_uri":                           facades.Config().GetString("oidc.op_terms_of_service_uri"),
		"op_logo_uri":                                       facades.Config().GetString("oidc.op_logo_uri"),
		"op_contacts":                                       facades.Config().Get("oidc.op_contacts"),
	}
}

// GetJWKS returns the JSON Web Key Set
func (s *OIDCService) GetJWKS() *JWKS {
	// Convert public key to JWK format
	n := base64.RawURLEncoding.EncodeToString(s.publicKey.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(s.publicKey.E)).Bytes())

	jwk := JWK{
		Kty: "RSA",
		Kid: s.keyID,
		Use: "sig",
		Alg: "RS256",
		N:   n,
		E:   e,
	}

	return &JWKS{
		Keys: []JWK{jwk},
	}
}

// GenerateIDToken generates an ID token for the user
func (s *OIDCService) GenerateIDToken(user *models.User, clientID string, scopes []string, nonce string, accessToken string, authCode string, authTime int64) (string, error) {
	issuer := facades.Config().GetString("oidc.issuer")
	audience := clientID
	subject := user.ID
	issuedAt := time.Now()
	expiresAt := issuedAt.Add(time.Duration(facades.Config().GetInt("oidc.id_token.lifetime", 60)) * time.Minute)

	claims := &IDTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,
			Audience:  []string{audience},
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			NotBefore: jwt.NewNumericDate(issuedAt),
		},
		Nonce:    nonce,
		AuthTime: authTime,
		ACR:      "urn:mace:incommon:iap:bronze",
		AMR:      []string{"pwd"},
	}

	// Include access token hash if access token is provided
	if accessToken != "" && facades.Config().GetBool("oidc.id_token.include_access_token_hash", true) {
		claims.AccessTokenHash = s.generateTokenHash(accessToken)
	}

	// Include authorization code hash if auth code is provided
	if authCode != "" && facades.Config().GetBool("oidc.id_token.include_authorization_code_hash", true) {
		claims.CodeHash = s.generateTokenHash(authCode)
	}

	// Include user claims if enabled
	if facades.Config().GetBool("oidc.id_token.include_user_claims", true) {
		s.addUserClaimsToIDToken(claims, user, scopes)
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keyID

	// Sign the token
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign ID token: %v", err)
	}

	return tokenString, nil
}

// GenerateUserInfoToken generates a userinfo token
func (s *OIDCService) GenerateUserInfoToken(user *models.User, scopes []string) (string, error) {
	issuer := facades.Config().GetString("oidc.issuer")
	subject := user.ID
	issuedAt := time.Now()

	claims := &UserInfoClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(issuedAt.Add(time.Duration(facades.Config().GetInt("oauth.access_token_ttl", 60)) * time.Minute)),
			NotBefore: jwt.NewNumericDate(issuedAt),
		},
	}

	// Add user claims based on scopes
	s.addUserClaimsToUserInfo(claims, user, scopes)

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keyID

	// Sign the token
	tokenString, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign userinfo token: %v", err)
	}

	return tokenString, nil
}

// ValidateIDToken validates an ID token
func (s *OIDCService) ValidateIDToken(tokenString string, expectedAudience string) (*IDTokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &IDTokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Return the public key for verification
		return s.publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse ID token: %v", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid ID token")
	}

	claims, ok := token.Claims.(*IDTokenClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Validate audience
	if expectedAudience != "" {
		audienceValid := false
		for _, aud := range claims.Audience {
			if aud == expectedAudience {
				audienceValid = true
				break
			}
		}
		if !audienceValid {
			return nil, fmt.Errorf("invalid audience")
		}
	}

	// Validate issuer
	expectedIssuer := facades.Config().GetString("oidc.issuer")
	if claims.Issuer != expectedIssuer {
		return nil, fmt.Errorf("invalid issuer")
	}

	return claims, nil
}

// addUserClaimsToIDToken adds user claims to ID token based on scopes
func (s *OIDCService) addUserClaimsToIDToken(claims *IDTokenClaims, user *models.User, scopes []string) {
	scopeMap := make(map[string]bool)
	for _, scope := range scopes {
		scopeMap[scope] = true
	}

	// Always include basic profile information
	claims.Name = user.Name
	claims.Email = user.Email
	claims.EmailVerified = user.EmailVerifiedAt != nil
	claims.UpdatedAt = user.UpdatedAt.Unix()

	// Include additional claims based on scopes
	if scopeMap["profile"] {
		// Split name into given and family name
		nameParts := strings.Fields(user.Name)
		if len(nameParts) > 0 {
			claims.GivenName = nameParts[0]
		}
		if len(nameParts) > 1 {
			claims.FamilyName = strings.Join(nameParts[1:], " ")
		}
		claims.PreferredUsername = user.Email
		claims.Profile = fmt.Sprintf("%s/users/%s", facades.Config().GetString("app.url"), user.ID)
	}

	if scopeMap["email"] {
		// Email is already included above
	}

	if scopeMap["address"] {
		// Address claims not available in current user model
		// This can be extended when address fields are added
	}

	if scopeMap["phone"] {
		// Phone claims not available in current user model
		// This can be extended when phone fields are added
	}
}

// addUserClaimsToUserInfo adds user claims to userinfo token based on scopes
func (s *OIDCService) addUserClaimsToUserInfo(claims *UserInfoClaims, user *models.User, scopes []string) {
	scopeMap := make(map[string]bool)
	for _, scope := range scopes {
		scopeMap[scope] = true
	}

	// Always include basic profile information
	claims.Name = user.Name
	claims.Email = user.Email
	claims.EmailVerified = user.EmailVerifiedAt != nil
	claims.UpdatedAt = user.UpdatedAt.Unix()

	// Include additional claims based on scopes
	if scopeMap["profile"] {
		// Split name into given and family name
		nameParts := strings.Fields(user.Name)
		if len(nameParts) > 0 {
			claims.GivenName = nameParts[0]
		}
		if len(nameParts) > 1 {
			claims.FamilyName = strings.Join(nameParts[1:], " ")
		}
		claims.PreferredUsername = user.Email
		claims.Profile = fmt.Sprintf("%s/users/%s", facades.Config().GetString("app.url"), user.ID)
	}

	if scopeMap["email"] {
		// Email is already included above
	}

	if scopeMap["address"] {
		// Address claims not available in current user model
		// This can be extended when address fields are added
	}

	if scopeMap["phone"] {
		// Phone claims not available in current user model
		// This can be extended when phone fields are added
	}
}

// generateTokenHash generates a hash for token validation
func (s *OIDCService) generateTokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(hash[:16])
}

// ValidateScopes validates that all requested scopes are supported
func (s *OIDCService) ValidateScopes(scopes []string) bool {
	supportedScopes := s.GetSupportedScopes()
	supportedScopesMap := make(map[string]bool)
	for _, scope := range supportedScopes {
		supportedScopesMap[scope] = true
	}

	for _, scope := range scopes {
		if !supportedScopesMap[scope] {
			return false
		}
	}

	return true
}

// GetSupportedScopes returns the list of supported scopes
func (s *OIDCService) GetSupportedScopes() []string {
	scopes := facades.Config().Get("oidc.scopes_supported")
	if scopes == nil {
		return []string{"openid", "profile", "email"}
	}

	scopesSlice, ok := scopes.([]string)
	if !ok {
		return []string{"openid", "profile", "email"}
	}

	return scopesSlice
}

// LogOIDCEvent logs an OIDC event for audit purposes
func (s *OIDCService) LogOIDCEvent(eventType string, clientID string, userID string, metadata map[string]interface{}) {
	if !facades.Config().GetBool("oidc.logging.enable_event_logging", true) {
		return
	}

	// Log the OIDC event
	facades.Log().Info("OIDC Event", map[string]interface{}{
		"event_type": eventType,
		"client_id":  clientID,
		"user_id":    userID,
		"metadata":   metadata,
		"timestamp":  time.Now().Unix(),
	})
}

// IntrospectToken introspects a token and returns its details
func (s *OIDCService) IntrospectToken(token string, clientID string) (map[string]interface{}, error) {
	// Try to validate as access token first
	accessToken, err := s.oauthService.ValidateAccessToken(token)
	if err == nil {
		user := accessToken.GetUser()
		userID := ""
		if user != nil {
			userID = user.ID
		}

		return map[string]interface{}{
			"active":     true,
			"scope":      s.oauthService.FormatScopes(accessToken.GetScopes()),
			"client_id":  accessToken.ClientID,
			"username":   userID,
			"token_type": "Bearer",
			"exp":        time.Now().Add(time.Duration(facades.Config().GetInt("oauth.access_token_ttl", 60)) * time.Minute).Unix(),
			"iat":        time.Now().Unix(),
			"nbf":        time.Now().Unix(),
			"sub":        userID,
			"aud":        accessToken.ClientID,
			"iss":        facades.Config().GetString("oidc.issuer"),
		}, nil
	}

	// Try to validate as refresh token
	refreshToken, err := s.oauthService.ValidateRefreshToken(token)
	if err == nil {
		// Get the access token to find the user
		accessToken, err := s.oauthService.ValidateAccessToken(refreshToken.AccessTokenID)
		if err == nil {
			user := accessToken.GetUser()
			userID := ""
			if user != nil {
				userID = user.ID
			}

			return map[string]interface{}{
				"active":     true,
				"scope":      s.oauthService.FormatScopes(accessToken.GetScopes()),
				"client_id":  accessToken.ClientID,
				"username":   userID,
				"token_type": "RefreshToken",
				"exp":        refreshToken.ExpiresAt.Unix(),
				"iat":        time.Now().Unix(),
				"nbf":        time.Now().Unix(),
				"sub":        userID,
				"aud":        accessToken.ClientID,
				"iss":        facades.Config().GetString("oidc.issuer"),
			}, nil
		}
	}

	// Try to validate as ID token
	idTokenClaims, err := s.ValidateIDToken(token, "")
	if err == nil {
		return map[string]interface{}{
			"active":     true,
			"scope":      "openid",
			"client_id":  idTokenClaims.Audience[0],
			"username":   idTokenClaims.Subject,
			"token_type": "IDToken",
			"exp":        idTokenClaims.ExpiresAt.Unix(),
			"iat":        idTokenClaims.IssuedAt.Unix(),
			"nbf":        idTokenClaims.NotBefore.Unix(),
			"sub":        idTokenClaims.Subject,
			"aud":        idTokenClaims.Audience,
			"iss":        idTokenClaims.Issuer,
		}, nil
	}

	// Token is not valid
	return map[string]interface{}{
		"active": false,
	}, nil
}

// RevokeToken revokes a token
func (s *OIDCService) RevokeToken(token string, clientID string) error {
	// Try to revoke as access token
	accessToken, err := s.oauthService.ValidateAccessToken(token)
	if err == nil {
		return s.oauthService.RevokeAccessToken(accessToken.ID)
	}

	// Try to revoke as refresh token
	refreshToken, err := s.oauthService.ValidateRefreshToken(token)
	if err == nil {
		return s.oauthService.RevokeRefreshToken(refreshToken.ID)
	}

	// Token not found or already revoked
	return fmt.Errorf("token not found or already revoked")
}

// ValidateAuthorizationRequest validates an authorization request
func (s *OIDCService) ValidateAuthorizationRequest(responseType, clientID, redirectURI, scope, state, nonce string) error {
	// Validate response type
	supportedResponseTypes := facades.Config().Get("oidc.response_types_supported").([]string)
	responseTypeValid := false
	for _, rt := range supportedResponseTypes {
		if rt == responseType {
			responseTypeValid = true
			break
		}
	}
	if !responseTypeValid {
		return fmt.Errorf("unsupported response type")
	}

	// Validate client
	client, err := s.oauthService.GetClient(clientID)
	if err != nil {
		return fmt.Errorf("invalid client")
	}

	if client.IsRevoked() {
		return fmt.Errorf("client is revoked")
	}

	// Validate redirect URI
	allowedURIs := client.GetRedirectURIs()
	redirectURIValid := false
	for _, uri := range allowedURIs {
		if uri == redirectURI {
			redirectURIValid = true
			break
		}
	}
	if !redirectURIValid {
		return fmt.Errorf("invalid redirect URI")
	}

	// Validate scopes
	scopes := s.oauthService.ParseScopes(scope)
	if len(scopes) == 0 {
		scopes = s.GetSupportedScopes()
	}
	if !s.ValidateScopes(scopes) {
		return fmt.Errorf("invalid scope")
	}

	// Validate state parameter if required
	if facades.Config().GetBool("oidc.security.require_state_parameter", true) && state == "" {
		return fmt.Errorf("state parameter required")
	}

	// Validate nonce parameter for implicit flow
	if (responseType == "id_token" || responseType == "token id_token") &&
		facades.Config().GetBool("oidc.security.require_nonce_parameter", true) && nonce == "" {
		return fmt.Errorf("nonce parameter required for implicit flow")
	}

	return nil
}

// GenerateAuthorizationCode generates an authorization code with PKCE support
func (s *OIDCService) GenerateAuthorizationCode(userID, clientID string, scopes []string, nonce, codeChallenge, codeChallengeMethod string) (*models.OAuthAuthCode, error) {
	expiresAt := time.Now().Add(time.Duration(facades.Config().GetInt("oauth.auth_code_ttl", 10)) * time.Minute)

	if codeChallenge != "" && codeChallengeMethod != "" {
		return s.oauthService.CreateAuthCodeWithPKCE(userID, clientID, scopes, expiresAt, codeChallenge, codeChallengeMethod)
	}

	return s.oauthService.CreateAuthCode(userID, clientID, scopes, expiresAt)
}

// ValidateAuthorizationCode validates an authorization code
func (s *OIDCService) ValidateAuthorizationCode(code, clientID, redirectURI, codeVerifier string) (*models.OAuthAuthCode, error) {
	authCode, err := s.oauthService.ValidateAuthCode(code)
	if err != nil {
		return nil, err
	}

	// Check if auth code belongs to the client
	if authCode.ClientID != clientID {
		return nil, fmt.Errorf("authorization code does not belong to client")
	}

	// Validate redirect URI
	client := authCode.GetClient()
	allowedURIs := client.GetRedirectURIs()
	redirectURIValid := false
	for _, uri := range allowedURIs {
		if uri == redirectURI {
			redirectURIValid = true
			break
		}
	}
	if !redirectURIValid {
		return nil, fmt.Errorf("redirect URI mismatch")
	}

	// Validate PKCE if code challenge is present
	if authCode.CodeChallenge != nil && *authCode.CodeChallenge != "" {
		if codeVerifier == "" {
			return nil, fmt.Errorf("code verifier required for PKCE")
		}

		if !s.oauthService.ValidatePKCE(codeVerifier, *authCode.CodeChallenge, *authCode.CodeChallengeMethod) {
			return nil, fmt.Errorf("invalid code verifier")
		}
	}

	return authCode, nil
}

// GenerateTokenResponse generates a complete token response
func (s *OIDCService) GenerateTokenResponse(authCode *models.OAuthAuthCode, clientID string) (map[string]interface{}, error) {
	// Get user
	user := authCode.GetUser()
	if user == nil {
		return nil, fmt.Errorf("invalid authorization code")
	}

	// Generate token pair
	accessToken, refreshToken, err := s.oauthService.GenerateTokenPair(&user.ID, clientID, authCode.GetScopes(), nil)
	if err != nil {
		return nil, err
	}

	// Generate ID token if openid scope is requested
	var idToken string
	scopes := authCode.GetScopes()
	hasOpenIDScope := false
	for _, scope := range scopes {
		if scope == "openid" {
			hasOpenIDScope = true
			break
		}
	}

	if hasOpenIDScope {
		idToken, err = s.GenerateIDToken(user, clientID, scopes, "", accessToken.ID, authCode.ID, time.Now().Unix())
		if err != nil {
			return nil, err
		}
	}

	// Build response
	response := map[string]interface{}{
		"access_token":  accessToken.ID,
		"token_type":    "Bearer",
		"expires_in":    facades.Config().GetInt("oauth.access_token_ttl", 60) * 60,
		"scope":         s.oauthService.FormatScopes(scopes),
		"refresh_token": refreshToken.ID,
	}

	if idToken != "" {
		response["id_token"] = idToken
	}

	return response, nil
}

// ValidateTokenRequest validates a token request
func (s *OIDCService) ValidateTokenRequest(grantType, clientID, clientSecret string) (*models.OAuthClient, error) {
	// Validate client
	client, err := s.oauthService.ValidateClient(clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	// Validate grant type
	supportedGrantTypes := facades.Config().Get("oidc.grant_types_supported").([]string)
	grantTypeValid := false
	for _, gt := range supportedGrantTypes {
		if gt == grantType {
			grantTypeValid = true
			break
		}
	}
	if !grantTypeValid {
		return nil, fmt.Errorf("unsupported grant type")
	}

	return client, nil
}

// GetClientMetadata returns client metadata for discovery
func (s *OIDCService) GetClientMetadata(clientID string) (map[string]interface{}, error) {
	client, err := s.oauthService.GetClient(clientID)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"client_id":                  client.ID,
		"client_name":                client.Name,
		"redirect_uris":              client.GetRedirectURIs(),
		"token_endpoint_auth_method": "client_secret_basic",
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"scope":                      "openid profile email",
		"subject_type":               "public",
	}, nil
}

// ValidateSecurityRequirements validates security requirements
func (s *OIDCService) ValidateSecurityRequirements(ctx http.Context) error {
	// Check HTTPS requirement
	if facades.Config().GetBool("oidc.security.require_https", true) {
		// In production, you should check if the request is over HTTPS
		// For now, we'll skip this check in development
		if facades.Config().GetString("app.env") == "production" {
			// TODO: Implement HTTPS check
		}
	}

	return nil
}

// LogTokenUsage logs token usage for audit purposes
func (s *OIDCService) LogTokenUsage(tokenType, tokenID, clientID, userID string, scopes []string) {
	if !facades.Config().GetBool("oidc.logging.enable_token_usage_logging", true) {
		return
	}

	facades.Log().Info("Token Usage", map[string]interface{}{
		"token_type": tokenType,
		"token_id":   tokenID,
		"client_id":  clientID,
		"user_id":    userID,
		"scopes":     scopes,
		"timestamp":  time.Now().Unix(),
		"ip_address": "", // TODO: Get from context
		"user_agent": "", // TODO: Get from context
	})
}
