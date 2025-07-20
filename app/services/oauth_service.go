package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"goravel/app/helpers"
	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type OAuthService struct {
	jwtService *JWTService
}

func NewOAuthService() *OAuthService {
	return &OAuthService{
		jwtService: NewJWTService(),
	}
}

// CreateClient creates a new OAuth2 client
func (s *OAuthService) CreateClient(name string, userID *string, redirectURIs []string, personalAccessClient, passwordClient bool) (*models.OAuthClient, error) {
	client := &models.OAuthClient{
		ID:                   helpers.GenerateULID(),
		UserID:               userID,
		Name:                 name,
		PersonalAccessClient: personalAccessClient,
		PasswordClient:       passwordClient,
		Revoked:              false,
	}

	// Set redirect URIs
	client.SetRedirectURIs(redirectURIs)

	// Generate secret for confidential clients
	if !personalAccessClient {
		secret := s.generateClientSecret()
		client.Secret = &secret
	}

	err := facades.Orm().Query().Create(client)
	if err != nil {
		return nil, err
	}

	// If this is a personal access client, create the personal access client record
	if personalAccessClient {
		personalClient := &models.OAuthPersonalAccessClient{
			ID:       helpers.GenerateULID(),
			ClientID: client.ID,
		}
		facades.Orm().Query().Create(personalClient)
	}

	return client, nil
}

// GetClient retrieves an OAuth2 client by ID
func (s *OAuthService) GetClient(clientID string) (*models.OAuthClient, error) {
	var client models.OAuthClient
	err := facades.Orm().Query().Where("id", clientID).First(&client)
	if err != nil {
		return nil, err
	}
	return &client, nil
}

// ValidateClient validates client credentials
func (s *OAuthService) ValidateClient(clientID, clientSecret string) (*models.OAuthClient, error) {
	client, err := s.GetClient(clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client")
	}

	if client.IsRevoked() {
		return nil, fmt.Errorf("client is revoked")
	}

	// For confidential clients, validate the secret
	if client.IsConfidential() {
		if client.Secret == nil || *client.Secret != clientSecret {
			return nil, fmt.Errorf("invalid client secret")
		}
	}

	return client, nil
}

// CreateAccessToken creates a new access token
func (s *OAuthService) CreateAccessToken(userID *string, clientID string, scopes []string, name *string) (*models.OAuthAccessToken, error) {
	token := &models.OAuthAccessToken{
		ID:       s.generateTokenID(),
		UserID:   userID,
		ClientID: clientID,
		Name:     name,
		Revoked:  false,
	}

	token.SetScopes(scopes)

	err := facades.Orm().Query().Create(token)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// CreateRefreshToken creates a new refresh token
func (s *OAuthService) CreateRefreshToken(accessTokenID string, expiresAt time.Time) (*models.OAuthRefreshToken, error) {
	token := &models.OAuthRefreshToken{
		ID:            s.generateTokenID(),
		AccessTokenID: accessTokenID,
		Revoked:       false,
		ExpiresAt:     expiresAt,
	}

	err := facades.Orm().Query().Create(token)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// CreateAuthCode creates a new authorization code
func (s *OAuthService) CreateAuthCode(userID, clientID string, scopes []string, expiresAt time.Time) (*models.OAuthAuthCode, error) {
	code := &models.OAuthAuthCode{
		ID:        s.generateTokenID(),
		UserID:    userID,
		ClientID:  clientID,
		Revoked:   false,
		ExpiresAt: expiresAt,
	}

	code.SetScopes(scopes)

	err := facades.Orm().Query().Create(code)
	if err != nil {
		return nil, err
	}

	return code, nil
}

// CreateAuthCodeWithPKCE creates a new authorization code with PKCE support
func (s *OAuthService) CreateAuthCodeWithPKCE(userID, clientID string, scopes []string, expiresAt time.Time, codeChallenge, codeChallengeMethod string) (*models.OAuthAuthCode, error) {
	code := &models.OAuthAuthCode{
		ID:                  s.generateTokenID(),
		UserID:              userID,
		ClientID:            clientID,
		Revoked:             false,
		ExpiresAt:           expiresAt,
		CodeChallenge:       &codeChallenge,
		CodeChallengeMethod: &codeChallengeMethod,
	}

	code.SetScopes(scopes)

	err := facades.Orm().Query().Create(code)
	if err != nil {
		return nil, err
	}

	return code, nil
}

// ValidatePKCE validates PKCE parameters
func (s *OAuthService) ValidatePKCE(codeVerifier, codeChallenge, codeChallengeMethod string) bool {
	if codeChallengeMethod == "S256" {
		// SHA256 hash of code_verifier
		hash := sha256.Sum256([]byte(codeVerifier))
		calculatedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
		return calculatedChallenge == codeChallenge
	} else if codeChallengeMethod == "plain" {
		return codeVerifier == codeChallenge
	}
	return false
}

// CreateDeviceCode creates a new device authorization code
func (s *OAuthService) CreateDeviceCode(clientID string, scopes []string, expiresAt time.Time) (*models.OAuthDeviceCode, error) {
	deviceCode := &models.OAuthDeviceCode{
		ID:        s.generateTokenID(),
		ClientID:  clientID,
		Revoked:   false,
		ExpiresAt: expiresAt,
		UserCode:  s.generateUserCode(),
	}

	deviceCode.SetScopes(scopes)

	err := facades.Orm().Query().Create(deviceCode)
	if err != nil {
		return nil, err
	}

	return deviceCode, nil
}

// ValidateDeviceCode validates a device authorization code
func (s *OAuthService) ValidateDeviceCode(deviceCode string) (*models.OAuthDeviceCode, error) {
	var code models.OAuthDeviceCode
	err := facades.Orm().Query().Where("id", deviceCode).First(&code)
	if err != nil {
		return nil, fmt.Errorf("invalid device code")
	}

	if code.IsRevoked() {
		return nil, fmt.Errorf("device code is revoked")
	}

	if code.IsExpired() {
		return nil, fmt.Errorf("device code is expired")
	}

	return &code, nil
}

// ValidateUserCode validates a user code for device authorization
func (s *OAuthService) ValidateUserCode(userCode string) (*models.OAuthDeviceCode, error) {
	var code models.OAuthDeviceCode
	err := facades.Orm().Query().Where("user_code", userCode).First(&code)
	if err != nil {
		return nil, fmt.Errorf("invalid user code")
	}

	if code.IsRevoked() {
		return nil, fmt.Errorf("user code is revoked")
	}

	if code.IsExpired() {
		return nil, fmt.Errorf("user code is expired")
	}

	return &code, nil
}

// CompleteDeviceAuthorization completes device authorization by setting user ID
func (s *OAuthService) CompleteDeviceAuthorization(deviceCodeID, userID string) error {
	var code models.OAuthDeviceCode
	err := facades.Orm().Query().Where("id", deviceCodeID).First(&code)
	if err != nil {
		return err
	}

	code.UserID = &userID
	code.Authorized = true

	return facades.Orm().Query().Save(&code)
}

// ValidateAccessToken validates an access token
func (s *OAuthService) ValidateAccessToken(tokenID string) (*models.OAuthAccessToken, error) {
	var token models.OAuthAccessToken
	err := facades.Orm().Query().Where("id", tokenID).First(&token)
	if err != nil {
		return nil, fmt.Errorf("invalid access token")
	}

	if token.IsRevoked() {
		return nil, fmt.Errorf("access token is revoked")
	}

	return &token, nil
}

// ValidateRefreshToken validates a refresh token
func (s *OAuthService) ValidateRefreshToken(tokenID string) (*models.OAuthRefreshToken, error) {
	var token models.OAuthRefreshToken
	err := facades.Orm().Query().Where("id", tokenID).First(&token)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	if token.IsRevoked() {
		return nil, fmt.Errorf("refresh token is revoked")
	}

	if token.IsExpired() {
		return nil, fmt.Errorf("refresh token is expired")
	}

	return &token, nil
}

// ValidateAuthCode validates an authorization code
func (s *OAuthService) ValidateAuthCode(codeID string) (*models.OAuthAuthCode, error) {
	var code models.OAuthAuthCode
	err := facades.Orm().Query().Where("id", codeID).First(&code)
	if err != nil {
		return nil, fmt.Errorf("invalid authorization code")
	}

	if code.IsRevoked() {
		return nil, fmt.Errorf("authorization code is revoked")
	}

	if code.IsExpired() {
		return nil, fmt.Errorf("authorization code is expired")
	}

	return &code, nil
}

// RevokeAccessToken revokes an access token
func (s *OAuthService) RevokeAccessToken(tokenID string) error {
	token, err := s.ValidateAccessToken(tokenID)
	if err != nil {
		return err
	}

	return token.Revoke()
}

// RevokeRefreshToken revokes a refresh token
func (s *OAuthService) RevokeRefreshToken(tokenID string) error {
	token, err := s.ValidateRefreshToken(tokenID)
	if err != nil {
		return err
	}

	return token.Revoke()
}

// RevokeAuthCode revokes an authorization code
func (s *OAuthService) RevokeAuthCode(codeID string) error {
	code, err := s.ValidateAuthCode(codeID)
	if err != nil {
		return err
	}

	return code.Revoke()
}

// RevokeDeviceCode revokes a device authorization code
func (s *OAuthService) RevokeDeviceCode(deviceCodeID string) error {
	code, err := s.ValidateDeviceCode(deviceCodeID)
	if err != nil {
		return err
	}

	return code.Revoke()
}

// GetUserTokens gets all access tokens for a user
func (s *OAuthService) GetUserTokens(userID string) ([]models.OAuthAccessToken, error) {
	var tokens []models.OAuthAccessToken
	err := facades.Orm().Query().Where("user_id", userID).Find(&tokens)
	return tokens, err
}

// GetClientTokens gets all access tokens for a client
func (s *OAuthService) GetClientTokens(clientID string) ([]models.OAuthAccessToken, error) {
	var tokens []models.OAuthAccessToken
	err := facades.Orm().Query().Where("client_id", clientID).Find(&tokens)
	return tokens, err
}

// GetPersonalAccessClient gets the personal access client
func (s *OAuthService) GetPersonalAccessClient() (*models.OAuthClient, error) {
	var personalClient models.OAuthPersonalAccessClient
	err := facades.Orm().Query().First(&personalClient)
	if err != nil {
		return nil, err
	}

	return s.GetClient(personalClient.ClientID)
}

// CreatePersonalAccessClient creates a personal access client if it doesn't exist
func (s *OAuthService) CreatePersonalAccessClient() (*models.OAuthClient, error) {
	// Check if personal access client already exists
	personalClient, err := s.GetPersonalAccessClient()
	if err == nil {
		return personalClient, nil
	}

	// Create new personal access client
	client, err := s.CreateClient(
		"Goravel Personal Access Client",
		nil,
		[]string{},
		true,
		false,
	)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// GenerateTokenPair generates a new access token and refresh token pair
func (s *OAuthService) GenerateTokenPair(userID *string, clientID string, scopes []string, name *string) (*models.OAuthAccessToken, *models.OAuthRefreshToken, error) {
	// Create access token
	accessToken, err := s.CreateAccessToken(userID, clientID, scopes, name)
	if err != nil {
		return nil, nil, err
	}

	// Create refresh token
	refreshTokenExpiry := time.Now().Add(time.Duration(facades.Config().GetInt("oauth.refresh_token_ttl", 20160)) * time.Minute)
	refreshToken, err := s.CreateRefreshToken(accessToken.ID, refreshTokenExpiry)
	if err != nil {
		// Clean up access token if refresh token creation fails
		s.RevokeAccessToken(accessToken.ID)
		return nil, nil, err
	}

	return accessToken, refreshToken, nil
}

// ExchangeToken exchanges one token for another (Token Exchange Grant)
func (s *OAuthService) ExchangeToken(subjectToken, subjectTokenType, requestedTokenType string, clientID string, scopes []string) (*models.OAuthAccessToken, error) {
	// Validate subject token based on type
	var subjectUserID *string

	switch subjectTokenType {
	case "access_token":
		accessToken, err := s.ValidateAccessToken(subjectToken)
		if err != nil {
			return nil, fmt.Errorf("invalid subject access token")
		}
		subjectUserID = accessToken.UserID
	case "refresh_token":
		refreshToken, err := s.ValidateRefreshToken(subjectToken)
		if err != nil {
			return nil, fmt.Errorf("invalid subject refresh token")
		}
		// Get the access token to find the user
		accessToken, err := s.ValidateAccessToken(refreshToken.AccessTokenID)
		if err != nil {
			return nil, fmt.Errorf("invalid subject token")
		}
		subjectUserID = accessToken.UserID
	default:
		return nil, fmt.Errorf("unsupported subject token type")
	}

	// Create new token based on requested type
	switch requestedTokenType {
	case "access_token":
		return s.CreateAccessToken(subjectUserID, clientID, scopes, nil)
	default:
		return nil, fmt.Errorf("unsupported requested token type")
	}
}

// generateClientSecret generates a random client secret
func (s *OAuthService) generateClientSecret() string {
	length := facades.Config().GetInt("oauth.client_secret_length", 40)
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// generateTokenID generates a random token ID
func (s *OAuthService) generateTokenID() string {
	length := facades.Config().GetInt("oauth.token_id_length", 40)
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// generateUserCode generates a user-friendly code for device authorization
func (s *OAuthService) generateUserCode() string {
	bytes := make([]byte, 4)
	rand.Read(bytes)
	return strings.ToUpper(hex.EncodeToString(bytes))
}

// ParseScopes parses a space-separated scope string into a slice
func (s *OAuthService) ParseScopes(scopeString string) []string {
	if scopeString == "" {
		return []string{}
	}
	return strings.Fields(scopeString)
}

// FormatScopes formats a slice of scopes into a space-separated string
func (s *OAuthService) FormatScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}

// ValidateScopes validates that all scopes are allowed
func (s *OAuthService) ValidateScopes(scopes []string) bool {
	if !facades.Config().GetBool("oauth.enable_scope_validation", true) {
		return true
	}

	allowedScopes := s.GetAllowedScopes()
	allowedScopesMap := make(map[string]bool)
	for _, scope := range allowedScopes {
		allowedScopesMap[scope] = true
	}

	for _, scope := range scopes {
		if !allowedScopesMap[scope] {
			return false
		}
	}

	return true
}

// GetAllowedScopes returns the list of allowed scopes
func (s *OAuthService) GetAllowedScopes() []string {
	scopes := facades.Config().Get("oauth.allowed_scopes")
	if scopes == nil {
		return []string{"read", "write"}
	}

	scopesSlice, ok := scopes.([]string)
	if !ok {
		return []string{"read", "write"}
	}

	return scopesSlice
}

// LogOAuthEvent logs an OAuth event for audit purposes
func (s *OAuthService) LogOAuthEvent(eventType, clientID, userID string, details map[string]interface{}) {
	if !facades.Config().GetBool("oauth.logging.enable_event_logging", true) {
		return
	}

	logData := map[string]interface{}{
		"event_type": eventType,
		"client_id":  clientID,
		"user_id":    userID,
		"timestamp":  time.Now().UTC(),
		"details":    details,
	}

	facades.Log().Info("OAuth Event", logData)
}
