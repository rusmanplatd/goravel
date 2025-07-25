package services

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"

	"goravel/app/helpers"
	"goravel/app/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goravel/framework/facades"
)

type OAuthService struct {
	jwtService    *JWTService
	rsaPrivateKey *rsa.PrivateKey
	rsaPublicKey  *rsa.PublicKey
}

func NewOAuthService() *OAuthService {
	service := &OAuthService{
		jwtService: NewJWTService(),
	}

	// Initialize RSA keys for JWT signing
	service.initializeRSAKeys()

	return service
}

// initializeRSAKeys initializes RSA key pair for JWT signing
func (s *OAuthService) initializeRSAKeys() {
	// Try to load existing keys or generate new ones
	privateKeyPEM := facades.Config().GetString("oauth.rsa_private_key", "")
	if privateKeyPEM == "" {
		// Generate new RSA key pair
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			facades.Log().Error("Failed to generate RSA key pair: " + err.Error())
			return
		}

		s.rsaPrivateKey = privateKey
		s.rsaPublicKey = &privateKey.PublicKey

		// Save keys to config for persistence (in production, use secure storage)
		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		privateKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		})

		publicKeyBytes, _ := x509.MarshalPKIXPublicKey(s.rsaPublicKey)
		publicKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		})

		facades.Log().Info("Generated new RSA key pair for OAuth2 JWT signing")
		facades.Log().Info("Private Key: " + string(privateKeyPEM))
		facades.Log().Info("Public Key: " + string(publicKeyPEM))
	} else {
		// Load existing keys
		block, _ := pem.Decode([]byte(privateKeyPEM))
		if block == nil {
			facades.Log().Error("Failed to decode RSA private key")
			return
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			facades.Log().Error("Failed to parse RSA private key: " + err.Error())
			return
		}

		s.rsaPrivateKey = privateKey
		s.rsaPublicKey = &privateKey.PublicKey
	}
}

// CreateJWTAccessToken creates a JWT access token
func (s *OAuthService) CreateJWTAccessToken(userID *string, clientID string, scopes []string, name *string) (string, error) {
	if s.rsaPrivateKey == nil {
		return "", fmt.Errorf("RSA private key not initialized")
	}

	ttl := facades.Config().GetInt("oauth.access_token_ttl", 60)

	// Get client information
	client, err := s.GetClient(clientID)
	if err != nil {
		return "", err
	}

	// Get user information if userID is provided
	var userEmail string
	if userID != nil {
		var user models.User
		if err := facades.Orm().Query().Where("id", *userID).First(&user); err == nil {
			userEmail = user.Email
		}
	}

	// Create JWT claims
	claims := jwt.MapClaims{
		"iss":    facades.Config().GetString("app.url", "http://localhost"),
		"sub":    userID,
		"aud":    clientID,
		"exp":    time.Now().Add(time.Duration(ttl) * time.Minute).Unix(),
		"iat":    time.Now().Unix(),
		"nbf":    time.Now().Unix(),
		"jti":    helpers.GenerateULID(),
		"scope":  strings.Join(scopes, " "),
		"client": client.Name,
		"email":  userEmail,
		"type":   "access_token",
	}

	// Create and sign token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.rsaPrivateKey)
}

// GetJWKS returns the JSON Web Key Set for JWT verification
func (s *OAuthService) GetJWKS() map[string]interface{} {
	if s.rsaPublicKey == nil {
		return map[string]interface{}{
			"keys": []interface{}{},
		}
	}

	// Convert public key to JWK format
	_, _ = x509.MarshalPKIXPublicKey(s.rsaPublicKey)

	return map[string]interface{}{
		"keys": []interface{}{
			map[string]interface{}{
				"kty": "RSA",
				"use": "sig",
				"kid": "oauth2-key-1",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(s.rsaPublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1}), // 65537
			},
		},
	}
}

// DetectSuspiciousActivity detects suspicious OAuth2 activity
func (s *OAuthService) DetectSuspiciousActivity(userID, clientID, ipAddress string, userAgent string) *SuspiciousActivityReport {
	report := &SuspiciousActivityReport{
		UserID:    userID,
		ClientID:  clientID,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Timestamp: time.Now(),
		Flags:     []string{},
		RiskScore: 0,
	}

	// Check for unusual IP address
	if s.isUnusualIP(userID, ipAddress) {
		report.Flags = append(report.Flags, "unusual_ip")
		report.RiskScore += 30
	}

	// Check for unusual user agent
	if s.isUnusualUserAgent(userID, userAgent) {
		report.Flags = append(report.Flags, "unusual_user_agent")
		report.RiskScore += 20
	}

	// Check for rapid successive requests
	if s.hasRapidRequests(userID, clientID) {
		report.Flags = append(report.Flags, "rapid_requests")
		report.RiskScore += 40
	}

	// Check for suspicious client
	if s.isSuspiciousClient(clientID) {
		report.Flags = append(report.Flags, "suspicious_client")
		report.RiskScore += 50
	}

	// Determine risk level
	if report.RiskScore >= 80 {
		report.RiskLevel = "HIGH"
	} else if report.RiskScore >= 50 {
		report.RiskLevel = "MEDIUM"
	} else if report.RiskScore >= 20 {
		report.RiskLevel = "LOW"
	} else {
		report.RiskLevel = "MINIMAL"
	}

	// Log suspicious activity
	if report.RiskScore > 0 {
		facades.Log().Warning("Suspicious OAuth2 activity detected", map[string]interface{}{
			"user_id":    userID,
			"client_id":  clientID,
			"ip_address": ipAddress,
			"risk_score": report.RiskScore,
			"risk_level": report.RiskLevel,
			"flags":      report.Flags,
		})
	}

	return report
}

type SuspiciousActivityReport struct {
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	Timestamp time.Time `json:"timestamp"`
	Flags     []string  `json:"flags"`
	RiskScore int       `json:"risk_score"`
	RiskLevel string    `json:"risk_level"`
}

// Helper methods for suspicious activity detection
func (s *OAuthService) isUnusualIP(userID, ipAddress string) bool {
	// Check if this IP is from a different country/region than usual
	// This is a simplified implementation
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return true
	}

	// Check if it's a private IP (less suspicious)
	if ip.IsPrivate() {
		return false
	}

	// In a real implementation, you would:
	// 1. Use a GeoIP service to determine location
	// 2. Compare with user's historical locations
	// 3. Check against known VPN/proxy ranges

	return false
}

func (s *OAuthService) isUnusualUserAgent(userID, userAgent string) bool {
	// Check if this user agent is significantly different from user's history
	// This is a simplified implementation

	// Basic checks for suspicious patterns
	suspiciousPatterns := []string{
		"curl", "wget", "python", "bot", "crawler", "scanner",
	}

	userAgentLower := strings.ToLower(userAgent)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(userAgentLower, pattern) {
			return true
		}
	}

	return false
}

func (s *OAuthService) hasRapidRequests(userID, clientID string) bool {
	// Check for rapid successive requests in the last minute
	// This would typically use a cache or rate limiting service

	// In a real implementation, you would:
	// 1. Use Redis to track request timestamps
	// 2. Count requests in the last minute
	// 3. Flag if more than a threshold (e.g., 10 requests/minute)

	return false
}

func (s *OAuthService) isSuspiciousClient(clientID string) bool {
	// Check if the client has been flagged as suspicious
	client, err := s.GetClient(clientID)
	if err != nil {
		return true
	}

	// Check for suspicious client patterns
	if client.IsRevoked() {
		return true
	}

	// In a real implementation, you might check:
	// 1. Client reputation score
	// 2. Recent security incidents
	// 3. Unusual permission requests

	return false
}

// CreateDeviceCodeWithQR creates a device code with QR code generation
func (s *OAuthService) CreateDeviceCodeWithQR(clientID string, scopes []string, expiresAt time.Time) (*models.OAuthDeviceCode, string, error) {
	// Create the device code
	deviceCode, err := s.CreateDeviceCode(clientID, scopes, expiresAt)
	if err != nil {
		return nil, "", err
	}

	// Generate verification URL with user code
	verificationURI := facades.Config().GetString("oauth.device_verification_uri", "https://example.com/device")
	verificationURIComplete := fmt.Sprintf("%s?user_code=%s", verificationURI, deviceCode.UserCode)

	// Generate QR code data (URL for QR code generation)
	qrCodeURL := fmt.Sprintf("https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=%s",
		fmt.Sprintf("Visit: %s", verificationURIComplete))

	return deviceCode, qrCodeURL, nil
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
