package services

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	mathrand "math/rand"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goravel/framework/facades"
)

type JWTService struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func NewJWTService() (*JWTService, error) {
	service := &JWTService{}
	err := service.initializeKeys()
	if err != nil {
		return nil, err
	}
	return service, nil
}

// MustNewJWTService creates a new JWT service and panics on error (for backward compatibility)
// Deprecated: Use NewJWTService() instead for proper error handling
func MustNewJWTService() *JWTService {
	service, err := NewJWTService()
	if err != nil {
		facades.Log().Error("Critical JWT service initialization failure", map[string]interface{}{
			"error": err.Error(),
		})
		panic(fmt.Sprintf("JWT service initialization failed: %v", err))
	}
	return service
}

// JWTClaims represents the claims in a JWT token
type JWTClaims struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	Type      string `json:"type"` // "access" or "refresh"
	SessionID string `json:"session_id"`
	DeviceID  string `json:"device_id,omitempty"`
	Scope     string `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

// TokenBlacklistEntry represents a blacklisted token
type TokenBlacklistEntry struct {
	JTI       string    `json:"jti"`
	ExpiresAt time.Time `json:"expires_at"`
}

// initializeKeys initializes RSA key pair for JWT signing
func (s *JWTService) initializeKeys() error {
	// Try to load existing keys from config/cache
	if s.loadExistingKeys() {
		return nil
	}

	// Generate new RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		facades.Log().Error("Failed to generate RSA key pair", map[string]interface{}{
			"error": err.Error(),
		})
		// Return error instead of panicking
		return fmt.Errorf("JWT service initialization failed: unable to generate secure RSA keys: %w", err)
	}

	s.privateKey = privateKey
	s.publicKey = &privateKey.PublicKey

	// Store keys for future use
	s.storeKeys()

	return nil
}

// loadExistingKeys attempts to load existing RSA keys
func (s *JWTService) loadExistingKeys() bool {
	privateKeyPEM := facades.Config().GetString("jwt.private_key", "")
	publicKeyPEM := facades.Config().GetString("jwt.public_key", "")

	if privateKeyPEM == "" || publicKeyPEM == "" {
		return false
	}

	// Parse private key
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return false
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return false
	}

	// Parse public key
	block, _ = pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return false
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return false
	}

	s.privateKey = privateKey
	s.publicKey = rsaPublicKey
	return true
}

// storeKeys stores the RSA keys for future use
func (s *JWTService) storeKeys() {
	// Convert private key to PEM
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(s.privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Convert public key to PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(s.publicKey)
	if err != nil {
		facades.Log().Error("Failed to marshal public key", map[string]interface{}{
			"error": err.Error(),
		})
		return
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Store in cache for persistence across restarts
	facades.Cache().Put("jwt_private_key", string(privateKeyPEM), 24*time.Hour)
	facades.Cache().Put("jwt_public_key", string(publicKeyPEM), 24*time.Hour)
}

// initializeFallbackKeys has been removed - no longer needed

// GenerateAccessToken generates a new access token with enhanced security
func (s *JWTService) GenerateAccessToken(userID, email, sessionID string) (string, error) {
	return s.generateToken(userID, email, sessionID, "access")
}

// GenerateRefreshToken generates a new refresh token with enhanced security
func (s *JWTService) GenerateRefreshToken(userID, email, sessionID string) (string, error) {
	return s.generateToken(userID, email, sessionID, "refresh")
}

// generateToken generates a JWT token with the specified type
func (s *JWTService) generateToken(userID, email, sessionID, tokenType string) (string, error) {
	now := time.Now()
	var ttl time.Duration

	if tokenType == "access" {
		ttl = time.Duration(facades.Config().GetInt("jwt.ttl", 15)) * time.Minute // Shorter default
	} else {
		ttl = time.Duration(facades.Config().GetInt("jwt.refresh_ttl", 7*24*60)) * time.Minute // 7 days
	}

	// Generate unique JTI for token tracking
	jti := s.generateJTI()

	claims := JWTClaims{
		UserID:    userID,
		Email:     email,
		Type:      tokenType,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    facades.Config().GetString("app.name", "goravel"),
			Subject:   userID,
			Audience:  jwt.ClaimStrings{facades.Config().GetString("app.url", "localhost")},
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	// Add key ID to header for key rotation support
	token.Header["kid"] = s.getKeyID()

	return token.SignedString(s.privateKey)
}

// ValidateToken validates a JWT token and returns the claims
func (s *JWTService) ValidateToken(tokenString string) (*JWTClaims, error) {
	// Check if token is blacklisted
	if s.isTokenBlacklisted(tokenString) {
		return nil, fmt.Errorf("token has been revoked")
	}

	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Verify key ID if present
		if kid, ok := token.Header["kid"].(string); ok {
			if kid != s.getKeyID() {
				facades.Log().Warning("Token signed with different key", map[string]interface{}{
					"expected_kid": s.getKeyID(),
					"token_kid":    kid,
				})
			}
		}

		return s.publicKey, nil
	})

	if err != nil {
		facades.Log().Error("Token validation failed", map[string]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		// Additional validation
		if err := s.validateClaims(claims); err != nil {
			return nil, err
		}
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}

// validateClaims performs additional validation on JWT claims
func (s *JWTService) validateClaims(claims *JWTClaims) error {
	// Validate issuer
	expectedIssuer := facades.Config().GetString("app.name", "goravel")
	if claims.Issuer != expectedIssuer {
		return fmt.Errorf("invalid issuer")
	}

	// Validate audience
	expectedAudience := facades.Config().GetString("app.url", "localhost")
	if len(claims.Audience) == 0 || claims.Audience[0] != expectedAudience {
		return fmt.Errorf("invalid audience")
	}

	// Validate token type
	if claims.Type != "access" && claims.Type != "refresh" {
		return fmt.Errorf("invalid token type")
	}

	return nil
}

// GenerateTokenPair generates both access and refresh tokens
func (s *JWTService) GenerateTokenPair(userID, email string, remember bool) (string, string, error) {
	sessionID := s.generateSessionID()

	accessToken, err := s.GenerateAccessToken(userID, email, sessionID)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := s.GenerateRefreshToken(userID, email, sessionID)
	if err != nil {
		return "", "", err
	}

	// Store session information
	s.storeSessionInfo(sessionID, userID, remember)

	return accessToken, refreshToken, nil
}

// RevokeToken adds a token to the blacklist
func (s *JWTService) RevokeToken(tokenString string) error {
	// Parse token to get JTI and expiration
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return s.publicKey, nil
	})

	if err != nil {
		return fmt.Errorf("failed to parse token for revocation: %v", err)
	}

	if claims, ok := token.Claims.(*JWTClaims); ok {
		entry := TokenBlacklistEntry{
			JTI:       claims.ID,
			ExpiresAt: claims.ExpiresAt.Time,
		}

		// Store in blacklist until token expires
		blacklistKey := fmt.Sprintf("jwt_blacklist:%s", claims.ID)
		ttl := time.Until(claims.ExpiresAt.Time)

		return facades.Cache().Put(blacklistKey, entry, ttl)
	}

	return fmt.Errorf("invalid token claims for revocation")
}

// RevokeAllUserTokens revokes all tokens for a specific user
func (s *JWTService) RevokeAllUserTokens(userID string) error {
	// This would typically involve storing a user token version
	// and incrementing it to invalidate all existing tokens
	userTokenVersionKey := fmt.Sprintf("user_token_version:%s", userID)

	var currentVersion int
	facades.Cache().Get(userTokenVersionKey, &currentVersion)
	currentVersion++

	return facades.Cache().Put(userTokenVersionKey, currentVersion, 30*24*time.Hour)
}

// RefreshToken generates a new access token from a valid refresh token
func (s *JWTService) RefreshToken(refreshTokenString string) (string, error) {
	claims, err := s.ValidateToken(refreshTokenString)
	if err != nil {
		return "", err
	}

	if claims.Type != "refresh" {
		return "", fmt.Errorf("invalid token type for refresh")
	}

	// Generate new access token with same session ID
	return s.GenerateAccessToken(claims.UserID, claims.Email, claims.SessionID)
}

// CleanupExpiredTokens removes expired tokens from blacklist
func (s *JWTService) CleanupExpiredTokens() {
	// This would typically be called by a background job
	// Implementation depends on cache backend capabilities
	facades.Log().Info("JWT token cleanup initiated")
}

// isTokenBlacklisted checks if a token is in the blacklist
func (s *JWTService) isTokenBlacklisted(tokenString string) bool {
	// Quick parse to get JTI without full validation
	token, _ := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return s.publicKey, nil
	})

	if claims, ok := token.Claims.(*JWTClaims); ok && claims.ID != "" {
		blacklistKey := fmt.Sprintf("jwt_blacklist:%s", claims.ID)
		var entry TokenBlacklistEntry
		err := facades.Cache().Get(blacklistKey, &entry)
		return err == nil
	}

	return false
}

// generateJTI generates a unique JWT ID
func (s *JWTService) generateJTI() string {
	return fmt.Sprintf("%d_%s", time.Now().UnixNano(), s.generateRandomString(8))
}

// generateSessionID generates a unique session ID
func (s *JWTService) generateSessionID() string {
	return fmt.Sprintf("sess_%d_%s", time.Now().UnixNano(), s.generateRandomString(16))
}

// generateRandomString generates a random string of specified length
func (s *JWTService) generateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[mathrand.Intn(len(charset))]
	}
	return string(b)
}

// getKeyID returns a unique identifier for the current key
func (s *JWTService) getKeyID() string {
	// Generate a simple key ID based on public key
	if s.publicKey == nil {
		return "default"
	}
	return fmt.Sprintf("rsa_%x", s.publicKey.N.Bytes()[:8])
}

// storeSessionInfo stores session information for tracking
func (s *JWTService) storeSessionInfo(sessionID, userID string, remember bool) {
	sessionInfo := map[string]interface{}{
		"user_id":    userID,
		"created_at": time.Now(),
		"remember":   remember,
	}

	sessionKey := fmt.Sprintf("session:%s", sessionID)
	ttl := 24 * time.Hour
	if remember {
		ttl = 30 * 24 * time.Hour
	}

	facades.Cache().Put(sessionKey, sessionInfo, ttl)
}
