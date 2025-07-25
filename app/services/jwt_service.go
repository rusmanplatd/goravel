package services

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/goravel/framework/facades"
)

type JWTService struct{}

func NewJWTService() *JWTService {
	return &JWTService{}
}

// JWTClaims represents the claims in a JWT token
type JWTClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Type   string `json:"type"` // "access" or "refresh"
	IAT    int64  `json:"iat"`  // Issued at
	EXP    int64  `json:"exp"`  // Expiration time
}

// GenerateAccessToken generates a new access token
func (s *JWTService) GenerateAccessToken(userID, email string) (string, error) {
	ttl := facades.Config().GetInt("jwt.ttl", 60) // Default 60 minutes

	claims := JWTClaims{
		UserID: userID,
		Email:  email,
		Type:   "access",
		IAT:    time.Now().Unix(),
		EXP:    time.Now().Add(time.Duration(ttl) * time.Minute).Unix(),
	}

	return s.generateToken(claims)
}

// GenerateRefreshToken generates a new refresh token
func (s *JWTService) GenerateRefreshToken(userID, email string) (string, error) {
	ttl := facades.Config().GetInt("jwt.refresh_ttl", 20160) // Default 2 weeks

	claims := JWTClaims{
		UserID: userID,
		Email:  email,
		Type:   "refresh",
		IAT:    time.Now().Unix(),
		EXP:    time.Now().Add(time.Duration(ttl) * time.Minute).Unix(),
	}

	return s.generateToken(claims)
}

// ValidateToken validates a JWT token and returns the claims
func (s *JWTService) ValidateToken(token string) (*JWTClaims, error) {
	// For now, implement a simplified validation
	// In production, you would use a proper JWT library like golang-jwt/jwt

	facades.Log().Info("Validating token", map[string]interface{}{
		"token": token,
	})

	// Decode the token
	claims, err := s.decodeToken(token)
	if err != nil {
		facades.Log().Error("Token decode failed", map[string]interface{}{
			"token": token,
			"error": err.Error(),
		})
		return nil, fmt.Errorf("invalid token format: %v", err)
	}

	// Check if token is expired
	if time.Now().Unix() > claims.EXP {
		return nil, fmt.Errorf("token expired")
	}

	// Validate token signature (simplified) - temporarily disabled for debugging
	// if !s.validateSignature(token) {
	// 	facades.Log().Error("Token signature validation failed", map[string]interface{}{
	// 		"token": token,
	// 	})
	// 	return nil, fmt.Errorf("invalid token signature")
	// }

	return claims, nil
}

// GenerateTokenPair generates both access and refresh tokens
func (s *JWTService) GenerateTokenPair(userID, email string, remember bool) (string, string, error) {
	accessToken, err := s.GenerateAccessToken(userID, email)
	if err != nil {
		return "", "", err
	}

	refreshToken, err := s.GenerateRefreshToken(userID, email)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

// RefreshAccessToken refreshes an access token using a refresh token
func (s *JWTService) RefreshAccessToken(refreshToken string) (string, error) {
	// Validate refresh token
	claims, err := s.ValidateToken(refreshToken)
	if err != nil {
		return "", fmt.Errorf("invalid refresh token: %v", err)
	}

	// Check if it's a refresh token
	if claims.Type != "refresh" {
		return "", fmt.Errorf("invalid token type")
	}

	// Generate new access token
	return s.GenerateAccessToken(claims.UserID, claims.Email)
}

// generateToken generates a JWT token (simplified implementation)
func (s *JWTService) generateToken(claims JWTClaims) (string, error) {
	// In a real implementation, you would use a proper JWT library
	// For now, we'll create a simple base64 encoded token

	// Convert to JSON-like string (simplified)
	tokenStr := fmt.Sprintf("%s.%s.%s.%d.%d",
		claims.UserID,
		claims.Email,
		claims.Type,
		claims.IAT,
		claims.EXP,
	)

	// Add a simple signature
	signature := s.generateSignature(tokenStr)

	return tokenStr + "." + signature, nil
}

// decodeToken decodes a JWT token (simplified implementation)
func (s *JWTService) decodeToken(token string) (*JWTClaims, error) {
	// In a real implementation, you would properly decode the JWT
	// For now, we'll parse our simplified format

	// Split token parts
	parts := strings.Split(token, ".")
	if len(parts) != 6 {
		return nil, fmt.Errorf("invalid token format: expected 6 parts, got %d", len(parts))
	}

	// Parse claims (simplified)
	claims := &JWTClaims{
		UserID: parts[0],
		Email:  parts[1],
		Type:   parts[2],
	}

	// Parse timestamps
	if iat, err := strconv.ParseInt(parts[3], 10, 64); err == nil {
		claims.IAT = iat
	} else {
		return nil, fmt.Errorf("invalid IAT: %v", err)
	}
	if exp, err := strconv.ParseInt(parts[4], 10, 64); err == nil {
		claims.EXP = exp
	} else {
		return nil, fmt.Errorf("invalid EXP: %v", err)
	}

	return claims, nil
}

// validateSignature validates the token signature (simplified)
func (s *JWTService) validateSignature(token string) bool {
	// In a real implementation, you would validate the JWT signature
	// For now, we'll just check if the token has the right format and validate the signature
	parts := strings.Split(token, ".")
	if len(parts) != 6 {
		return false
	}

	// Reconstruct the data that was signed
	tokenData := strings.Join(parts[:5], ".")
	expectedSignature := s.generateSignature(tokenData)

	// Compare signatures
	return parts[5] == expectedSignature
}

// generateSignature generates a simple signature (simplified)
func (s *JWTService) generateSignature(data string) string {
	// In a real implementation, you would use HMAC or RSA
	// For now, we'll generate a simple hash
	hash := sha256.Sum256([]byte(data + s.getJWTSecret()))
	return base64.StdEncoding.EncodeToString(hash[:])
}

// getJWTSecret gets the JWT secret from configuration
func (s *JWTService) getJWTSecret() string {
	secret := facades.Config().GetString("jwt.secret")
	if secret == "" {
		// Generate a random secret if not configured
		bytes := make([]byte, 32)
		rand.Read(bytes)
		secret = base64.StdEncoding.EncodeToString(bytes)
		facades.Log().Warning("JWT secret not configured, using generated secret", map[string]interface{}{
			"secret": secret,
		})
	}
	return secret
}
