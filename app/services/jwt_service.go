package services

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
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
	jwt.RegisteredClaims
}

// GenerateAccessToken generates a new access token
func (s *JWTService) GenerateAccessToken(userID, email string) (string, error) {
	ttl := facades.Config().GetInt("jwt.ttl", 60) // Default 60 minutes

	claims := JWTClaims{
		UserID: userID,
		Email:  email,
		Type:   "access",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(ttl) * time.Minute)),
			Issuer:    facades.Config().GetString("app.name", "goravel"),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.getJWTSecret()))
}

// GenerateRefreshToken generates a new refresh token
func (s *JWTService) GenerateRefreshToken(userID, email string) (string, error) {
	ttl := facades.Config().GetInt("jwt.refresh_ttl", 20160) // Default 2 weeks

	claims := JWTClaims{
		UserID: userID,
		Email:  email,
		Type:   "refresh",
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(ttl) * time.Minute)),
			Issuer:    facades.Config().GetString("app.name", "goravel"),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.getJWTSecret()))
}

// ValidateToken validates a JWT token and returns the claims
func (s *JWTService) ValidateToken(tokenString string) (*JWTClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.getJWTSecret()), nil
	})

	if err != nil {
		facades.Log().Error("Token validation failed", map[string]interface{}{
			"token": tokenString,
			"error": err.Error(),
		})
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	if claims, ok := token.Claims.(*JWTClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
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

// getJWTSecret gets the JWT secret from configuration
func (s *JWTService) getJWTSecret() string {
	secret := facades.Config().GetString("jwt.secret")
	if secret == "" {
		// Use app key as fallback
		secret = facades.Config().GetString("app.key")
		if secret == "" {
			facades.Log().Error("JWT secret not configured and no app key found")
			return "fallback-secret-key"
		}
		facades.Log().Warning("JWT secret not configured, using app key")
	}
	return secret
}
