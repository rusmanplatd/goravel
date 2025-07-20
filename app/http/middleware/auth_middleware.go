package middleware

import (
	"fmt"
	"strings"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
	"goravel/app/services"
)

type AuthMiddleware struct {
	jwtService *services.JWTService
}

func NewAuthMiddleware() *AuthMiddleware {
	return &AuthMiddleware{
		jwtService: services.NewJWTService(),
	}
}

func (m *AuthMiddleware) Handle(ctx http.Context) http.Response {
	// Get Authorization header
	authHeader := ctx.Request().Header("Authorization", "")
	if authHeader == "" {
		return ctx.Response().Status(401).Json(http.Json{
			"status":  "error",
			"message": "Authorization header required",
		})
	}

	// Check if it's a Bearer token
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return ctx.Response().Status(401).Json(http.Json{
			"status":  "error",
			"message": "Invalid authorization format",
		})
	}

	// Extract token
	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Validate token and get user
	user, err := m.validateToken(token)
	if err != nil {
		return ctx.Response().Status(401).Json(http.Json{
			"status":  "error",
			"message": "Invalid token",
		})
	}

	// Add user to context
	ctx.WithValue("user", user)
	ctx.WithValue("user_id", user.ID)

	ctx.Request().Next()
	return nil
}

// validateToken validates JWT token and returns user
func (m *AuthMiddleware) validateToken(token string) (*models.User, error) {
	// Validate token using JWT service
	claims, err := m.jwtService.ValidateToken(token)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	// Check if it's an access token
	if claims.Type != "access" {
		return nil, fmt.Errorf("invalid token type")
	}

	// Find user by ID
	var user models.User
	err = facades.Orm().Query().Where("id", claims.UserID).First(&user)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, fmt.Errorf("user account is deactivated")
	}

	return &user, nil
}

// Auth helper function
func Auth() func(ctx http.Context) http.Response {
	middleware := NewAuthMiddleware()
	return middleware.Handle
}
