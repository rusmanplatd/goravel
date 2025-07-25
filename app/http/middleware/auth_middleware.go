package middleware

import (
	"fmt"
	"strings"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
	"goravel/app/services"
)

// Auth returns a middleware function for authentication
func Auth() http.Middleware {
	return func(ctx http.Context) {
		// Get Authorization header
		authHeader := ctx.Request().Header("Authorization", "")
		if authHeader == "" {
			ctx.Response().Status(401).Json(http.Json{
				"status":  "error",
				"message": "Authorization header required",
			})
			return
		}

		// Check if it's a Bearer token
		if !strings.HasPrefix(authHeader, "Bearer ") {
			ctx.Response().Status(401).Json(http.Json{
				"status":  "error",
				"message": "Invalid authorization format",
			})
			return
		}

		// Extract token
		token := strings.TrimPrefix(authHeader, "Bearer ")

		// Validate token and get user
		user, err := validateToken(token)
		if err != nil {
			ctx.Response().Status(401).Json(http.Json{
				"status":  "error",
				"message": "Invalid token",
			})
			return
		}

		// Add user to context
		ctx.WithValue("user", user)
		ctx.WithValue("user_id", user.ID)

		// Continue to next middleware/handler
		ctx.Request().Next()
	}
}

// validateToken validates JWT token and returns user
func validateToken(token string) (*models.User, error) {
	// Create JWT service instance
	jwtService := services.NewJWTService()

	// Validate token using JWT service
	claims, err := jwtService.ValidateToken(token)
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
