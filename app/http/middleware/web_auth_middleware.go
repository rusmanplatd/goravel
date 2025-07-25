package middleware

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
)

// WebAuth returns a middleware function for web authentication using sessions
func WebAuth() http.Middleware {
	return func(ctx http.Context) {
		// Check if user is already authenticated via session
		userID := ctx.Request().Session().Get("user_id")
		if userID == nil {
			// Redirect to login page for web routes
			ctx.Response().Redirect(302, "/login")
			return
		}

		// Get user from database
		var user models.User
		err := facades.Orm().Query().Where("id", userID).First(&user)
		if err != nil {
			// Clear invalid session and redirect to login
			ctx.Request().Session().Forget("user_id")
			ctx.Request().Session().Forget("user_email")
			ctx.Response().Redirect(302, "/login")
			return
		}

		// Check if user is active
		if !user.IsActive {
			// Clear session and redirect to login
			ctx.Request().Session().Forget("user_id")
			ctx.Request().Session().Forget("user_email")
			ctx.Response().Redirect(302, "/login?error=account_deactivated")
			return
		}

		// Add user to context
		ctx.WithValue("user", &user)
		ctx.WithValue("user_id", user.ID)

		// Continue to next middleware/handler
		ctx.Request().Next()
	}
}
