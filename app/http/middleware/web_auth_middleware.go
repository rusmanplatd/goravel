package middleware

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
	"goravel/app/services"
)

// WebAuth returns a middleware function for web authentication using multi-account sessions
func WebAuth() http.Middleware {
	return func(ctx http.Context) {
		facades.Log().Info("WebAuth middleware: Starting execution")

		// Check if session is available
		session := ctx.Request().Session()
		if session == nil {
			facades.Log().Info("WebAuth middleware: No session available, redirecting to login")
			ctx.Response().Redirect(302, "/login")
			return
		}

		facades.Log().Info("WebAuth middleware: Session found, checking multi-account session")
		multiAccountService, err := services.NewMultiAccountService()
		if err != nil {
			facades.Log().Error("Failed to create multi-account service", map[string]interface{}{
				"error": err.Error(),
			})
			ctx.Response().Redirect(302, "/login")
			return
		}

		// Get active account from multi-account session
		activeAccount, err := multiAccountService.GetActiveAccount(ctx)
		if err != nil || activeAccount == nil {
			facades.Log().Info("WebAuth middleware: No active account found, redirecting to login", map[string]interface{}{
				"error": err,
			})
			ctx.Response().Redirect(302, "/login")
			return
		}

		facades.Log().Info("WebAuth middleware: Active account found", map[string]interface{}{
			"user_id": activeAccount.UserID,
			"email":   activeAccount.Email,
		})

		// Get full user data from database
		var user models.User
		err = facades.Orm().Query().Where("id", activeAccount.UserID).First(&user)
		if err != nil {
			facades.Log().Error("WebAuth middleware: User not found in database", map[string]interface{}{
				"user_id": activeAccount.UserID,
				"error":   err.Error(),
			})
			// Clear multi-account session and redirect to login
			multiAccountService.ClearAllAccounts(ctx)
			ctx.Response().Redirect(302, "/login")
			return
		}

		// Check if user is active
		if !user.IsActive {
			facades.Log().Warning("WebAuth middleware: User account is not active", map[string]interface{}{
				"user_id": activeAccount.UserID,
			})
			// Clear multi-account session and redirect to login
			multiAccountService.ClearAllAccounts(ctx)
			ctx.Response().Redirect(302, "/login?error=account_deactivated")
			return
		}

		facades.Log().Info("WebAuth middleware: Authentication successful", map[string]interface{}{
			"user_id": user.ID,
			"email":   user.Email,
		})

		// Add user to context
		ctx.WithValue("user", &user)
		ctx.WithValue("user_id", user.ID)
		ctx.WithValue("multi_account_session", true)

		facades.Log().Info("WebAuth middleware: User added to context, continuing to next handler")

		// Continue to next middleware/handler
		ctx.Request().Next()
	}
}
