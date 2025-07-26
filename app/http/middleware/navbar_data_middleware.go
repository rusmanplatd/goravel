package middleware

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
	"goravel/app/services"
)

// NavbarData returns a middleware that adds navbar data to the view context
func NavbarData() http.Middleware {
	return func(ctx http.Context) {
		// Get user from context (should be set by WebAuth middleware)
		user, ok := ctx.Value("user").(*models.User)
		if !ok {
			// If no user, continue without adding navbar data
			ctx.Request().Next()
			return
		}

		// Get multi-account session info
		multiAccountService := services.NewMultiAccountService()
		accounts, _ := multiAccountService.GetAllAccounts(ctx)
		activeAccount, _ := multiAccountService.GetActiveAccount(ctx)
		hasMultipleAccounts := len(accounts) > 1

		// Get notification stats
		unreadNotifications, _ := facades.Orm().Query().Model(&models.Notification{}).
			Where("notifiable_id = ?", user.ID).
			Where("read_at IS NULL").
			Count()

		// Build stats for navbar
		stats := map[string]interface{}{
			"unread_notifications": unreadNotifications,
		}

		// Add navbar data to context
		ctx.WithValue("navbar_data", map[string]interface{}{
			"user":                  user,
			"accounts":              accounts,
			"active_account":        activeAccount,
			"has_multiple_accounts": hasMultipleAccounts,
			"account_count":         len(accounts),
			"stats":                 stats,
		})

		ctx.Request().Next()
	}
}
