package web

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/services"
)

type AccountSwitcherController struct {
	multiAccountService *services.MultiAccountService
}

func NewAccountSwitcherController() *AccountSwitcherController {
	return &AccountSwitcherController{
		multiAccountService: services.NewMultiAccountService(),
	}
}

// GetAccounts returns all accounts in the current session
func (c *AccountSwitcherController) GetAccounts(ctx http.Context) http.Response {
	accounts, err := c.multiAccountService.GetAllAccounts(ctx)
	if err != nil {
		facades.Log().Error("Failed to get accounts", map[string]interface{}{
			"error":      err.Error(),
			"session_id": ctx.Request().Session().GetID(),
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"error":   "failed_to_get_accounts",
			"message": "Failed to retrieve accounts",
		})
	}

	activeAccount, err := c.multiAccountService.GetActiveAccount(ctx)
	if err != nil {
		facades.Log().Error("Failed to get active account", map[string]interface{}{
			"error":      err.Error(),
			"session_id": ctx.Request().Session().GetID(),
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"error":   "failed_to_get_active_account",
			"message": "Failed to get active account",
		})
	}

	// Get session statistics
	stats, _ := c.multiAccountService.GetSessionStatistics(ctx)

	return ctx.Response().Json(200, map[string]interface{}{
		"accounts":       accounts,
		"active_account": activeAccount,
		"count":          len(accounts),
		"statistics":     stats,
	})
}

// SwitchAccount switches to a different account in the session
func (c *AccountSwitcherController) SwitchAccount(ctx http.Context) http.Response {
	userID := ctx.Request().Input("user_id", "")
	if userID == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "missing_user_id",
			"message": "User ID is required",
		})
	}

	// Validate account access before switching
	if err := c.multiAccountService.ValidateAccountAccess(ctx, userID); err != nil {
		facades.Log().Warning("Account switch validation failed", map[string]interface{}{
			"user_id":    userID,
			"error":      err.Error(),
			"session_id": ctx.Request().Session().GetID(),
			"ip_address": ctx.Request().Ip(),
		})

		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "validation_failed",
			"message": err.Error(),
		})
	}

	err := c.multiAccountService.SwitchAccount(ctx, userID)
	if err != nil {
		facades.Log().Error("Account switch failed", map[string]interface{}{
			"user_id":    userID,
			"error":      err.Error(),
			"session_id": ctx.Request().Session().GetID(),
			"ip_address": ctx.Request().Ip(),
		})

		// Check for specific error types to provide better user feedback
		if err.Error() == "too many account switches. Please wait before switching again" {
			return ctx.Response().Json(429, map[string]interface{}{
				"error":   "rate_limit_exceeded",
				"message": "You're switching accounts too frequently. Please wait a moment before trying again.",
			})
		}

		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "switch_failed",
			"message": err.Error(),
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "Account switched successfully",
	})
}

// RemoveAccount removes an account from the session
func (c *AccountSwitcherController) RemoveAccount(ctx http.Context) http.Response {
	userID := ctx.Request().Input("user_id", "")
	if userID == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "missing_user_id",
			"message": "User ID is required",
		})
	}

	// Get current active account to prevent removing the only account
	activeAccount, err := c.multiAccountService.GetActiveAccount(ctx)
	if err != nil {
		facades.Log().Error("Failed to get active account for removal", map[string]interface{}{
			"error":      err.Error(),
			"session_id": ctx.Request().Session().GetID(),
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"error":   "failed_to_get_active_account",
			"message": "Failed to get active account",
		})
	}

	accountCount := c.multiAccountService.GetAccountCount(ctx)
	if accountCount <= 1 {
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "cannot_remove_last_account",
			"message": "Cannot remove the last account. Use logout instead.",
		})
	}

	err = c.multiAccountService.RemoveAccount(ctx, userID)
	if err != nil {
		facades.Log().Error("Account removal failed", map[string]interface{}{
			"user_id":    userID,
			"error":      err.Error(),
			"session_id": ctx.Request().Session().GetID(),
		})
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "remove_failed",
			"message": err.Error(),
		})
	}

	// Log the account removal
	facades.Log().Info("Account removed from session", map[string]interface{}{
		"removed_account": userID,
		"active_account":  activeAccount.UserID,
		"session_id":      ctx.Request().Session().GetID(),
		"ip_address":      ctx.Request().Ip(),
	})

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "Account removed successfully",
	})
}

// ShowAccountSwitcher displays the account switcher page
func (c *AccountSwitcherController) ShowAccountSwitcher(ctx http.Context) http.Response {
	accounts, err := c.multiAccountService.GetAllAccounts(ctx)
	if err != nil {
		facades.Log().Error("Failed to load accounts for switcher", map[string]interface{}{
			"error":      err.Error(),
			"session_id": ctx.Request().Session().GetID(),
		})
		return ctx.Response().Redirect(302, "/dashboard?error=Failed to load accounts")
	}

	activeAccount, err := c.multiAccountService.GetActiveAccount(ctx)
	if err != nil {
		facades.Log().Error("Failed to get active account for switcher", map[string]interface{}{
			"error":      err.Error(),
			"session_id": ctx.Request().Session().GetID(),
		})
		return ctx.Response().Redirect(302, "/dashboard?error=Failed to get active account")
	}

	// Get session statistics for display
	stats, _ := c.multiAccountService.GetSessionStatistics(ctx)

	return ctx.Response().View().Make("auth/account-switcher.tmpl", map[string]interface{}{
		"title":          "Switch Account",
		"accounts":       accounts,
		"active_account": activeAccount,
		"account_count":  len(accounts),
		"statistics":     stats,
	})
}

// AddAccountPrompt shows the login form for adding another account
func (c *AccountSwitcherController) AddAccountPrompt(ctx http.Context) http.Response {
	// Check if we're at the account limit
	accountCount := c.multiAccountService.GetAccountCount(ctx)
	if accountCount >= 5 {
		return ctx.Response().View().Make("auth/login.tmpl", map[string]interface{}{
			"title":            "Add Account",
			"error":            "Maximum number of accounts (5) reached. Please remove an account first.",
			"add_account_mode": true,
		})
	}

	return ctx.Response().View().Make("auth/login.tmpl", map[string]interface{}{
		"title":            "Add Account",
		"add_account_mode": true,
		"message":          "Sign in to add another account",
	})
}

// GetSessionStatistics returns detailed session statistics
func (c *AccountSwitcherController) GetSessionStatistics(ctx http.Context) http.Response {
	stats, err := c.multiAccountService.GetSessionStatistics(ctx)
	if err != nil {
		facades.Log().Error("Failed to get session statistics", map[string]interface{}{
			"error":      err.Error(),
			"session_id": ctx.Request().Session().GetID(),
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"error":   "failed_to_get_statistics",
			"message": "Failed to retrieve session statistics",
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success":    true,
		"statistics": stats,
	})
}

// RefreshAccount updates account data from the database
func (c *AccountSwitcherController) RefreshAccount(ctx http.Context) http.Response {
	userID := ctx.Request().Input("user_id", "")
	if userID == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "missing_user_id",
			"message": "User ID is required",
		})
	}

	err := c.multiAccountService.RefreshAccountData(ctx, userID)
	if err != nil {
		facades.Log().Error("Failed to refresh account data", map[string]interface{}{
			"user_id":    userID,
			"error":      err.Error(),
			"session_id": ctx.Request().Session().GetID(),
		})
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "refresh_failed",
			"message": err.Error(),
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "Account data refreshed successfully",
	})
}

// ExtendSession extends the expiration time for a specific account
func (c *AccountSwitcherController) ExtendSession(ctx http.Context) http.Response {
	userID := ctx.Request().Input("user_id", "")
	if userID == "" {
		// If no user ID provided, extend the active account
		activeAccount, err := c.multiAccountService.GetActiveAccount(ctx)
		if err != nil {
			return ctx.Response().Json(400, map[string]interface{}{
				"error":   "no_active_account",
				"message": "No active account found",
			})
		}
		userID = activeAccount.UserID
	}

	err := c.multiAccountService.ExtendAccountSession(ctx, userID)
	if err != nil {
		facades.Log().Error("Failed to extend account session", map[string]interface{}{
			"user_id":    userID,
			"error":      err.Error(),
			"session_id": ctx.Request().Session().GetID(),
		})
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "extend_failed",
			"message": err.Error(),
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "Session extended successfully",
	})
}

// ValidateAccount checks if an account is valid and accessible
func (c *AccountSwitcherController) ValidateAccount(ctx http.Context) http.Response {
	userID := ctx.Request().Input("user_id", "")
	if userID == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "missing_user_id",
			"message": "User ID is required",
		})
	}

	err := c.multiAccountService.ValidateAccountAccess(ctx, userID)
	if err != nil {
		return ctx.Response().Json(400, map[string]interface{}{
			"valid":   false,
			"error":   err.Error(),
			"message": "Account validation failed",
		})
	}

	account, err := c.multiAccountService.GetAccountByID(ctx, userID)
	if err != nil {
		return ctx.Response().Json(400, map[string]interface{}{
			"valid":   false,
			"error":   err.Error(),
			"message": "Failed to get account details",
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"valid":   true,
		"account": account,
		"message": "Account is valid and accessible",
	})
}
