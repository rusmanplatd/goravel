package web

import (
	"fmt"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/services"
)

type AccountSwitcherController struct {
	multiAccountService *services.MultiAccountService
}

func NewAccountSwitcherController() *AccountSwitcherController {
	multiAccountService, err := services.NewMultiAccountService()
	if err != nil {
		facades.Log().Error("Failed to create multi-account service", map[string]interface{}{
			"error": err.Error(),
		})
		return nil
	}

	return &AccountSwitcherController{
		multiAccountService: multiAccountService,
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

// QuickSwitch switches to the next or previous account in the session
func (c *AccountSwitcherController) QuickSwitch(ctx http.Context) http.Response {
	direction := ctx.Request().Input("direction", "next")

	accounts, err := c.multiAccountService.GetAllAccounts(ctx)
	if err != nil {
		facades.Log().Error("Failed to get accounts for quick switch", map[string]interface{}{
			"error":      err.Error(),
			"session_id": ctx.Request().Session().GetID(),
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"error":   "failed_to_get_accounts",
			"message": "Failed to retrieve accounts",
		})
	}

	if len(accounts) <= 1 {
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "insufficient_accounts",
			"message": "Need at least 2 accounts for quick switching",
		})
	}

	activeAccount, err := c.multiAccountService.GetActiveAccount(ctx)
	if err != nil {
		facades.Log().Error("Failed to get active account for quick switch", map[string]interface{}{
			"error":      err.Error(),
			"session_id": ctx.Request().Session().GetID(),
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"error":   "failed_to_get_active_account",
			"message": "Failed to get active account",
		})
	}

	// Find current account index
	currentIndex := -1
	for i, account := range accounts {
		if account.UserID == activeAccount.UserID {
			currentIndex = i
			break
		}
	}

	if currentIndex == -1 {
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "active_account_not_found",
			"message": "Active account not found in session",
		})
	}

	// Calculate next account index
	var nextIndex int
	if direction == "previous" || direction == "prev" {
		nextIndex = (currentIndex - 1 + len(accounts)) % len(accounts)
	} else {
		nextIndex = (currentIndex + 1) % len(accounts)
	}

	nextAccount := accounts[nextIndex]

	// Switch to the next account
	err = c.multiAccountService.SwitchAccount(ctx, nextAccount.UserID)
	if err != nil {
		facades.Log().Error("Quick switch failed", map[string]interface{}{
			"from_user_id": activeAccount.UserID,
			"to_user_id":   nextAccount.UserID,
			"direction":    direction,
			"error":        err.Error(),
			"session_id":   ctx.Request().Session().GetID(),
		})
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "switch_failed",
			"message": err.Error(),
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success":      true,
		"message":      "Account switched successfully",
		"from_account": activeAccount,
		"to_account":   nextAccount,
		"direction":    direction,
	})
}

// GetAccountSuggestions returns account suggestions based on recent activity
func (c *AccountSwitcherController) GetAccountSuggestions(ctx http.Context) http.Response {
	suggestions, err := c.multiAccountService.GetAccountSuggestions(ctx)
	if err != nil {
		facades.Log().Error("Failed to get account suggestions", map[string]interface{}{
			"error":      err.Error(),
			"session_id": ctx.Request().Session().GetID(),
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"error":   "failed_to_get_suggestions",
			"message": "Failed to retrieve account suggestions",
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success":     true,
		"suggestions": suggestions,
	})
}

// GetAccountsByOrganization returns accounts grouped by organization
func (c *AccountSwitcherController) GetAccountsByOrganization(ctx http.Context) http.Response {
	grouped, err := c.multiAccountService.GetAccountsByOrganization(ctx)
	if err != nil {
		facades.Log().Error("Failed to get accounts by organization", map[string]interface{}{
			"error":      err.Error(),
			"session_id": ctx.Request().Session().GetID(),
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"error":   "failed_to_get_grouped_accounts",
			"message": "Failed to retrieve grouped accounts",
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"groups":  grouped,
	})
}

// GetSecurityInsights returns security insights about the current session
func (c *AccountSwitcherController) GetSecurityInsights(ctx http.Context) http.Response {
	insights, err := c.multiAccountService.GetSecurityInsights(ctx)
	if err != nil {
		facades.Log().Error("Failed to get security insights", map[string]interface{}{
			"error":      err.Error(),
			"session_id": ctx.Request().Session().GetID(),
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"error":   "failed_to_get_insights",
			"message": "Failed to retrieve security insights",
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success":  true,
		"insights": insights,
	})
}

// UpdateAccountActivity updates the last activity for the current account
func (c *AccountSwitcherController) UpdateAccountActivity(ctx http.Context) http.Response {
	activity := ctx.Request().Input("activity", "")
	if activity == "" {
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "missing_activity",
			"message": "Activity description is required",
		})
	}

	activeAccount, err := c.multiAccountService.GetActiveAccount(ctx)
	if err != nil {
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "no_active_account",
			"message": "No active account found",
		})
	}

	err = c.multiAccountService.UpdateAccountActivity(ctx, activeAccount.UserID, activity)
	if err != nil {
		facades.Log().Error("Failed to update account activity", map[string]interface{}{
			"user_id":    activeAccount.UserID,
			"activity":   activity,
			"error":      err.Error(),
			"session_id": ctx.Request().Session().GetID(),
		})
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "update_failed",
			"message": err.Error(),
		})
	}

	return ctx.Response().Json(200, map[string]interface{}{
		"success": true,
		"message": "Activity updated successfully",
	})
}

// BulkRefreshAccounts refreshes data for all accounts in the session
func (c *AccountSwitcherController) BulkRefreshAccounts(ctx http.Context) http.Response {
	accounts, err := c.multiAccountService.GetAllAccounts(ctx)
	if err != nil {
		facades.Log().Error("Failed to get accounts for bulk refresh", map[string]interface{}{
			"error":      err.Error(),
			"session_id": ctx.Request().Session().GetID(),
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"error":   "failed_to_get_accounts",
			"message": "Failed to retrieve accounts",
		})
	}

	successCount := 0
	errors := []string{}

	for _, account := range accounts {
		err := c.multiAccountService.RefreshAccountData(ctx, account.UserID)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to refresh %s: %s", account.Email, err.Error()))
			facades.Log().Warning("Account refresh failed in bulk operation", map[string]interface{}{
				"user_id": account.UserID,
				"email":   account.Email,
				"error":   err.Error(),
			})
		} else {
			successCount++
		}
	}

	response := map[string]interface{}{
		"success":       true,
		"total":         len(accounts),
		"success_count": successCount,
		"error_count":   len(errors),
	}

	if len(errors) > 0 {
		response["errors"] = errors
		response["message"] = fmt.Sprintf("Refreshed %d of %d accounts. Some accounts had errors.", successCount, len(accounts))
	} else {
		response["message"] = fmt.Sprintf("Successfully refreshed all %d accounts", successCount)
	}

	return ctx.Response().Json(200, response)
}

// BulkExtendSessions extends session expiration for all accounts
func (c *AccountSwitcherController) BulkExtendSessions(ctx http.Context) http.Response {
	accounts, err := c.multiAccountService.GetAllAccounts(ctx)
	if err != nil {
		facades.Log().Error("Failed to get accounts for bulk session extension", map[string]interface{}{
			"error":      err.Error(),
			"session_id": ctx.Request().Session().GetID(),
		})
		return ctx.Response().Json(500, map[string]interface{}{
			"error":   "failed_to_get_accounts",
			"message": "Failed to retrieve accounts",
		})
	}

	successCount := 0
	errors := []string{}

	for _, account := range accounts {
		err := c.multiAccountService.ExtendAccountSession(ctx, account.UserID)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to extend session for %s: %s", account.Email, err.Error()))
			facades.Log().Warning("Session extension failed in bulk operation", map[string]interface{}{
				"user_id": account.UserID,
				"email":   account.Email,
				"error":   err.Error(),
			})
		} else {
			successCount++
		}
	}

	response := map[string]interface{}{
		"success":       true,
		"total":         len(accounts),
		"success_count": successCount,
		"error_count":   len(errors),
	}

	if len(errors) > 0 {
		response["errors"] = errors
		response["message"] = fmt.Sprintf("Extended sessions for %d of %d accounts. Some accounts had errors.", successCount, len(accounts))
	} else {
		response["message"] = fmt.Sprintf("Successfully extended sessions for all %d accounts", successCount)
	}

	return ctx.Response().Json(200, response)
}

// BulkRemoveAccounts removes multiple accounts from the session
func (c *AccountSwitcherController) BulkRemoveAccounts(ctx http.Context) http.Response {
	var requestData struct {
		UserIDs []string `json:"user_ids"`
	}

	if err := ctx.Request().Bind(&requestData); err != nil {
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "invalid_request",
			"message": "Invalid request data",
		})
	}

	if len(requestData.UserIDs) == 0 {
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "no_accounts_specified",
			"message": "No account IDs provided",
		})
	}

	// Check if we're trying to remove all accounts
	totalAccounts := c.multiAccountService.GetAccountCount(ctx)
	if len(requestData.UserIDs) >= totalAccounts {
		return ctx.Response().Json(400, map[string]interface{}{
			"error":   "cannot_remove_all_accounts",
			"message": "Cannot remove all accounts. At least one account must remain.",
		})
	}

	successCount := 0
	errors := []string{}

	for _, userID := range requestData.UserIDs {
		err := c.multiAccountService.RemoveAccount(ctx, userID)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Failed to remove account %s: %s", userID, err.Error()))
			facades.Log().Warning("Account removal failed in bulk operation", map[string]interface{}{
				"user_id": userID,
				"error":   err.Error(),
			})
		} else {
			successCount++
		}
	}

	response := map[string]interface{}{
		"success":       true,
		"total":         len(requestData.UserIDs),
		"success_count": successCount,
		"error_count":   len(errors),
	}

	if len(errors) > 0 {
		response["errors"] = errors
		response["message"] = fmt.Sprintf("Removed %d of %d accounts. Some accounts had errors.", successCount, len(requestData.UserIDs))
	} else {
		response["message"] = fmt.Sprintf("Successfully removed %d accounts", successCount)
	}

	return ctx.Response().Json(200, response)
}
