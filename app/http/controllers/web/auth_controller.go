package web

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
	"github.com/goravel/framework/support"

	"goravel/app/http/requests"
	"goravel/app/models"
	"goravel/app/services"
)

type AuthController struct {
	authService         *services.AuthService
	multiAccountService *services.MultiAccountService
}

func NewAuthController() *AuthController {
	return &AuthController{
		authService:         services.NewAuthService(),
		multiAccountService: services.NewMultiAccountService(),
	}
}

// ShowLogin displays the login page with all available authentication methods
func (c *AuthController) ShowLogin(ctx http.Context) http.Response {
	// Initialize Google OAuth service to check if it's enabled
	googleOAuthService := services.NewGoogleOAuthService()

	// Check for any messages from query parameters
	message := ctx.Request().Query("message", "")

	return ctx.Response().View().Make("auth/login.tmpl", map[string]interface{}{
		"title":                "Login",
		"google_oauth_enabled": googleOAuthService.IsEnabled(),
		"message":              message,
	})
}

// ShowRegister displays the registration page
func (c *AuthController) ShowRegister(ctx http.Context) http.Response {
	return ctx.Response().View().Make("auth/register.tmpl", map[string]interface{}{
		"title": "Register",
	})
}

// ShowDashboard displays the main dashboard
func (c *AuthController) ShowDashboard(ctx http.Context) http.Response {
	// Get user from context (set by middleware)
	user, ok := ctx.Value("user").(*models.User)
	if !ok {
		facades.Log().Error("ShowDashboard: User not found in context")
		return ctx.Response().Redirect(302, "/login")
	}

	// Get basic stats
	tenantCount, _ := facades.Orm().Query().Model(&models.Tenant{}).Count()
	roleCount, _ := facades.Orm().Query().Model(&models.Role{}).Count()
	permissionCount, _ := facades.Orm().Query().Model(&models.Permission{}).Count()
	userCount, _ := facades.Orm().Query().Model(&models.User{}).Count()

	stats := map[string]interface{}{
		"tenants":     tenantCount,
		"roles":       roleCount,
		"permissions": permissionCount,
		"users":       userCount,
	}

	// Get multi-account session info
	accounts, _ := c.multiAccountService.GetAllAccounts(ctx)
	activeAccount, _ := c.multiAccountService.GetActiveAccount(ctx)
	hasMultipleAccounts := len(accounts) > 1

	// Check for messages
	message := ctx.Request().Query("message", "")

	return ctx.Response().View().Make("dashboard.tmpl", map[string]interface{}{
		"title":                 "Dashboard",
		"user":                  user,
		"stats":                 stats,
		"version":               support.Version,
		"accounts":              accounts,
		"active_account":        activeAccount,
		"has_multiple_accounts": hasMultipleAccounts,
		"account_count":         len(accounts),
		"message":               message,
	})
}

// ShowForgotPassword displays the forgot password page
func (c *AuthController) ShowForgotPassword(ctx http.Context) http.Response {
	return ctx.Response().View().Make("auth/forgot-password.tmpl", map[string]interface{}{
		"title": "Forgot Password",
	})
}

// ShowResetPassword displays the reset password page
func (c *AuthController) ShowResetPassword(ctx http.Context) http.Response {
	token := ctx.Request().Input("token", "")
	if token == "" {
		return ctx.Response().Redirect(302, "/forgot-password")
	}

	return ctx.Response().View().Make("auth/reset-password.tmpl", map[string]interface{}{
		"title": "Reset Password",
		"token": token,
	})
}

// Login handles web login form submission
func (c *AuthController) Login(ctx http.Context) http.Response {
	var req requests.LoginRequest
	if err := ctx.Request().Bind(&req); err != nil {
		// Initialize Google OAuth service for error page
		googleOAuthService := services.NewGoogleOAuthService()

		return ctx.Response().View().Make("auth/login.tmpl", map[string]interface{}{
			"title":                "Login",
			"error":                "Invalid request data",
			"email":                req.Email,
			"google_oauth_enabled": googleOAuthService.IsEnabled(),
		})
	}

	// First, try basic login without MFA/WebAuthn
	user, _, err := c.authService.Login(ctx, &req)
	if err != nil {
		// Initialize Google OAuth service for error pages
		googleOAuthService := services.NewGoogleOAuthService()

		// Check if the error is specifically about MFA being required
		if err.Error() == "MFA code required" {
			// Store user ID in session for MFA verification
			var tempUser models.User
			userErr := facades.Orm().Query().Where("email", req.Email).First(&tempUser)
			if userErr == nil {
				ctx.Request().Session().Put("pending_mfa_user_id", tempUser.ID)
				return ctx.Response().Redirect(302, "/auth/mfa/verify")
			}
		}

		// Check if the error is about WebAuthn being required
		if err.Error() == "WebAuthn authentication required" {
			return ctx.Response().View().Make("auth/login.tmpl", map[string]interface{}{
				"title":                "Login",
				"email":                req.Email,
				"webauthn_required":    true,
				"message":              "Please use your security key to complete login",
				"google_oauth_enabled": googleOAuthService.IsEnabled(),
			})
		}

		return ctx.Response().View().Make("auth/login.tmpl", map[string]interface{}{
			"title":                "Login",
			"error":                "Invalid credentials",
			"email":                req.Email,
			"google_oauth_enabled": googleOAuthService.IsEnabled(),
		})
	}

	// Add account to multi-account session
	err = c.multiAccountService.AddAccount(ctx, user, "password")
	if err != nil {
		facades.Log().Error("Failed to add account to multi-account session", map[string]interface{}{
			"error":   err.Error(),
			"user_id": user.ID,
		})
		// Even if multi-account session fails, we can still redirect to dashboard
		// The user will be able to login again if needed
	}

	// Check for intended URL and redirect appropriately
	intendedURL := ctx.Request().Session().Get("intended_url", "/dashboard")
	ctx.Request().Session().Remove("intended_url")

	// Redirect to intended URL or dashboard
	return ctx.Response().Redirect(302, intendedURL.(string))
}

// Register handles web registration form submission
func (c *AuthController) Register(ctx http.Context) http.Response {
	var req requests.RegisterRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().View().Make("auth/register.tmpl", map[string]interface{}{
			"title": "Register",
			"error": "Invalid request data",
			"name":  req.Name,
			"email": req.Email,
		})
	}

	user, _, err := c.authService.Register(ctx, &req)
	if err != nil {
		errorMsg := "Registration failed"
		if err.Error() == "user already exists" {
			errorMsg = "User already exists"
		}

		return ctx.Response().View().Make("auth/register.tmpl", map[string]interface{}{
			"title": "Register",
			"error": errorMsg,
			"name":  req.Name,
			"email": req.Email,
		})
	}

	// Add account to multi-account session
	err = c.multiAccountService.AddAccount(ctx, user, "registration")
	if err != nil {
		facades.Log().Error("Failed to add account to multi-account session", map[string]interface{}{
			"error":   err.Error(),
			"user_id": user.ID,
		})
	}

	// Set session data for web authentication (backward compatibility)
	ctx.Request().Session().Put("user_id", user.ID)
	ctx.Request().Session().Put("user_email", user.Email)

	// Redirect to dashboard
	return ctx.Response().Redirect(302, "/dashboard")
}

// Logout handles user logout
func (c *AuthController) Logout(ctx http.Context) http.Response {
	// Get current user ID
	userID := ctx.Request().Session().Get("user_id")

	// Check if we should logout all accounts or just the current one
	logoutAll := ctx.Request().Input("all", "false") == "true"

	if logoutAll || userID == nil {
		// Clear all accounts
		c.multiAccountService.ClearAllAccounts(ctx)
		ctx.Request().Session().Flush()
		return ctx.Response().Redirect(302, "/login?message=Logged out of all accounts successfully")
	} else {
		// Remove only the current account
		err := c.multiAccountService.RemoveAccount(ctx, userID.(string))
		if err != nil {
			facades.Log().Error("Failed to remove account from multi-account session", map[string]interface{}{
				"error":   err.Error(),
				"user_id": userID,
			})
		}

		// Check if there are other accounts to switch to
		accountCount := c.multiAccountService.GetAccountCount(ctx)
		if accountCount > 0 {
			return ctx.Response().Redirect(302, "/dashboard?message=Switched to another account")
		} else {
			// No other accounts, clear session completely
			ctx.Request().Session().Flush()
			return ctx.Response().Redirect(302, "/login?message=Logged out successfully")
		}
	}
}

// ForgotPassword handles forgot password form submission
func (c *AuthController) ForgotPassword(ctx http.Context) http.Response {
	var req requests.ForgotPasswordRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().View().Make("auth/forgot-password.tmpl", map[string]interface{}{
			"title": "Forgot Password",
			"error": "Invalid email address",
		})
	}

	err := c.authService.ForgotPassword(ctx, &req)
	if err != nil {
		return ctx.Response().View().Make("auth/forgot-password.tmpl", map[string]interface{}{
			"title": "Forgot Password",
			"error": "Failed to send reset email",
		})
	}

	return ctx.Response().View().Make("auth/forgot-password.tmpl", map[string]interface{}{
		"title":   "Forgot Password",
		"success": "Password reset email sent successfully",
	})
}

// ResetPassword handles password reset form submission
func (c *AuthController) ResetPassword(ctx http.Context) http.Response {
	var req requests.ResetPasswordRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().View().Make("auth/reset-password.tmpl", map[string]interface{}{
			"title": "Reset Password",
			"error": "Invalid request data",
			"token": req.Token,
		})
	}

	err := c.authService.ResetPassword(ctx, &req)
	if err != nil {
		return ctx.Response().View().Make("auth/reset-password.tmpl", map[string]interface{}{
			"title": "Reset Password",
			"error": "Failed to reset password",
			"token": req.Token,
		})
	}

	return ctx.Response().Redirect(302, "/login?message=Password reset successfully")
}
