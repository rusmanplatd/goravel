package web

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"
	"github.com/goravel/framework/support"

	"goravel/app/http/requests"
	"goravel/app/models"
	"goravel/app/services"
	"time"
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
	// Check for any messages from query parameters
	message := ctx.Request().Query("message", "")
	error := ctx.Request().Query("error", "")
	success := ctx.Request().Query("success", "")
	email := ctx.Request().Query("email", "")

	// Check if this is add account mode
	addAccountMode := ctx.Request().Query("add_account", "") == "true"

	// Get app name from config
	appName := facades.Config().GetString("app.name", "Goravel")

	return ctx.Response().View().Make("auth/login.tmpl", map[string]interface{}{
		"title":            "Login",
		"message":          message,
		"error":            error,
		"success":          success,
		"email":            email,
		"add_account_mode": addAccountMode,
		"app_name":         appName,
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

	// Get comprehensive stats for all features
	tenantCount, _ := facades.Orm().Query().Model(&models.Tenant{}).Count()
	roleCount, _ := facades.Orm().Query().Model(&models.Role{}).Count()
	permissionCount, _ := facades.Orm().Query().Model(&models.Permission{}).Count()
	userCount, _ := facades.Orm().Query().Model(&models.User{}).Count()

	// Organization stats
	organizationCount, _ := facades.Orm().Query().Model(&models.Organization{}).Count()

	// Chat system stats
	chatRoomCount, _ := facades.Orm().Query().Table("chat_rooms").Count()
	chatMessageCount, _ := facades.Orm().Query().Table("chat_messages").Count()

	// Calendar stats
	calendarEventCount, _ := facades.Orm().Query().Model(&models.CalendarEvent{}).Count()
	upcomingEventsCount, _ := facades.Orm().Query().Model(&models.CalendarEvent{}).
		Where("start_time > ?", time.Now()).
		Where("start_time < ?", time.Now().AddDate(0, 0, 7)).
		Count()

	// Task management stats
	taskCount, _ := facades.Orm().Query().Table("tasks").Count()
	activeTasks, _ := facades.Orm().Query().Table("tasks").
		Where("status IN ?", []string{"todo", "in_progress"}).
		Count()
	completedTasks, _ := facades.Orm().Query().Table("tasks").
		Where("status = ?", "done").
		Count()

	// Notification stats
	notificationCount, _ := facades.Orm().Query().Model(&models.Notification{}).Count()
	unreadNotifications, _ := facades.Orm().Query().Model(&models.Notification{}).
		Where("notifiable_id = ?", user.ID).
		Where("read_at IS NULL").
		Count()

	// OAuth stats
	oauthClientCount, _ := facades.Orm().Query().Table("oauth_clients").Count()
	activeTokens, _ := facades.Orm().Query().Table("oauth_access_tokens").
		Where("expires_at > ?", time.Now()).
		Count()

	// Activity stats (recent activity in last 24 hours)
	recentActivityCount, _ := facades.Orm().Query().Model(&models.ActivityLog{}).
		Where("created_at > ?", time.Now().AddDate(0, 0, -1)).
		Count()

	stats := map[string]interface{}{
		"tenants":              tenantCount,
		"roles":                roleCount,
		"permissions":          permissionCount,
		"users":                userCount,
		"organizations":        organizationCount,
		"chat_rooms":           chatRoomCount,
		"chat_messages":        chatMessageCount,
		"calendar_events":      calendarEventCount,
		"upcoming_events":      upcomingEventsCount,
		"tasks":                taskCount,
		"active_tasks":         activeTasks,
		"completed_tasks":      completedTasks,
		"notifications":        notificationCount,
		"unread_notifications": unreadNotifications,
		"oauth_clients":        oauthClientCount,
		"active_tokens":        activeTokens,
		"recent_activity":      recentActivityCount,
	}

	// Get recent activity for activity feed
	var recentActivities []models.ActivityLog
	facades.Orm().Query().Model(&models.ActivityLog{}).
		With("User").
		OrderBy("created_at DESC").
		Limit(10).
		Find(&recentActivities)

	// Get upcoming events for quick view
	var upcomingEvents []models.CalendarEvent
	facades.Orm().Query().Model(&models.CalendarEvent{}).
		Where("start_time > ?", time.Now()).
		Where("start_time < ?", time.Now().AddDate(0, 0, 7)).
		OrderBy("start_time ASC").
		Limit(5).
		Find(&upcomingEvents)

	// Get recent notifications
	var recentNotifications []models.Notification
	facades.Orm().Query().Model(&models.Notification{}).
		Where("notifiable_id = ?", user.ID).
		OrderBy("created_at DESC").
		Limit(5).
		Find(&recentNotifications)

	// Get navbar data from middleware
	navbarData := ctx.Value("navbar_data")
	if navbarData == nil {
		navbarData = map[string]interface{}{}
	}

	// Check for messages
	message := ctx.Request().Query("message", "")

	// Merge navbar data with dashboard data
	templateData := map[string]interface{}{
		"title":                "Dashboard",
		"user":                 user,
		"stats":                stats,
		"recent_activities":    recentActivities,
		"upcoming_events":      upcomingEvents,
		"recent_notifications": recentNotifications,
		"version":              support.Version,
		"message":              message,
	}

	// Add navbar data to template data
	if navbarDataMap, ok := navbarData.(map[string]interface{}); ok {
		for key, value := range navbarDataMap {
			templateData[key] = value
		}
	}

	return ctx.Response().View().Make("dashboard.tmpl", templateData)
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
