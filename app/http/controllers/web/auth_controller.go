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
	authService *services.AuthService
}

func NewAuthController() *AuthController {
	return &AuthController{
		authService: services.NewAuthService(),
	}
}

// ShowLogin displays the login page
func (c *AuthController) ShowLogin(ctx http.Context) http.Response {
	return ctx.Response().View().Make("auth/login.tmpl", map[string]interface{}{
		"title": "Login",
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
	user := ctx.Value("user")
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	authenticatedUser := user.(*models.User)

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

	return ctx.Response().View().Make("dashboard.tmpl", map[string]interface{}{
		"title":   "Dashboard",
		"user":    authenticatedUser,
		"stats":   stats,
		"version": support.Version,
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
		return ctx.Response().View().Make("auth/login.tmpl", map[string]interface{}{
			"title": "Login",
			"error": "Invalid request data",
			"email": req.Email,
		})
	}

	// First, try basic login without MFA/WebAuthn
	user, _, err := c.authService.Login(ctx, &req)
	if err != nil {
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
				"title":             "Login",
				"email":             req.Email,
				"webauthn_required": true,
				"message":           "Please use your security key to complete login",
			})
		}

		return ctx.Response().View().Make("auth/login.tmpl", map[string]interface{}{
			"title": "Login",
			"error": "Invalid credentials",
			"email": req.Email,
		})
	}

	// Set session data for web authentication
	ctx.Request().Session().Put("user_id", user.ID)
	ctx.Request().Session().Put("user_email", user.Email)

	// Redirect to dashboard
	return ctx.Response().Redirect(302, "/dashboard")
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

	// Set session data for web authentication
	ctx.Request().Session().Put("user_id", user.ID)
	ctx.Request().Session().Put("user_email", user.Email)

	// Redirect to dashboard
	return ctx.Response().Redirect(302, "/dashboard")
}

// Logout handles user logout
func (c *AuthController) Logout(ctx http.Context) http.Response {
	// Clear session data
	ctx.Request().Session().Forget("user_id")
	ctx.Request().Session().Forget("user_email")
	ctx.Request().Session().Flush()

	return ctx.Response().Redirect(302, "/login?message=Logged out successfully")
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
