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
	// For now, create a mock user and stats
	// In a real implementation, you would get this from session/auth
	user := map[string]interface{}{
		"Name":  "Admin User",
		"Email": "admin@example.com",
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

	return ctx.Response().View().Make("dashboard.tmpl", map[string]interface{}{
		"title":   "Dashboard",
		"user":    user,
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

	user, token, err := c.authService.Login(ctx, &req)
	if err != nil {
		return ctx.Response().View().Make("auth/login.tmpl", map[string]interface{}{
			"title": "Login",
			"error": "Invalid credentials",
			"email": req.Email,
		})
	}

	// For now, just redirect to dashboard with success message
	// In a real implementation, you would set session data
	return ctx.Response().View().Make("dashboard.tmpl", map[string]interface{}{
		"title":   "Dashboard",
		"user":    user,
		"token":   token,
		"version": support.Version,
		"message": "Login successful",
	})
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

	user, token, err := c.authService.Register(ctx, &req)
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

	// For now, just redirect to dashboard with success message
	// In a real implementation, you would set session data
	return ctx.Response().View().Make("dashboard.tmpl", map[string]interface{}{
		"title":   "Dashboard",
		"user":    user,
		"token":   token,
		"version": support.Version,
		"message": "Registration successful",
	})
}

// Logout handles user logout
func (c *AuthController) Logout(ctx http.Context) http.Response {
	// In a real implementation, you would clear session data
	return ctx.Response().Redirect(302, "/login")
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
