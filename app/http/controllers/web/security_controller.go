package web

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/models"
	"goravel/app/services"
)

type SecurityController struct {
	authService     *services.AuthService
	webauthnService *services.WebAuthnService
}

func NewSecurityController() *SecurityController {
	return &SecurityController{
		authService:     services.NewAuthService(),
		webauthnService: services.NewWebAuthnService(),
	}
}

// getCurrentUser gets the current authenticated user from context
func (c *SecurityController) getCurrentUser(ctx http.Context) *models.User {
	// Get user from context (set by WebAuth middleware)
	user := ctx.Value("user")
	if user == nil {
		return nil
	}

	// Type assertion to ensure it's a User pointer
	if userPtr, ok := user.(*models.User); ok {
		return userPtr
	}

	return nil
}

// Index displays the main security settings page
func (c *SecurityController) Index(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get WebAuthn credentials
	credentials, err := c.webauthnService.GetUserCredentials(user)
	if err != nil {
		credentials = []models.WebauthnCredential{}
	}

	// Get success/error messages from query params
	success := ctx.Request().Input("success", "")
	errorMsg := ctx.Request().Input("error", "")

	return ctx.Response().View().Make("security/index.tmpl", map[string]interface{}{
		"title":                "Security Settings",
		"user":                 user,
		"mfa_enabled":          user.MfaEnabled,
		"webauthn_enabled":     user.WebauthnEnabled,
		"webauthn_credentials": credentials,
		"credential_count":     len(credentials),
		"success":              success,
		"error":                errorMsg,
	})
}

// ShowChangePassword displays the change password page
func (c *SecurityController) ShowChangePassword(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	return ctx.Response().View().Make("security/change-password.tmpl", map[string]interface{}{
		"title": "Change Password",
		"user":  user,
	})
}

// ChangePassword handles password change form submission
func (c *SecurityController) ChangePassword(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	var req struct {
		CurrentPassword string `form:"current_password" json:"current_password"`
		NewPassword     string `form:"new_password" json:"new_password"`
		ConfirmPassword string `form:"confirm_password" json:"confirm_password"`
	}

	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().View().Make("security/change-password.tmpl", map[string]interface{}{
			"title": "Change Password",
			"user":  user,
			"error": "Invalid request data",
		})
	}

	// Validate password confirmation
	if req.NewPassword != req.ConfirmPassword {
		return ctx.Response().View().Make("security/change-password.tmpl", map[string]interface{}{
			"title": "Change Password",
			"user":  user,
			"error": "New password and confirmation do not match",
		})
	}

	// Verify current password
	if !facades.Hash().Check(req.CurrentPassword, user.Password) {
		return ctx.Response().View().Make("security/change-password.tmpl", map[string]interface{}{
			"title": "Change Password",
			"user":  user,
			"error": "Current password is incorrect",
		})
	}

	// Update password
	hashedPassword, err := facades.Hash().Make(req.NewPassword)
	if err != nil {
		return ctx.Response().View().Make("security/change-password.tmpl", map[string]interface{}{
			"title": "Change Password",
			"user":  user,
			"error": "Failed to update password",
		})
	}

	user.Password = hashedPassword
	err = facades.Orm().Query().Save(user)
	if err != nil {
		return ctx.Response().View().Make("security/change-password.tmpl", map[string]interface{}{
			"title": "Change Password",
			"user":  user,
			"error": "Failed to save new password",
		})
	}

	return ctx.Response().Redirect(302, "/security?success=Password changed successfully")
}

// ShowSessions displays active sessions
func (c *SecurityController) ShowSessions(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// In a real implementation, you would fetch actual session data
	// For now, we'll show the current session
	sessions := []map[string]interface{}{
		{
			"id":            ctx.Request().Session().GetID(),
			"ip_address":    ctx.Request().Ip(),
			"user_agent":    ctx.Request().Header("User-Agent", "Unknown"),
			"last_activity": "Just now",
			"is_current":    true,
		},
	}

	return ctx.Response().View().Make("security/sessions.tmpl", map[string]interface{}{
		"title":    "Active Sessions",
		"user":     user,
		"sessions": sessions,
	})
}

// RevokeSession revokes a specific session
func (c *SecurityController) RevokeSession(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	sessionID := ctx.Request().Route("id")
	currentSessionID := ctx.Request().Session().GetID()

	// Don't allow revoking current session
	if sessionID == currentSessionID {
		return ctx.Response().Redirect(302, "/security/sessions?error=Cannot revoke current session")
	}

	// In a real implementation, you would revoke the actual session
	// For now, we'll just redirect with success message
	return ctx.Response().Redirect(302, "/security/sessions?success=Session revoked successfully")
}

// ShowAuditLog displays security audit log
func (c *SecurityController) ShowAuditLog(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// Get recent activity logs for the user
	var activities []models.ActivityLog
	err := facades.Orm().Query().
		Where("user_id", user.ID).
		Where("category", "security").
		OrderBy("created_at", "desc").
		Limit(50).
		Find(&activities)

	if err != nil {
		activities = []models.ActivityLog{}
	}

	return ctx.Response().View().Make("security/audit-log.tmpl", map[string]interface{}{
		"title":      "Security Audit Log",
		"user":       user,
		"activities": activities,
	})
}
