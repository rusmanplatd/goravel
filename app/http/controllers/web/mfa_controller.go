package web

import (
	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/requests"
	"goravel/app/models"
	"goravel/app/services"
)

type MfaController struct {
	authService *services.AuthService
}

func NewMfaController() *MfaController {
	return &MfaController{
		authService: services.NewAuthService(),
	}
}

// getCurrentUser gets the current authenticated user from session
func (c *MfaController) getCurrentUser(ctx http.Context) *models.User {
	userID := ctx.Request().Session().Get("user_id")
	if userID == nil {
		return nil
	}

	var user models.User
	err := facades.Orm().Query().Where("id", userID).First(&user)
	if err != nil {
		return nil
	}

	return &user
}

// ShowSetup displays the MFA setup page
func (c *MfaController) ShowSetup(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	// If MFA is already enabled, redirect to manage page
	if user.MfaEnabled {
		return ctx.Response().Redirect(302, "/security/mfa/manage")
	}

	// Generate MFA setup data
	setupData := c.authService.GenerateMfaSetup(user)

	return ctx.Response().View().Make("security/mfa/setup.tmpl", map[string]interface{}{
		"title":        "Setup Two-Factor Authentication",
		"user":         user,
		"secret":       setupData["secret"],
		"qr_code_url":  setupData["qr_code_url"],
		"manual_entry": setupData["secret"],
	})
}

// ShowManage displays the MFA management page
func (c *MfaController) ShowManage(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	return ctx.Response().View().Make("security/mfa/manage.tmpl", map[string]interface{}{
		"title":       "Manage Two-Factor Authentication",
		"user":        user,
		"mfa_enabled": user.MfaEnabled,
	})
}

// Enable handles MFA enable form submission
func (c *MfaController) Enable(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	var req requests.EnableMfaRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().View().Make("security/mfa/setup.tmpl", map[string]interface{}{
			"title": "Setup Two-Factor Authentication",
			"user":  user,
			"error": "Invalid request data",
		})
	}

	_, err := c.authService.EnableMfa(ctx, user, &req)
	if err != nil {
		// Re-generate setup data for error case
		setupData := c.authService.GenerateMfaSetup(user)
		return ctx.Response().View().Make("security/mfa/setup.tmpl", map[string]interface{}{
			"title":        "Setup Two-Factor Authentication",
			"user":         user,
			"secret":       setupData["secret"],
			"qr_code_url":  setupData["qr_code_url"],
			"manual_entry": setupData["secret"],
			"error":        "Invalid verification code or setup failed",
		})
	}

	return ctx.Response().Redirect(302, "/security/mfa/manage?success=MFA enabled successfully")
}

// Disable handles MFA disable form submission
func (c *MfaController) Disable(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	var req requests.DisableMfaRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().View().Make("security/mfa/manage.tmpl", map[string]interface{}{
			"title":       "Manage Two-Factor Authentication",
			"user":        user,
			"mfa_enabled": user.MfaEnabled,
			"error":       "Invalid request data",
		})
	}

	err := c.authService.DisableMfa(ctx, user, &req)
	if err != nil {
		return ctx.Response().View().Make("security/mfa/manage.tmpl", map[string]interface{}{
			"title":       "Manage Two-Factor Authentication",
			"user":        user,
			"mfa_enabled": user.MfaEnabled,
			"error":       "Invalid password or verification code",
		})
	}

	return ctx.Response().Redirect(302, "/security/mfa/manage?success=MFA disabled successfully")
}

// ShowVerify displays the MFA verification page during login
func (c *MfaController) ShowVerify(ctx http.Context) http.Response {
	// Check if there's a pending MFA verification in session
	pendingMfa := ctx.Request().Session().Get("pending_mfa_user_id")
	if pendingMfa == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	return ctx.Response().View().Make("auth/mfa-verify.tmpl", map[string]interface{}{
		"title": "Two-Factor Authentication",
	})
}

// Verify handles MFA verification during login
func (c *MfaController) Verify(ctx http.Context) http.Response {
	// Get pending user from session
	pendingUserID := ctx.Request().Session().Get("pending_mfa_user_id")
	if pendingUserID == nil {
		return ctx.Response().Redirect(302, "/login")
	}

	var user models.User
	err := facades.Orm().Query().Where("id", pendingUserID).First(&user)
	if err != nil {
		return ctx.Response().Redirect(302, "/login")
	}

	var req struct {
		Code string `form:"code" json:"code"`
	}

	if err := ctx.Request().Bind(&req); err != nil {
		return ctx.Response().View().Make("auth/mfa-verify.tmpl", map[string]interface{}{
			"title": "Two-Factor Authentication",
			"error": "Invalid request data",
		})
	}

	// Verify MFA code
	if !c.authService.VerifyMfa(&user, req.Code) {
		return ctx.Response().View().Make("auth/mfa-verify.tmpl", map[string]interface{}{
			"title": "Two-Factor Authentication",
			"error": "Invalid verification code",
		})
	}

	// Complete login
	ctx.Request().Session().Put("user_id", user.ID)
	ctx.Request().Session().Put("user_email", user.Email)
	ctx.Request().Session().Forget("pending_mfa_user_id")

	return ctx.Response().Redirect(302, "/dashboard")
}
