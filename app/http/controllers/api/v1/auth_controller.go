package v1

import (
	"github.com/goravel/framework/contracts/http"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
)

type AuthController struct {
	authService *services.AuthService
}

// NewAuthController creates a new authentication controller
func NewAuthController() *AuthController {
	return &AuthController{
		authService: services.NewAuthService(),
	}
}

// Login handles user authentication
// @Summary Authenticate user
// @Description Authenticate user with email and password, optionally with MFA or WebAuthn
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body requests.LoginRequest true "Login credentials"
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /auth/login [post]
func (c *AuthController) Login(ctx http.Context) http.Response {
	var req requests.LoginRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	user, token, err := c.authService.Login(ctx, &req)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Authentication failed", err.Error(), 401)
	}

	return responses.SuccessResponse(ctx, "Login successful", map[string]interface{}{
		"user":  user,
		"token": token,
	})
}

// Register handles user registration
// @Summary Register new user
// @Description Register a new user account
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body requests.RegisterRequest true "Registration data"
// @Success 201 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Failure 409 {object} responses.ApiResponse
// @Router /auth/register [post]
func (c *AuthController) Register(ctx http.Context) http.Response {
	var req requests.RegisterRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	user, token, err := c.authService.Register(ctx, &req)
	if err != nil {
		status := 400
		if err.Error() == "user already exists" {
			status = 409
		}
		return responses.CreateErrorResponse(ctx, "Registration failed", err.Error(), status)
	}

	return responses.SuccessResponse(ctx, "Registration successful", map[string]interface{}{
		"user":  user,
		"token": token,
	})
}

// ForgotPassword handles password reset request
// @Summary Request password reset
// @Description Send password reset email to user
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body requests.ForgotPasswordRequest true "Email address"
// @Success 200 {object} responses.ApiResponse
// @Failure 400 {object} responses.ApiResponse
// @Router /auth/forgot-password [post]
func (c *AuthController) ForgotPassword(ctx http.Context) http.Response {
	var req requests.ForgotPasswordRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	err := c.authService.ForgotPassword(ctx, &req)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to send reset email", err.Error(), 400)
	}

	return responses.SuccessResponse(ctx, "Password reset email sent", nil)
}

// ResetPassword handles password reset confirmation
// @Summary Reset password
// @Description Reset password using reset token
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body requests.ResetPasswordRequest true "Reset data"
// @Success 200 {object} responses.ApiResponse
// @Failure 400 {object} responses.ApiResponse
// @Router /auth/reset-password [post]
func (c *AuthController) ResetPassword(ctx http.Context) http.Response {
	var req requests.ResetPasswordRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	err := c.authService.ResetPassword(ctx, &req)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Password reset failed", err.Error(), 400)
	}

	return responses.SuccessResponse(ctx, "Password reset successful", nil)
}

// EnableMfa enables two-factor authentication
// @Summary Enable MFA
// @Description Enable two-factor authentication for user
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body requests.EnableMfaRequest true "MFA setup data"
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Router /auth/mfa/enable [post]
func (c *AuthController) EnableMfa(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return responses.CreateErrorResponse(ctx, "Unauthorized", "User not authenticated", 401)
	}

	var req requests.EnableMfaRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	result, err := c.authService.EnableMfa(ctx, user, &req)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to enable MFA", err.Error(), 400)
	}

	return responses.SuccessResponse(ctx, "MFA enabled successfully", result)
}

// DisableMfa disables two-factor authentication
// @Summary Disable MFA
// @Description Disable two-factor authentication for user
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body requests.DisableMfaRequest true "MFA disable data"
// @Success 200 {object} responses.ApiResponse
// @Failure 400 {object} responses.ApiResponse
// @Router /auth/mfa/disable [post]
func (c *AuthController) DisableMfa(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return responses.CreateErrorResponse(ctx, "Unauthorized", "User not authenticated", 401)
	}

	var req requests.DisableMfaRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	err := c.authService.DisableMfa(ctx, user, &req)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to disable MFA", err.Error(), 400)
	}

	return responses.SuccessResponse(ctx, "MFA disabled successfully", nil)
}

// GenerateMfaSetup generates MFA setup data
// @Summary Generate MFA setup
// @Description Generate MFA secret and QR code for setup
// @Tags Authentication
// @Produce json
// @Security BearerAuth
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 401 {object} responses.ApiResponse
// @Router /auth/mfa/setup [get]
func (c *AuthController) GenerateMfaSetup(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return responses.CreateErrorResponse(ctx, "Unauthorized", "User not authenticated", 401)
	}

	result := c.authService.GenerateMfaSetup(user)
	return responses.SuccessResponse(ctx, "MFA setup data generated", result)
}

// VerifyMfa verifies MFA code
// @Summary Verify MFA code
// @Description Verify MFA code for authentication
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body requests.VerifyMfaRequest true "MFA code"
// @Success 200 {object} responses.ApiResponse
// @Failure 400 {object} responses.ApiResponse
// @Router /auth/mfa/verify [post]
func (c *AuthController) VerifyMfa(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return responses.CreateErrorResponse(ctx, "Unauthorized", "User not authenticated", 401)
	}

	var req requests.VerifyMfaRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	if !c.authService.VerifyMfa(user, req.Code) {
		return responses.CreateErrorResponse(ctx, "Invalid MFA code", "The provided MFA code is invalid", 400)
	}

	return responses.SuccessResponse(ctx, "MFA code verified", nil)
}

// WebauthnRegister registers a new WebAuthn credential
// @Summary Register WebAuthn credential
// @Description Register a new WebAuthn authenticator for user
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body requests.WebauthnRegisterRequest true "WebAuthn registration data"
// @Success 201 {object} responses.ApiResponse{data=models.WebauthnCredential}
// @Failure 400 {object} responses.ApiResponse
// @Router /auth/webauthn/register [post]
func (c *AuthController) WebauthnRegister(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return responses.CreateErrorResponse(ctx, "Unauthorized", "User not authenticated", 401)
	}

	var req requests.WebauthnRegisterRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	credential, err := c.authService.WebauthnRegister(ctx, user, &req)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to register WebAuthn credential", err.Error(), 400)
	}

	return responses.SuccessResponse(ctx, "WebAuthn credential registered", credential)
}

// WebauthnAuthenticate authenticates using WebAuthn
// @Summary Authenticate with WebAuthn
// @Description Authenticate user using WebAuthn assertion
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body requests.WebauthnAuthenticateRequest true "WebAuthn assertion"
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Router /auth/webauthn/authenticate [post]
func (c *AuthController) WebauthnAuthenticate(ctx http.Context) http.Response {
	var req requests.WebauthnAuthenticateRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// In a real implementation, you would identify the user from the assertion
	// For now, we'll use a placeholder
	var user models.User
	if !c.authService.WebauthnAuthenticate(ctx, &user, &req) {
		return responses.CreateErrorResponse(ctx, "WebAuthn authentication failed", "Invalid assertion", 400)
	}

	token, err := c.authService.GenerateJWTToken(&user, false)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Authentication failed", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "WebAuthn authentication successful", map[string]interface{}{
		"user":  user,
		"token": token,
	})
}

// ChangePassword changes user password
// @Summary Change password
// @Description Change user password
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body requests.ChangePasswordRequest true "Password change data"
// @Success 200 {object} responses.ApiResponse
// @Failure 400 {object} responses.ApiResponse
// @Router /auth/change-password [post]
func (c *AuthController) ChangePassword(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return responses.CreateErrorResponse(ctx, "Unauthorized", "User not authenticated", 401)
	}

	var req requests.ChangePasswordRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	err := c.authService.ChangePassword(ctx, user, &req)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to change password", err.Error(), 400)
	}

	return responses.SuccessResponse(ctx, "Password changed successfully", nil)
}

// RefreshToken refreshes JWT token
// @Summary Refresh token
// @Description Refresh JWT authentication token
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body requests.RefreshTokenRequest true "Refresh token"
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Router /auth/refresh [post]
func (c *AuthController) RefreshToken(ctx http.Context) http.Response {
	var req requests.RefreshTokenRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	token, err := c.authService.RefreshToken(ctx, &req)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Token refresh failed", err.Error(), 400)
	}

	return responses.SuccessResponse(ctx, "Token refreshed successfully", map[string]interface{}{
		"token": token,
	})
}

// Logout handles user logout
// @Summary Logout user
// @Description Logout user and invalidate session
// @Tags Authentication
// @Produce json
// @Security BearerAuth
// @Success 200 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /auth/logout [post]
func (c *AuthController) Logout(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return responses.CreateErrorResponse(ctx, "Unauthorized", "User not authenticated", 401)
	}

	err := c.authService.Logout(ctx, user)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Logout failed", err.Error(), 500)
	}

	return responses.SuccessResponse(ctx, "Logout successful", nil)
}

// GetProfile gets current user profile
// @Summary Get user profile
// @Description Get current authenticated user profile
// @Tags Authentication
// @Produce json
// @Security BearerAuth
// @Success 200 {object} responses.ApiResponse{data=models.User}
// @Failure 401 {object} responses.ApiResponse
// @Router /auth/profile [get]
func (c *AuthController) GetProfile(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return responses.CreateErrorResponse(ctx, "Unauthorized", "User not authenticated", 401)
	}

	return responses.SuccessResponse(ctx, "Profile retrieved successfully", user)
}

// BeginWebauthnRegistration starts the WebAuthn registration process
// @Summary Begin WebAuthn registration
// @Description Start the WebAuthn registration process for user
// @Tags Authentication
// @Produce json
// @Security BearerAuth
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 401 {object} responses.ApiResponse
// @Router /auth/webauthn/begin-registration [get]
func (c *AuthController) BeginWebauthnRegistration(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return responses.CreateErrorResponse(ctx, "Unauthorized", "User not authenticated", 401)
	}

	registrationData, err := c.authService.GetWebAuthnService().BeginRegistration(user)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to begin WebAuthn registration", err.Error(), 400)
	}

	return responses.SuccessResponse(ctx, "WebAuthn registration started", registrationData)
}

// BeginWebauthnAuthentication starts the WebAuthn authentication process
// @Summary Begin WebAuthn authentication
// @Description Start the WebAuthn authentication process for user
// @Tags Authentication
// @Produce json
// @Security BearerAuth
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 401 {object} responses.ApiResponse
// @Router /auth/webauthn/begin-authentication [get]
func (c *AuthController) BeginWebauthnAuthentication(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return responses.CreateErrorResponse(ctx, "Unauthorized", "User not authenticated", 401)
	}

	authData, err := c.authService.GetWebAuthnService().BeginLogin(user)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to begin WebAuthn authentication", err.Error(), 400)
	}

	return responses.SuccessResponse(ctx, "WebAuthn authentication started", authData)
}

// GetWebauthnCredentials gets user's WebAuthn credentials
// @Summary Get WebAuthn credentials
// @Description Get all WebAuthn credentials for the authenticated user
// @Tags Authentication
// @Produce json
// @Security BearerAuth
// @Success 200 {object} responses.ApiResponse{data=[]models.WebauthnCredential}
// @Failure 401 {object} responses.ApiResponse
// @Router /auth/webauthn/credentials [get]
func (c *AuthController) GetWebauthnCredentials(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return responses.CreateErrorResponse(ctx, "Unauthorized", "User not authenticated", 401)
	}

	credentials, err := c.authService.GetWebAuthnService().GetUserCredentials(user)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to get WebAuthn credentials", err.Error(), 400)
	}

	return responses.SuccessResponse(ctx, "WebAuthn credentials retrieved", credentials)
}

// DeleteWebauthnCredential deletes a WebAuthn credential
// @Summary Delete WebAuthn credential
// @Description Delete a specific WebAuthn credential for the authenticated user
// @Tags Authentication
// @Produce json
// @Security BearerAuth
// @Param id path string true "Credential ID"
// @Success 200 {object} responses.ApiResponse
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /auth/webauthn/credentials/{id} [delete]
func (c *AuthController) DeleteWebauthnCredential(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return responses.CreateErrorResponse(ctx, "Unauthorized", "User not authenticated", 401)
	}

	credentialID := ctx.Request().Route("id")
	if credentialID == "" {
		return responses.CreateErrorResponse(ctx, "Invalid request", "Credential ID is required", 400)
	}

	err := c.authService.GetWebAuthnService().DeleteCredential(user, credentialID)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to delete WebAuthn credential", err.Error(), 400)
	}

	return responses.SuccessResponse(ctx, "WebAuthn credential deleted", nil)
}

// Helper methods

func (c *AuthController) getCurrentUser(ctx http.Context) *models.User {
	// Get user from context (set by auth middleware)
	user := ctx.Value("user")
	if user == nil {
		return nil
	}

	// Type assertion
	if userModel, ok := user.(*models.User); ok {
		return userModel
	}

	return nil
}
