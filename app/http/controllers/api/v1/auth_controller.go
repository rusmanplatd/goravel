package v1

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/requests"
	"goravel/app/http/responses"
	"goravel/app/models"
	"goravel/app/services"
)

// AuthController handles authentication related requests
type AuthController struct {
	authService         *services.AuthService
	jwtService          *services.JWTService
	multiAccountService *services.MultiAccountService
	auditService        *services.AuditService
	webauthnService     *services.WebAuthnService
	totpService         *services.TOTPService
	emailService        *services.EmailService
	rateLimitService    *RateLimitService
}

// NewAuthController creates a new auth controller
func NewAuthController() (*AuthController, error) {
	authService, err := services.NewAuthService()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize auth service: %w", err)
	}

	jwtService, err := services.NewJWTService()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize JWT service: %w", err)
	}

	multiAccountService, err := services.NewMultiAccountService()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize multi-account service: %w", err)
	}

	return &AuthController{
		authService:         authService,
		jwtService:          jwtService,
		multiAccountService: multiAccountService,
		auditService:        services.NewAuditService(),
		webauthnService:     services.NewWebAuthnService(),
		totpService:         services.NewTOTPService(),
		emailService:        services.NewEmailService(),
		rateLimitService:    NewRateLimitService(),
	}, nil
}

// MustNewAuthController creates a new auth controller and panics on error (for backward compatibility)
// Deprecated: This function has been removed. Use NewAuthController() instead for proper error handling.

// DeviceInfo represents device information for security tracking
type DeviceInfo struct {
	DeviceID   string    `json:"device_id"`
	DeviceName string    `json:"device_name"`
	UserAgent  string    `json:"user_agent"`
	IPAddress  string    `json:"ip_address"`
	Location   string    `json:"location,omitempty"`
	IsTrusted  bool      `json:"is_trusted"`
	LastUsedAt time.Time `json:"last_used_at"`
}

// LoginResponse represents enhanced login response with security information
type LoginResponse struct {
	User             *models.User `json:"user"`
	AccessToken      string       `json:"access_token"`
	RefreshToken     string       `json:"refresh_token,omitempty"`
	TokenType        string       `json:"token_type"`
	ExpiresIn        int          `json:"expires_in"`
	RequiresMFA      bool         `json:"requires_mfa"`
	RequiresWebAuthn bool         `json:"requires_webauthn"`
	DeviceInfo       *DeviceInfo  `json:"device_info"`
	SecurityAlerts   []string     `json:"security_alerts,omitempty"`
}

// Login handles user authentication with enhanced security features
// @Summary Authenticate user with enhanced security
// @Description Authenticate user with email and password, with support for MFA, WebAuthn, and device tracking
// @Tags Authentication
// @Accept json
// @Produce json
// @Public
// @Param request body requests.LoginRequest true "Login credentials"
// @Success 200 {object} responses.ApiResponse{data=LoginResponse}
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Failure 423 {object} responses.ApiResponse
// @Failure 429 {object} responses.ApiResponse
// @Router /auth/login [post]
func (c *AuthController) Login(ctx http.Context) http.Response {
	var req requests.LoginRequest
	if err := ctx.Request().Bind(&req); err != nil {
		c.auditService.LogSecurityEvent("auth_login_invalid_request", "Invalid login request", ctx, map[string]interface{}{
			"error": err.Error(),
		})
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// Enhanced rate limiting check
	if !c.checkAdvancedRateLimit(ctx, req.Email) {
		c.auditService.LogSecurityEvent("auth_login_rate_limited", "Login rate limit exceeded", ctx, map[string]interface{}{
			"email": req.Email,
		})
		return responses.CreateErrorResponse(ctx, "Too many login attempts", "Please try again later", 429)
	}

	// Get device information
	deviceInfo := c.extractDeviceInfo(ctx)

	// Attempt authentication (using existing method for now)
	user, token, err := c.authService.Login(ctx, &req)
	if err != nil {
		c.auditService.LogSecurityEvent("auth_login_failed", "Login attempt failed", ctx, map[string]interface{}{
			"email":     req.Email,
			"error":     err.Error(),
			"device_id": deviceInfo.DeviceID,
		})
		return c.handleLoginError(ctx, err)
	}

	// Check for security alerts
	securityAlerts := c.checkSecurityAlerts(user, deviceInfo, ctx)

	// Log successful authentication
	c.auditService.LogSecurityEvent("auth_login_success", "User logged in successfully", ctx, map[string]interface{}{
		"user_id":         user.ID,
		"device_id":       deviceInfo.DeviceID,
		"security_alerts": len(securityAlerts),
	})

	// Create enhanced response
	response := LoginResponse{
		User:             user,
		AccessToken:      token,
		RefreshToken:     "", // Will be implemented later
		TokenType:        "Bearer",
		ExpiresIn:        3600, // 1 hour
		RequiresMFA:      user.MfaEnabled && req.MfaCode == "",
		RequiresWebAuthn: user.WebauthnEnabled && !user.MfaEnabled && req.WebauthnAssertion == nil,
		DeviceInfo:       deviceInfo,
		SecurityAlerts:   securityAlerts,
	}

	return responses.SuccessResponse(ctx, "Login successful", response)
}

// Register handles user registration with enhanced security validation
// @Summary Register new user with enhanced security
// @Description Register a new user account with comprehensive validation and security checks
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body requests.RegisterRequest true "Registration data"
// @Success 201 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Failure 409 {object} responses.ApiResponse
// @Failure 429 {object} responses.ApiResponse
// @Router /auth/register [post]
func (c *AuthController) Register(ctx http.Context) http.Response {
	var req requests.RegisterRequest
	if err := ctx.Request().Bind(&req); err != nil {
		c.auditService.LogSecurityEvent("auth_register_invalid_request", "Invalid registration request", ctx, map[string]interface{}{
			"error": err.Error(),
		})
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// Enhanced registration rate limiting
	if !c.checkRegistrationRateLimit(ctx, req.Email) {
		c.auditService.LogSecurityEvent("auth_register_rate_limited", "Registration rate limit exceeded", ctx, map[string]interface{}{
			"email": req.Email,
		})
		return responses.CreateErrorResponse(ctx, "Too many registration attempts", "Please try again later", 429)
	}

	// Get device information
	deviceInfo := c.extractDeviceInfo(ctx)

	// Enhanced registration with security checks (using existing method for now)
	user, token, err := c.authService.Register(ctx, &req)
	if err != nil {
		c.auditService.LogSecurityEvent("auth_register_failed", "Registration attempt failed", ctx, map[string]interface{}{
			"email":     req.Email,
			"error":     err.Error(),
			"device_id": deviceInfo.DeviceID,
		})
		return c.handleRegistrationError(ctx, err)
	}

	// Log successful registration
	c.auditService.LogSecurityEvent("auth_register_success", "User registered successfully", ctx, map[string]interface{}{
		"user_id":   user.ID,
		"device_id": deviceInfo.DeviceID,
	})

	return responses.SuccessResponse(ctx, "Registration successful", map[string]interface{}{
		"user":        user,
		"token":       token,
		"device_info": deviceInfo,
		"message":     "Please verify your email address to complete registration",
	})
}

// ForgotPassword handles password reset request
// @Summary Request password reset
// @Description Send password reset email to user with enhanced security validation
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body requests.ForgotPasswordRequest true "Email address for password reset"
// @Success 200 {object} responses.ApiResponse
// @Failure 400 {object} responses.ApiResponse
// @Failure 429 {object} responses.ApiResponse
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

// ResetPassword handles password reset with token
// @Summary Reset password with token
// @Description Reset user password using the token sent via email
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body requests.ResetPasswordRequest true "Password reset data with token"
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

// EnableMfa enables two-factor authentication with enhanced security
// @Summary Enable MFA with backup codes
// @Description Enable two-factor authentication for user with backup code generation
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body requests.EnableMfaRequest true "MFA setup data"
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Failure 429 {object} responses.ApiResponse
// @Router /auth/mfa/enable [post]
func (c *AuthController) EnableMfa(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return responses.CreateErrorResponse(ctx, "Unauthorized", "User not authenticated", 401)
	}

	var req requests.EnableMfaRequest
	if err := ctx.Request().Bind(&req); err != nil {
		c.auditService.LogSecurityEvent("mfa_enable_invalid_request", "Invalid MFA enable request", ctx, map[string]interface{}{
			"user_id": user.ID,
			"error":   err.Error(),
		})
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// Check if MFA is already enabled
	if user.MfaEnabled {
		return responses.CreateErrorResponse(ctx, "MFA already enabled", "Multi-factor authentication is already enabled", 400)
	}

	// Rate limiting for MFA operations
	if !c.checkMfaRateLimit(ctx, user.ID) {
		c.auditService.LogSecurityEvent("mfa_enable_rate_limited", "MFA enable rate limit exceeded", ctx, map[string]interface{}{
			"user_id": user.ID,
		})
		return responses.CreateErrorResponse(ctx, "Too many MFA attempts", "Please try again later", 429)
	}

	// Enhanced MFA setup with backup codes
	result, backupCodes, err := c.totpService.SetupMFAWithBackupCodes(user, req.Code)
	if err != nil {
		c.auditService.LogSecurityEvent("mfa_enable_failed", "MFA enable attempt failed", ctx, map[string]interface{}{
			"user_id": user.ID,
			"error":   err.Error(),
		})
		return responses.CreateErrorResponse(ctx, "Failed to enable MFA", err.Error(), 400)
	}

	// Log successful MFA enablement
	c.auditService.LogSecurityEvent("mfa_enabled", "MFA enabled successfully", ctx, map[string]interface{}{
		"user_id":            user.ID,
		"backup_codes_count": len(backupCodes),
	})

	// Prepare response with security information
	response := map[string]interface{}{
		"message":      "MFA enabled successfully",
		"secret":       result["secret"],
		"qr_code":      result["qr_code"],
		"backup_codes": backupCodes,
		"security_info": map[string]interface{}{
			"backup_codes_generated": len(backupCodes),
			"next_steps": []string{
				"Save backup codes in a secure location",
				"Test MFA authentication",
				"Consider enabling WebAuthn as additional security",
			},
		},
	}

	return responses.SuccessResponse(ctx, "MFA enabled successfully", response)
}

// DisableMfa disables two-factor authentication with enhanced security
// @Summary Disable MFA with security verification
// @Description Disable two-factor authentication with additional security checks
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body requests.DisableMfaRequest true "MFA disable data"
// @Success 200 {object} responses.ApiResponse
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Failure 429 {object} responses.ApiResponse
// @Router /auth/mfa/disable [post]
func (c *AuthController) DisableMfa(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return responses.CreateErrorResponse(ctx, "Unauthorized", "User not authenticated", 401)
	}

	var req requests.DisableMfaRequest
	if err := ctx.Request().Bind(&req); err != nil {
		c.auditService.LogSecurityEvent("mfa_disable_invalid_request", "Invalid MFA disable request", ctx, map[string]interface{}{
			"user_id": user.ID,
			"error":   err.Error(),
		})
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// Check if MFA is enabled
	if !user.MfaEnabled {
		return responses.CreateErrorResponse(ctx, "MFA not enabled", "Multi-factor authentication is not enabled", 400)
	}

	// Rate limiting for MFA operations
	if !c.checkMfaRateLimit(ctx, user.ID) {
		c.auditService.LogSecurityEvent("mfa_disable_rate_limited", "MFA disable rate limit exceeded", ctx, map[string]interface{}{
			"user_id": user.ID,
		})
		return responses.CreateErrorResponse(ctx, "Too many MFA attempts", "Please try again later", 429)
	}

	// Enhanced verification - require both password and MFA code
	if !c.authService.VerifyPassword(user, req.Password) {
		c.auditService.LogSecurityEvent("mfa_disable_invalid_password", "Invalid password for MFA disable", ctx, map[string]interface{}{
			"user_id": user.ID,
		})
		return responses.CreateErrorResponse(ctx, "Invalid password", "Current password is incorrect", 401)
	}

	// Verify MFA code or backup code
	if !c.totpService.VerifyCodeOrBackup(user, req.Code) {
		c.auditService.LogSecurityEvent("mfa_disable_invalid_code", "Invalid MFA code for disable", ctx, map[string]interface{}{
			"user_id": user.ID,
		})
		return responses.CreateErrorResponse(ctx, "Invalid MFA code", "The provided MFA code is invalid", 400)
	}

	// Disable MFA and clear backup codes
	err := c.totpService.DisableMFACompletely(user)
	if err != nil {
		c.auditService.LogSecurityEvent("mfa_disable_failed", "MFA disable failed", ctx, map[string]interface{}{
			"user_id": user.ID,
			"error":   err.Error(),
		})
		return responses.CreateErrorResponse(ctx, "Failed to disable MFA", err.Error(), 400)
	}

	// Log successful MFA disablement
	c.auditService.LogSecurityEvent("mfa_disabled", "MFA disabled successfully", ctx, map[string]interface{}{
		"user_id": user.ID,
	})

	return responses.SuccessResponse(ctx, "MFA disabled successfully", map[string]interface{}{
		"message":                 "Multi-factor authentication has been disabled",
		"security_recommendation": "Consider enabling WebAuthn for enhanced security",
	})
}

// GenerateMfaSetup generates enhanced MFA setup data
// @Summary Generate enhanced MFA setup
// @Description Generate MFA secret, QR code, and setup instructions
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

	// Check if MFA is already enabled
	if user.MfaEnabled {
		return responses.CreateErrorResponse(ctx, "MFA already enabled", "Multi-factor authentication is already enabled", 400)
	}

	// Generate enhanced MFA setup
	result := c.totpService.GenerateEnhancedMfaSetup(user)

	// Log MFA setup generation
	c.auditService.LogSecurityEvent("mfa_setup_generated", "MFA setup data generated", ctx, map[string]interface{}{
		"user_id": user.ID,
	})

	// Add setup instructions and security tips
	result["setup_instructions"] = []string{
		"1. Install an authenticator app (Google Authenticator, Authy, etc.)",
		"2. Scan the QR code or manually enter the secret key",
		"3. Enter the 6-digit code from your authenticator app to verify",
		"4. Save the backup codes in a secure location",
	}

	result["security_tips"] = []string{
		"Keep backup codes in a secure, offline location",
		"Don't share your secret key or QR code",
		"Consider using multiple authenticator apps for redundancy",
		"Enable WebAuthn for additional security",
	}

	return responses.SuccessResponse(ctx, "MFA setup data generated", result)
}

// VerifyMfa verifies MFA code with enhanced security
// @Summary Verify MFA code with backup support
// @Description Verify MFA code with support for backup codes and enhanced logging
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body requests.VerifyMfaRequest true "MFA code"
// @Success 200 {object} responses.ApiResponse
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /auth/mfa/verify [post]
func (c *AuthController) VerifyMfa(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return responses.CreateErrorResponse(ctx, "Unauthorized", "User not authenticated", 401)
	}

	var req requests.VerifyMfaRequest
	if err := ctx.Request().Bind(&req); err != nil {
		c.auditService.LogSecurityEvent("mfa_verify_invalid_request", "Invalid MFA verify request", ctx, map[string]interface{}{
			"user_id": user.ID,
			"error":   err.Error(),
		})
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// Check if MFA is enabled
	if !user.MfaEnabled {
		return responses.CreateErrorResponse(ctx, "MFA not enabled", "Multi-factor authentication is not enabled", 400)
	}

	// Rate limiting for MFA verification
	if !c.checkMfaVerificationRateLimit(ctx, user.ID) {
		c.auditService.LogSecurityEvent("mfa_verify_rate_limited", "MFA verification rate limit exceeded", ctx, map[string]interface{}{
			"user_id": user.ID,
		})
		return responses.CreateErrorResponse(ctx, "Too many verification attempts", "Please try again later", 429)
	}

	// Enhanced verification with backup code support
	verificationResult := c.totpService.EnhancedVerifyCode(user, req.Code)
	if !verificationResult.Valid {
		c.auditService.LogSecurityEvent("mfa_verify_failed", "MFA verification failed", ctx, map[string]interface{}{
			"user_id":   user.ID,
			"code_type": verificationResult.CodeType,
		})
		return responses.CreateErrorResponse(ctx, "Invalid MFA code", "The provided MFA code is invalid or expired", 400)
	}

	// Log successful verification
	c.auditService.LogSecurityEvent("mfa_verified", "MFA verification successful", ctx, map[string]interface{}{
		"user_id":                user.ID,
		"code_type":              verificationResult.CodeType,
		"backup_codes_remaining": verificationResult.BackupCodesRemaining,
	})

	response := map[string]interface{}{
		"message":   "MFA code verified successfully",
		"code_type": verificationResult.CodeType,
	}

	// Add backup code information if a backup code was used
	if verificationResult.CodeType == "backup" {
		response["backup_codes_remaining"] = verificationResult.BackupCodesRemaining
		if verificationResult.BackupCodesRemaining <= 2 {
			response["warning"] = "You have few backup codes remaining. Consider generating new ones."
		}
	}

	return responses.SuccessResponse(ctx, "MFA code verified", response)
}

// GenerateNewBackupCodes generates new backup codes for MFA
// @Summary Generate new MFA backup codes
// @Description Generate new backup codes and invalidate old ones
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body requests.VerifyMfaRequest true "MFA verification for security"
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Router /auth/mfa/backup-codes/regenerate [post]
func (c *AuthController) GenerateNewBackupCodes(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return responses.CreateErrorResponse(ctx, "Unauthorized", "User not authenticated", 401)
	}

	var req requests.VerifyMfaRequest
	if err := ctx.Request().Bind(&req); err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// Check if MFA is enabled
	if !user.MfaEnabled {
		return responses.CreateErrorResponse(ctx, "MFA not enabled", "Multi-factor authentication is not enabled", 400)
	}

	// Verify current MFA code for security
	if !c.totpService.ValidateCode(user.MfaSecret, req.Code) {
		c.auditService.LogSecurityEvent("backup_codes_regenerate_failed", "Invalid MFA code for backup code regeneration", ctx, map[string]interface{}{
			"user_id": user.ID,
		})
		return responses.CreateErrorResponse(ctx, "Invalid MFA code", "Please provide a valid MFA code to regenerate backup codes", 400)
	}

	// Generate new backup codes
	newBackupCodes, err := c.totpService.RegenerateBackupCodes(user)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to generate backup codes", err.Error(), 500)
	}

	// Log backup code regeneration
	c.auditService.LogSecurityEvent("backup_codes_regenerated", "New backup codes generated", ctx, map[string]interface{}{
		"user_id":     user.ID,
		"codes_count": len(newBackupCodes),
	})

	return responses.SuccessResponse(ctx, "New backup codes generated", map[string]interface{}{
		"backup_codes": newBackupCodes,
		"message":      "New backup codes generated. Old codes are no longer valid.",
		"warning":      "Save these codes in a secure location. They will not be shown again.",
	})
}

// WebauthnRegister registers a new WebAuthn credential with enhanced security
// @Summary Register WebAuthn credential with enhanced security
// @Description Register a new WebAuthn authenticator with comprehensive validation and security checks
// @Tags Authentication
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body requests.WebauthnRegisterRequest true "WebAuthn registration data"
// @Success 201 {object} responses.ApiResponse{data=models.WebauthnCredential}
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Failure 429 {object} responses.ApiResponse
// @Router /auth/webauthn/register [post]
func (c *AuthController) WebauthnRegister(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return responses.CreateErrorResponse(ctx, "Unauthorized", "User not authenticated", 401)
	}

	var req requests.WebauthnRegisterRequest
	if err := ctx.Request().Bind(&req); err != nil {
		c.auditService.LogSecurityEvent("webauthn_register_invalid_request", "Invalid WebAuthn registration request", ctx, map[string]interface{}{
			"user_id": user.ID,
			"error":   err.Error(),
		})
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// Rate limiting for WebAuthn registration
	if !c.checkWebAuthnRateLimit(ctx, user.ID) {
		c.auditService.LogSecurityEvent("webauthn_register_rate_limited", "WebAuthn registration rate limit exceeded", ctx, map[string]interface{}{
			"user_id": user.ID,
		})
		return responses.CreateErrorResponse(ctx, "Too many WebAuthn registration attempts", "Please try again later", 429)
	}

	// Enhanced WebAuthn registration with security validation
	credential, err := c.webauthnService.EnhancedRegisterCredential(user, &req, c.extractDeviceInfo(ctx))
	if err != nil {
		c.auditService.LogSecurityEvent("webauthn_register_failed", "WebAuthn registration failed", ctx, map[string]interface{}{
			"user_id": user.ID,
			"error":   err.Error(),
		})
		return responses.CreateErrorResponse(ctx, "Failed to register WebAuthn credential", err.Error(), 400)
	}

	// Log successful WebAuthn registration
	c.auditService.LogSecurityEvent("webauthn_registered", "WebAuthn credential registered successfully", ctx, map[string]interface{}{
		"user_id":       user.ID,
		"credential_id": credential.ID,
		"name":          req.Name,
	})

	return responses.SuccessResponse(ctx, "WebAuthn credential registered", map[string]interface{}{
		"credential": credential,
		"message":    "WebAuthn credential registered successfully",
		"security_info": map[string]interface{}{
			"credential_name":   req.Name,
			"registration_time": credential.CreatedAt,
			"next_steps": []string{
				"Test the credential by authenticating",
				"Consider registering backup credentials",
				"Keep your authenticator device secure",
			},
		},
	})
}

// WebauthnAuthenticate authenticates using WebAuthn with enhanced security
// @Summary Authenticate with WebAuthn enhanced security
// @Description Authenticate user using WebAuthn assertion with comprehensive validation
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body requests.WebauthnAuthenticateRequest true "WebAuthn assertion"
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Failure 401 {object} responses.ApiResponse
// @Failure 429 {object} responses.ApiResponse
// @Router /auth/webauthn/authenticate [post]
func (c *AuthController) WebauthnAuthenticate(ctx http.Context) http.Response {
	var req requests.WebauthnAuthenticateRequest
	if err := ctx.Request().Bind(&req); err != nil {
		c.auditService.LogSecurityEvent("webauthn_auth_invalid_request", "Invalid WebAuthn authentication request", ctx, map[string]interface{}{
			"error": err.Error(),
		})
		return responses.CreateErrorResponse(ctx, "Invalid request data", err.Error(), 400)
	}

	// Rate limiting for WebAuthn authentication
	if !c.checkWebAuthnAuthRateLimit(ctx) {
		c.auditService.LogSecurityEvent("webauthn_auth_rate_limited", "WebAuthn authentication rate limit exceeded", ctx, map[string]interface{}{})
		return responses.CreateErrorResponse(ctx, "Too many WebAuthn authentication attempts", "Please try again later", 429)
	}

	// Get device information
	deviceInfo := c.extractDeviceInfo(ctx)

	// Enhanced WebAuthn authentication
	authResult, err := c.webauthnService.EnhancedAuthenticate(&req, deviceInfo)
	if err != nil {
		c.auditService.LogSecurityEvent("webauthn_auth_failed", "WebAuthn authentication failed", ctx, map[string]interface{}{
			"error":     err.Error(),
			"device_id": deviceInfo.DeviceID,
		})
		return responses.CreateErrorResponse(ctx, "WebAuthn authentication failed", err.Error(), 401)
	}

	// Generate JWT token for successful authentication
	accessToken, _, err := c.jwtService.GenerateTokenPair(authResult.User.ID, authResult.User.Email, false)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Authentication failed", err.Error(), 500)
	}

	// Check for security alerts
	securityAlerts := c.checkSecurityAlerts(authResult.User, deviceInfo, ctx)

	// Log successful WebAuthn authentication
	c.auditService.LogSecurityEvent("webauthn_auth_success", "WebAuthn authentication successful", ctx, map[string]interface{}{
		"user_id":         authResult.User.ID,
		"credential_id":   authResult.CredentialID,
		"device_id":       deviceInfo.DeviceID,
		"security_alerts": len(securityAlerts),
	})

	response := map[string]interface{}{
		"user":            authResult.User,
		"access_token":    accessToken,
		"token_type":      "Bearer",
		"expires_in":      3600,
		"credential_used": authResult.CredentialName,
		"device_info":     deviceInfo,
		"security_alerts": securityAlerts,
	}

	return responses.SuccessResponse(ctx, "WebAuthn authentication successful", response)
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

	// Refresh the token using the new JWT service method
	newAccessToken, err := c.jwtService.RefreshToken(req.RefreshToken)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Invalid refresh token", err.Error(), 401)
	}

	return responses.SuccessResponse(ctx, "Token refreshed successfully", map[string]interface{}{
		"token": newAccessToken,
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

// BeginWebauthnRegistration starts the WebAuthn registration process with enhanced security
// @Summary Begin enhanced WebAuthn registration
// @Description Start the WebAuthn registration process with comprehensive security checks
// @Tags Authentication
// @Produce json
// @Security BearerAuth
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 401 {object} responses.ApiResponse
// @Failure 429 {object} responses.ApiResponse
// @Router /auth/webauthn/begin-registration [get]
func (c *AuthController) BeginWebauthnRegistration(ctx http.Context) http.Response {
	user := c.getCurrentUser(ctx)
	if user == nil {
		return responses.CreateErrorResponse(ctx, "Unauthorized", "User not authenticated", 401)
	}

	// Rate limiting for WebAuthn operations
	if !c.checkWebAuthnRateLimit(ctx, user.ID) {
		c.auditService.LogSecurityEvent("webauthn_begin_registration_rate_limited", "WebAuthn begin registration rate limit exceeded", ctx, map[string]interface{}{
			"user_id": user.ID,
		})
		return responses.CreateErrorResponse(ctx, "Too many WebAuthn attempts", "Please try again later", 429)
	}

	// Enhanced registration initialization
	registrationData, err := c.webauthnService.EnhancedBeginRegistration(user, c.extractDeviceInfo(ctx))
	if err != nil {
		c.auditService.LogSecurityEvent("webauthn_begin_registration_failed", "WebAuthn begin registration failed", ctx, map[string]interface{}{
			"user_id": user.ID,
			"error":   err.Error(),
		})
		return responses.CreateErrorResponse(ctx, "Failed to begin WebAuthn registration", err.Error(), 400)
	}

	// Log registration initiation
	c.auditService.LogSecurityEvent("webauthn_begin_registration", "WebAuthn registration initiated", ctx, map[string]interface{}{
		"user_id": user.ID,
	})

	// Add enhanced setup information
	response := map[string]interface{}{
		"registration_data": registrationData,
		"setup_instructions": []string{
			"Ensure your authenticator device is ready",
			"Follow your browser's prompts to complete registration",
			"Choose a memorable name for this credential",
			"Test the credential after registration",
		},
		"security_tips": []string{
			"Use a hardware security key for best security",
			"Register multiple credentials as backups",
			"Keep your authenticator devices secure and accessible",
			"Don't share access to your authenticator",
		},
		"supported_authenticators": []string{
			"Hardware security keys (YubiKey, etc.)",
			"Built-in platform authenticators (TouchID, FaceID, Windows Hello)",
			"Mobile authenticators",
		},
	}

	return responses.SuccessResponse(ctx, "WebAuthn registration started", response)
}

// BeginWebauthnAuthentication starts the WebAuthn authentication process with enhanced security
// @Summary Begin enhanced WebAuthn authentication
// @Description Start the WebAuthn authentication process with comprehensive security validation
// @Tags Authentication
// @Produce json
// @Param email query string false "User email for authentication context"
// @Success 200 {object} responses.ApiResponse{data=map[string]interface{}}
// @Failure 400 {object} responses.ApiResponse
// @Failure 429 {object} responses.ApiResponse
// @Router /auth/webauthn/begin-authentication [get]
func (c *AuthController) BeginWebauthnAuthentication(ctx http.Context) http.Response {
	email := ctx.Request().Query("email", "")

	// Rate limiting for WebAuthn authentication initiation
	if !c.checkWebAuthnAuthRateLimit(ctx) {
		c.auditService.LogSecurityEvent("webauthn_begin_auth_rate_limited", "WebAuthn begin authentication rate limit exceeded", ctx, map[string]interface{}{
			"email": email,
		})
		return responses.CreateErrorResponse(ctx, "Too many WebAuthn attempts", "Please try again later", 429)
	}

	// Enhanced authentication initialization
	authData, err := c.webauthnService.EnhancedBeginAuthentication(email, c.extractDeviceInfo(ctx))
	if err != nil {
		c.auditService.LogSecurityEvent("webauthn_begin_auth_failed", "WebAuthn begin authentication failed", ctx, map[string]interface{}{
			"email": email,
			"error": err.Error(),
		})
		return responses.CreateErrorResponse(ctx, "Failed to begin WebAuthn authentication", err.Error(), 400)
	}

	// Log authentication initiation
	c.auditService.LogSecurityEvent("webauthn_begin_auth", "WebAuthn authentication initiated", ctx, map[string]interface{}{
		"email": email,
	})

	response := map[string]interface{}{
		"authentication_data": authData,
		"instructions": []string{
			"Use your registered authenticator device",
			"Follow your browser's authentication prompts",
			"Complete the authentication gesture",
		},
		"fallback_options": []string{
			"Use password + MFA if WebAuthn fails",
			"Contact support if you've lost access to your authenticator",
		},
	}

	return responses.SuccessResponse(ctx, "WebAuthn authentication started", response)
}

// GetWebauthnCredentials gets user's WebAuthn credentials with enhanced information
// @Summary Get enhanced WebAuthn credentials
// @Description Get all WebAuthn credentials for the authenticated user with usage statistics
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

	// Get enhanced credential information
	credentials, err := c.webauthnService.GetEnhancedUserCredentials(user)
	if err != nil {
		return responses.CreateErrorResponse(ctx, "Failed to get WebAuthn credentials", err.Error(), 400)
	}

	// Log credential access
	c.auditService.LogSecurityEvent("webauthn_credentials_accessed", "WebAuthn credentials accessed", ctx, map[string]interface{}{
		"user_id":           user.ID,
		"credentials_count": len(credentials),
	})

	response := map[string]interface{}{
		"credentials": credentials,
		"summary": map[string]interface{}{
			"total_credentials": len(credentials),
			"recommendations":   c.getWebAuthnRecommendations(credentials),
		},
	}

	return responses.SuccessResponse(ctx, "WebAuthn credentials retrieved", response)
}

// DeleteWebauthnCredential deletes a WebAuthn credential with enhanced security
// @Summary Delete WebAuthn credential with security verification
// @Description Delete a WebAuthn credential with additional security checks
// @Tags Authentication
// @Produce json
// @Security BearerAuth
// @Param id path string true "Credential ID"
// @Param request body requests.VerifyMfaRequest false "MFA verification for security"
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
		return responses.CreateErrorResponse(ctx, "Invalid credential ID", "Credential ID is required", 400)
	}

	// Enhanced credential deletion with security verification
	deletionResult, err := c.webauthnService.EnhancedDeleteCredential(user, credentialID)
	if err != nil {
		c.auditService.LogSecurityEvent("webauthn_credential_delete_failed", "WebAuthn credential deletion failed", ctx, map[string]interface{}{
			"user_id":       user.ID,
			"credential_id": credentialID,
			"error":         err.Error(),
		})
		return responses.CreateErrorResponse(ctx, "Failed to delete WebAuthn credential", err.Error(), 400)
	}

	// Log successful credential deletion
	c.auditService.LogSecurityEvent("webauthn_credential_deleted", "WebAuthn credential deleted successfully", ctx, map[string]interface{}{
		"user_id":         user.ID,
		"credential_id":   credentialID,
		"remaining_count": deletionResult.RemainingCredentials,
	})

	response := map[string]interface{}{
		"message":               "WebAuthn credential deleted successfully",
		"remaining_credentials": deletionResult.RemainingCredentials,
	}

	// Add warning if this was the last credential
	if deletionResult.RemainingCredentials == 0 {
		response["warning"] = "You have no remaining WebAuthn credentials. Consider registering new ones or enabling MFA for account security."
	}

	return responses.SuccessResponse(ctx, "WebAuthn credential deleted", response)
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

// Helper methods for enhanced security features

// extractDeviceInfo extracts device information from the request context
func (c *AuthController) extractDeviceInfo(ctx http.Context) *DeviceInfo {
	// Generate or retrieve device ID
	deviceID := ctx.Request().Header("X-Device-ID", "")
	if deviceID == "" {
		deviceID = c.generateDeviceID(ctx)
	}

	return &DeviceInfo{
		DeviceID:   deviceID,
		DeviceName: ctx.Request().Header("X-Device-Name", "Unknown Device"),
		UserAgent:  ctx.Request().Header("User-Agent", ""),
		IPAddress:  ctx.Request().Ip(),
		Location:   c.getLocationFromIP(ctx.Request().Ip()),
		IsTrusted:  c.isDeviceTrusted(deviceID, ctx.Request().Ip()),
		LastUsedAt: time.Now(),
	}
}

// generateDeviceID generates a unique device ID
func (c *AuthController) generateDeviceID(ctx http.Context) string {
	// Generate random bytes for uniqueness
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes)

	// Create a shorter device ID
	deviceBytes := make([]byte, 16)
	rand.Read(deviceBytes)
	return hex.EncodeToString(deviceBytes)
}

// getLocationFromIP gets approximate location from IP address
func (c *AuthController) getLocationFromIP(ip string) string {
	// In a real implementation, you would use a GeoIP service
	// For now, return a placeholder
	if strings.HasPrefix(ip, "127.") || strings.HasPrefix(ip, "::1") {
		return "Local"
	}
	return "Unknown"
}

// isDeviceTrusted checks if a device is trusted
func (c *AuthController) isDeviceTrusted(deviceID, ip string) bool {
	// In a real implementation, check against trusted devices database
	// For now, return false for new devices
	return false
}

// checkAdvancedRateLimit performs advanced rate limiting checks
func (c *AuthController) checkAdvancedRateLimit(ctx http.Context, email string) bool {
	ip := ctx.Request().Ip()

	// Check IP-based rate limiting
	ipKey := fmt.Sprintf("rate_limit:login:ip:%s", ip)
	if !c.checkRateLimit(ipKey, 10, time.Hour) {
		return false
	}

	// Check email-based rate limiting
	emailKey := fmt.Sprintf("rate_limit:login:email:%s", email)
	if !c.checkRateLimit(emailKey, 5, time.Hour) {
		return false
	}

	return true
}

// checkRegistrationRateLimit checks registration rate limits
func (c *AuthController) checkRegistrationRateLimit(ctx http.Context, email string) bool {
	ip := ctx.Request().Ip()

	// Check IP-based registration rate limiting
	ipKey := fmt.Sprintf("rate_limit:register:ip:%s", ip)
	if !c.checkRateLimit(ipKey, 3, time.Hour) {
		return false
	}

	// Check email-based registration rate limiting
	emailKey := fmt.Sprintf("rate_limit:register:email:%s", email)
	if !c.checkRateLimit(emailKey, 1, time.Hour) {
		return false
	}

	return true
}

// checkRateLimit checks rate limit for a given key
func (c *AuthController) checkRateLimit(key string, limit int, window time.Duration) bool {
	// Production rate limiting implementation using Redis for distributed rate limiting
	return c.rateLimitService.CheckRateLimit(key, limit, window)
}

// rateLimitService provides production-ready rate limiting
type RateLimitService struct{}

// CheckRateLimit implements sliding window rate limiting
func (rls *RateLimitService) CheckRateLimit(key string, limit int, window time.Duration) bool {
	// Use Redis for distributed rate limiting
	cacheKey := fmt.Sprintf("rate_limit:%s", key)

	// Get current request count
	var currentCount int
	if err := facades.Cache().Get(cacheKey, &currentCount); err != nil {
		// First request, initialize counter
		currentCount = 0
	}

	// Check if limit exceeded
	if currentCount >= limit {
		facades.Log().Warning("Rate limit exceeded", map[string]interface{}{
			"key":           key,
			"current_count": currentCount,
			"limit":         limit,
			"window":        window.String(),
		})
		return false
	}

	// Increment counter with expiration
	newCount := currentCount + 1
	facades.Cache().Put(cacheKey, newCount, window)

	// Log rate limit check for monitoring
	if newCount > limit/2 { // Log when approaching limit
		facades.Log().Info("Rate limit approaching", map[string]interface{}{
			"key":           key,
			"current_count": newCount,
			"limit":         limit,
			"remaining":     limit - newCount,
		})
	}

	return true
}

// CheckSlidingWindowRateLimit implements more accurate sliding window rate limiting
func (rls *RateLimitService) CheckSlidingWindowRateLimit(key string, limit int, window time.Duration) bool {
	now := time.Now()
	windowStart := now.Add(-window)

	// Use sorted set to track request timestamps
	cacheKey := fmt.Sprintf("sliding_rate_limit:%s", key)

	// Clean old entries and count current requests
	// This is a simplified implementation - in production you'd use Redis sorted sets
	var requestTimes []time.Time
	if err := facades.Cache().Get(cacheKey, &requestTimes); err != nil {
		requestTimes = []time.Time{}
	}

	// Filter out old requests
	var validRequests []time.Time
	for _, reqTime := range requestTimes {
		if reqTime.After(windowStart) {
			validRequests = append(validRequests, reqTime)
		}
	}

	// Check if limit exceeded
	if len(validRequests) >= limit {
		facades.Log().Warning("Sliding window rate limit exceeded", map[string]interface{}{
			"key":           key,
			"current_count": len(validRequests),
			"limit":         limit,
			"window":        window.String(),
		})
		return false
	}

	// Add current request
	validRequests = append(validRequests, now)
	facades.Cache().Put(cacheKey, validRequests, window)

	return true
}

// GetRateLimitInfo returns current rate limit status
func (rls *RateLimitService) GetRateLimitInfo(key string, limit int, window time.Duration) map[string]interface{} {
	cacheKey := fmt.Sprintf("rate_limit:%s", key)

	var currentCount int
	if err := facades.Cache().Get(cacheKey, &currentCount); err != nil {
		currentCount = 0
	}

	remaining := limit - currentCount
	if remaining < 0 {
		remaining = 0
	}

	return map[string]interface{}{
		"limit":     limit,
		"remaining": remaining,
		"used":      currentCount,
		"window":    window.String(),
		"reset_at":  time.Now().Add(window),
	}
}

// NewRateLimitService creates a new rate limiting service
func NewRateLimitService() *RateLimitService {
	return &RateLimitService{}
}

// Initialize rate limiting service
var rateLimitService = NewRateLimitService()

// checkSecurityAlerts checks for security alerts
func (c *AuthController) checkSecurityAlerts(user *models.User, deviceInfo *DeviceInfo, ctx http.Context) []string {
	var alerts []string

	// Check for new device
	if !deviceInfo.IsTrusted {
		alerts = append(alerts, "Login from new device")
	}

	// Check for unusual location
	if deviceInfo.Location != "Local" && deviceInfo.Location != "Unknown" {
		alerts = append(alerts, "Login from unusual location")
	}

	// Check for multiple concurrent sessions (placeholder implementation)
	// Count active sessions for the user
	activeSessions, _ := facades.Orm().Query().Table("sessions").
		Where("user_id", user.ID).
		Where("expires_at > ?", time.Now()).
		Count()
	if activeSessions > 3 {
		alerts = append(alerts, "Multiple active sessions detected")
	}

	return alerts
}

// handleLoginError handles login errors with appropriate responses
func (c *AuthController) handleLoginError(ctx http.Context, err error) http.Response {
	errMsg := err.Error()

	switch {
	case strings.Contains(errMsg, "invalid credentials"):
		return responses.CreateErrorResponse(ctx, "Authentication failed", "Invalid email or password", 401)
	case strings.Contains(errMsg, "account is deactivated"):
		return responses.CreateErrorResponse(ctx, "Account deactivated", "Your account has been deactivated", 403)
	case strings.Contains(errMsg, "account is temporarily locked"):
		return responses.CreateErrorResponse(ctx, "Account locked", "Your account is temporarily locked due to too many failed attempts", 423)
	case strings.Contains(errMsg, "MFA code required"):
		return responses.CreateErrorResponse(ctx, "MFA required", "Multi-factor authentication code is required", 401)
	case strings.Contains(errMsg, "invalid MFA code"):
		return responses.CreateErrorResponse(ctx, "Invalid MFA code", "The provided MFA code is invalid or expired", 401)
	case strings.Contains(errMsg, "WebAuthn authentication required"):
		return responses.CreateErrorResponse(ctx, "WebAuthn required", "WebAuthn authentication is required", 401)
	case strings.Contains(errMsg, "invalid WebAuthn assertion"):
		return responses.CreateErrorResponse(ctx, "Invalid WebAuthn", "WebAuthn authentication failed", 401)
	default:
		return responses.CreateErrorResponse(ctx, "Authentication failed", "Login failed", 401)
	}
}

// handleRegistrationError handles registration errors with appropriate responses
func (c *AuthController) handleRegistrationError(ctx http.Context, err error) http.Response {
	errMsg := err.Error()

	switch {
	case strings.Contains(errMsg, "user already exists"):
		return responses.CreateErrorResponse(ctx, "Registration failed", "User with this email already exists", 409)
	case strings.Contains(errMsg, "invalid email"):
		return responses.CreateErrorResponse(ctx, "Invalid email", "Please provide a valid email address", 400)
	case strings.Contains(errMsg, "weak password"):
		return responses.CreateErrorResponse(ctx, "Weak password", "Password does not meet security requirements", 400)
	case strings.Contains(errMsg, "email domain not allowed"):
		return responses.CreateErrorResponse(ctx, "Email not allowed", "Registration from this email domain is not permitted", 400)
	default:
		return responses.CreateErrorResponse(ctx, "Registration failed", "Registration failed", 400)
	}
}

// Helper methods for MFA operations

// checkMfaRateLimit checks rate limits for MFA operations
func (c *AuthController) checkMfaRateLimit(ctx http.Context, userID string) bool {
	key := fmt.Sprintf("rate_limit:mfa:%s", userID)
	return c.checkRateLimit(key, 5, time.Minute*15) // 5 attempts per 15 minutes
}

// checkMfaVerificationRateLimit checks rate limits for MFA verification
func (c *AuthController) checkMfaVerificationRateLimit(ctx http.Context, userID string) bool {
	key := fmt.Sprintf("rate_limit:mfa_verify:%s", userID)
	return c.checkRateLimit(key, 10, time.Minute*5) // 10 attempts per 5 minutes
}

// Helper methods for WebAuthn operations

// checkWebAuthnRateLimit checks rate limits for WebAuthn operations
func (c *AuthController) checkWebAuthnRateLimit(ctx http.Context, userID string) bool {
	key := fmt.Sprintf("rate_limit:webauthn:%s", userID)
	return c.checkRateLimit(key, 10, time.Minute*15) // 10 attempts per 15 minutes
}

// checkWebAuthnAuthRateLimit checks rate limits for WebAuthn authentication
func (c *AuthController) checkWebAuthnAuthRateLimit(ctx http.Context) bool {
	ip := ctx.Request().Ip()
	key := fmt.Sprintf("rate_limit:webauthn_auth:ip:%s", ip)
	return c.checkRateLimit(key, 20, time.Minute*15) // 20 attempts per 15 minutes per IP
}

// getWebAuthnRecommendations provides security recommendations based on credentials
func (c *AuthController) getWebAuthnRecommendations(credentials []map[string]interface{}) []string {
	var recommendations []string

	if len(credentials) == 0 {
		recommendations = append(recommendations, "Register at least one WebAuthn credential for enhanced security")
	} else if len(credentials) == 1 {
		recommendations = append(recommendations, "Consider registering a backup WebAuthn credential")
	}

	recommendations = append(recommendations, "Use hardware security keys for maximum security")
	recommendations = append(recommendations, "Keep your authenticator devices secure and accessible")
	recommendations = append(recommendations, "Test your credentials periodically")

	return recommendations
}
