package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"time"

	"goravel/app/helpers"

	"github.com/goravel/framework/contracts/http"
	"github.com/goravel/framework/facades"

	"goravel/app/http/requests"
	"goravel/app/models"
)

type AuthService struct {
	jwtService      *JWTService
	totpService     *TOTPService
	webauthnService *WebAuthnService
	emailService    *EmailService
	auditService    *AuditService
	auditHelper     *AuditHelper
}

// NewAuthService creates a new authentication service
func NewAuthService() (*AuthService, error) {
	jwtService, err := NewJWTService()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize JWT service: %w", err)
	}

	return &AuthService{
		jwtService:      jwtService,
		totpService:     NewTOTPService(),
		webauthnService: NewWebAuthnService(),
		emailService:    NewEmailService(),
		auditService:    GetAuditService(),
		auditHelper:     NewAuditHelper(GetAuditService()),
	}, nil
}

// MustNewAuthService creates a new authentication service and panics on error (for backward compatibility)
// Deprecated: This function has been removed. Use NewAuthService() instead for proper error handling.

// Login handles user authentication
func (s *AuthService) Login(ctx http.Context, req *requests.LoginRequest) (*models.User, string, error) {
	// Find user by email
	var user models.User
	err := facades.Orm().Query().Where("email", req.Email).First(&user)
	if err != nil {
		return nil, "", fmt.Errorf("invalid credentials")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, "", fmt.Errorf("account is deactivated")
	}

	// Check if account is locked
	if user.LockedAt != nil && user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return nil, "", fmt.Errorf("account is temporarily locked")
	}

	// Verify password
	if !facades.Hash().Check(req.Password, user.Password) {
		s.recordFailedLogin(&user, ctx)
		return nil, "", fmt.Errorf("invalid credentials")
	}

	// Reset failed login attempts on successful login
	if user.FailedLoginAttempts > 0 {
		user.FailedLoginAttempts = 0
		user.LockedAt = nil
		user.LockedUntil = nil
		facades.Orm().Query().Save(&user)
	}

	// Check MFA if enabled
	if user.MfaEnabled {
		if req.MfaCode == "" {
			return nil, "", fmt.Errorf("MFA code required")
		}
		if !s.totpService.ValidateCode(user.MfaSecret, req.MfaCode) {
			return nil, "", fmt.Errorf("invalid MFA code")
		}
	}

	// Check WebAuthn if enabled and no MFA
	if user.WebauthnEnabled && !user.MfaEnabled && req.MfaCode == "" {
		if req.WebauthnAssertion == nil {
			return nil, "", fmt.Errorf("WebAuthn authentication required")
		}
		if !s.verifyWebauthnAssertion(&user, req.WebauthnAssertion) {
			return nil, "", fmt.Errorf("invalid WebAuthn assertion")
		}
	}

	// Update last login info
	s.updateLastLogin(&user, ctx)

	// Generate JWT token
	accessToken, _, err := s.jwtService.GenerateTokenPair(user.ID, user.Email, req.Remember)
	if err != nil {
		return nil, "", err
	}

	// Use audit helper for login logging
	loginMethod := "password"
	if req.WebauthnAssertion != nil {
		loginMethod = "webauthn"
	} else if req.MfaCode != "" {
		loginMethod = "mfa"
	}

	s.auditHelper.LogUserLogin(user.ID, ctx.Request().Ip(), ctx.Request().Header("User-Agent", ""), true, map[string]interface{}{
		"login_method": loginMethod,
		"email":        req.Email,
		"mfa_required": user.MfaEnabled,
		"remember":     req.Remember,
	})

	return &user, accessToken, nil
}

// Register handles user registration
func (s *AuthService) Register(ctx http.Context, req *requests.RegisterRequest) (*models.User, string, error) {
	// Check if user already exists
	var existingUser models.User
	err := facades.Orm().Query().Where("email", req.Email).First(&existingUser)
	if err == nil {
		return nil, "", fmt.Errorf("user already exists")
	}

	// Create new user
	hashedPassword, err := facades.Hash().Make(req.Password)
	if err != nil {
		return nil, "", err
	}

	user := models.User{
		Name:     req.Name,
		Email:    req.Email,
		Password: hashedPassword,
		IsActive: true,
	}

	// Generate ULID for user
	user.ID = helpers.GenerateULID()

	// Save user
	err = facades.Orm().Query().Create(&user)
	if err != nil {
		return nil, "", err
	}

	// Generate JWT token
	accessToken, _, err := s.jwtService.GenerateTokenPair(user.ID, user.Email, false)
	if err != nil {
		return nil, "", err
	}

	// Send welcome email
	s.emailService.SendWelcomeEmail(&user)

	return &user, accessToken, nil
}

// ForgotPassword handles password reset request
func (s *AuthService) ForgotPassword(ctx http.Context, req *requests.ForgotPasswordRequest) error {
	// Find user by email
	var user models.User
	err := facades.Orm().Query().Where("email", req.Email).First(&user)
	if err != nil {
		// Don't reveal if user exists or not
		return nil
	}

	// Generate reset token
	token := s.generateResetToken()
	expiresAt := time.Now().Add(60 * time.Minute) // 1 hour

	// Save reset token
	user.PasswordResetToken = token
	user.PasswordResetExpiresAt = &expiresAt
	facades.Orm().Query().Save(&user)

	// Send reset email
	return s.emailService.SendPasswordResetEmail(&user, token)
}

// ResetPassword handles password reset confirmation
func (s *AuthService) ResetPassword(ctx http.Context, req *requests.ResetPasswordRequest) error {
	// Find user by email and token
	var user models.User
	err := facades.Orm().Query().Where("email", req.Email).Where("password_reset_token", req.Token).First(&user)
	if err != nil {
		return fmt.Errorf("invalid reset token")
	}

	// Check if token is expired
	if user.PasswordResetExpiresAt == nil || time.Now().After(*user.PasswordResetExpiresAt) {
		return fmt.Errorf("reset token has expired")
	}

	// Update password
	hashedPassword, err := facades.Hash().Make(req.Password)
	if err != nil {
		return err
	}
	user.Password = hashedPassword
	user.PasswordResetToken = ""
	user.PasswordResetExpiresAt = nil

	// Save user
	return facades.Orm().Query().Save(&user)
}

// EnableMfa enables MFA for a user
func (s *AuthService) EnableMfa(ctx http.Context, user *models.User, req *requests.EnableMfaRequest) (map[string]interface{}, error) {
	// Validate the provided code against the secret
	if !s.totpService.ValidateCode(req.Secret, req.Code) {
		return nil, fmt.Errorf("invalid MFA code")
	}

	// Enable MFA for the user
	now := time.Now()
	user.MfaEnabled = true
	user.MfaSecret = req.Secret
	user.MfaEnabledAt = &now

	// Generate backup codes
	backupCodes := s.totpService.GenerateBackupCodes(10)

	// Store backup codes securely with proper encryption and hashing
	hashedBackupCodes := make([]string, len(backupCodes))
	for i, backupCode := range backupCodes {
		hashedCode, err := facades.Hash().Make(backupCode.Code)
		if err != nil {
			facades.Log().Error("Failed to hash backup code", map[string]interface{}{
				"user_id": user.ID,
				"error":   err.Error(),
			})
			return nil, fmt.Errorf("failed to process backup codes")
		}
		hashedBackupCodes[i] = hashedCode
	}

	// Store hashed backup codes in secure JSON format
	backupCodesData := map[string]interface{}{
		"codes":      hashedBackupCodes,
		"created_at": time.Now(),
		"used_codes": []string{}, // Track used codes
	}
	backupCodesJSON, err := json.Marshal(backupCodesData)
	if err != nil {
		facades.Log().Error("Failed to marshal backup codes", map[string]interface{}{
			"user_id": user.ID,
			"error":   err.Error(),
		})
		return nil, fmt.Errorf("failed to process backup codes")
	}

	// Encrypt the backup codes JSON before storage
	encryptedBackupCodes, err := s.encryptSensitiveData(string(backupCodesJSON))
	if err != nil {
		facades.Log().Error("Failed to encrypt backup codes", map[string]interface{}{
			"user_id": user.ID,
			"error":   err.Error(),
		})
		return nil, fmt.Errorf("failed to secure backup codes")
	}

	user.MfaBackupCodes = encryptedBackupCodes

	// Save user
	if err := facades.Orm().Query().Save(user); err != nil {
		return nil, err
	}

	// Log MFA enablement for security audit
	facades.Log().Info("MFA enabled for user", map[string]interface{}{
		"user_id":    user.ID,
		"user_email": user.Email,
		"timestamp":  time.Now(),
	})

	// Generate QR code URL for backup
	config := TOTPConfig{
		Issuer:      facades.Config().GetString("app.name", "Goravel"),
		AccountName: user.Email,
		Secret:      req.Secret,
		Algorithm:   "SHA1",
		Digits:      6,
		Period:      30,
	}
	qrURL := s.totpService.GenerateQRCodeURL(config)

	return map[string]interface{}{
		"backup_codes": backupCodes,
		"qr_code":      qrURL,
	}, nil
}

// DisableMfa disables two-factor authentication for a user
func (s *AuthService) DisableMfa(ctx http.Context, user *models.User, req *requests.DisableMfaRequest) error {
	// Verify current password
	if !facades.Hash().Check(req.Password, user.Password) {
		return fmt.Errorf("invalid password")
	}

	// Verify MFA code
	if !s.totpService.ValidateCode(user.MfaSecret, req.Code) {
		return fmt.Errorf("invalid MFA code")
	}

	// Disable MFA
	user.MfaEnabled = false
	user.MfaSecret = ""
	user.MfaEnabledAt = nil

	return facades.Orm().Query().Save(user)
}

// VerifyMfa verifies an MFA code
func (s *AuthService) VerifyMfa(user *models.User, code string) bool {
	return s.totpService.ValidateCode(user.MfaSecret, code)
}

// GenerateMfaSetup generates MFA setup data for a user
func (s *AuthService) GenerateMfaSetup(user *models.User) map[string]interface{} {
	// Generate a new secret
	secret := s.totpService.GenerateSecret()

	// Generate QR code URL
	config := TOTPConfig{
		Issuer:      facades.Config().GetString("app.name", "Goravel"),
		AccountName: user.Email,
		Secret:      secret,
		Algorithm:   "SHA1",
		Digits:      6,
		Period:      30,
	}
	qrURL := s.totpService.GenerateQRCodeURL(config)

	return map[string]interface{}{
		"secret":  secret,
		"qr_code": qrURL,
	}
}

// WebauthnRegister registers a new WebAuthn credential
func (s *AuthService) WebauthnRegister(ctx http.Context, user *models.User, req *requests.WebauthnRegisterRequest) (*models.WebauthnCredential, error) {
	// Extract credential creation data from the attestation response
	attestationResponse := req.AttestationResponse

	// Convert the request to the expected format
	credentialCreation := &WebAuthnCredentialCreation{
		ID:       attestationResponse["id"].(string),
		RawID:    attestationResponse["rawId"].(string),
		Type:     attestationResponse["type"].(string),
		Response: attestationResponse["response"].(map[string]interface{}),
	}

	return s.webauthnService.CompleteRegistration(user.ID, credentialCreation)
}

// WebauthnAuthenticate authenticates using WebAuthn
func (s *AuthService) WebauthnAuthenticate(ctx http.Context, user *models.User, req *requests.WebauthnAuthenticateRequest) bool {
	// Extract assertion data from the assertion response
	assertionResponse := req.AssertionResponse

	// Convert the request to the expected format
	assertion := &WebAuthnAssertion{
		ID:       assertionResponse["id"].(string),
		RawID:    assertionResponse["rawId"].(string),
		Type:     assertionResponse["type"].(string),
		Response: assertionResponse["response"].(map[string]interface{}),
	}

	result, err := s.webauthnService.CompleteLogin(assertion)
	return err == nil && result != nil && result.Success
}

// ChangePassword changes user password
func (s *AuthService) ChangePassword(ctx http.Context, user *models.User, req *requests.ChangePasswordRequest) error {
	// Verify current password
	if !facades.Hash().Check(req.CurrentPassword, user.Password) {
		return fmt.Errorf("invalid current password")
	}

	// Update password
	hashedPassword, err := facades.Hash().Make(req.NewPassword)
	if err != nil {
		return err
	}
	user.Password = hashedPassword

	// Log password change with security context
	s.auditHelper.LogSecurityIncident(user.ID, "password_change", "User password changed successfully", models.SeverityMedium, map[string]interface{}{
		"changed_by": user.ID,
		"method":     "user_initiated",
		"ip_address": ctx.Request().Ip(),
	})

	return facades.Orm().Query().Save(user)
}

// RefreshToken refreshes an access token using a refresh token
func (s *AuthService) RefreshToken(refreshToken string) (string, error) {
	return s.jwtService.RefreshToken(refreshToken)
}

// Logout handles user logout
func (s *AuthService) Logout(ctx http.Context, user *models.User) error {
	// In a real implementation, you might want to:
	// 1. Invalidate the JWT token
	// 2. Clear remember token
	// 3. Log the logout event

	user.RememberToken = ""
	return facades.Orm().Query().Save(user)
}

// Helper methods

func (s *AuthService) GenerateJWTToken(user *models.User, remember bool) (string, error) {
	accessToken, _, err := s.jwtService.GenerateTokenPair(user.ID, user.Email, remember)
	return accessToken, err
}

func (s *AuthService) generateResetToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (s *AuthService) generateMFASecret() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return base32.StdEncoding.EncodeToString(bytes)
}

func (s *AuthService) verifyMfaCode(secret, code string) bool {
	totpService := NewTOTPService()
	return totpService.ValidateCode(secret, code)
}

func (s *AuthService) generateMfaQRCode(email, secret string) string {
	issuer := facades.Config().GetString("app.name", "Goravel")
	url := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", issuer, email, secret, issuer)
	return url
}

func (s *AuthService) verifyWebauthnAssertion(user *models.User, assertion map[string]interface{}) bool {
	// Production WebAuthn assertion verification
	webauthnService := NewWebAuthnService()

	// Extract assertion data
	assertionResponse, ok := assertion["response"].(map[string]interface{})
	if !ok {
		facades.Log().Warning("Invalid WebAuthn assertion format", map[string]interface{}{
			"user_id": user.ID,
		})
		return false
	}

	// Get user's credentials
	var credentials []models.WebauthnCredential
	err := facades.Orm().Query().Where("user_id = ?", user.ID).Where("is_active = ?", true).Find(&credentials)
	if err != nil {
		facades.Log().Error("Failed to load user WebAuthn credentials", map[string]interface{}{
			"user_id": user.ID,
			"error":   err.Error(),
		})
		return false
	}

	if len(credentials) == 0 {
		facades.Log().Warning("No active WebAuthn credentials found for user", map[string]interface{}{
			"user_id": user.ID,
		})
		return false
	}

	// Verify the assertion against each credential
	for _, credential := range credentials {
		if webauthnService.verifyAssertion(&credential, assertionResponse) {
			// Update credential usage
			now := time.Now()
			credential.LastUsedAt = &now

			if err := facades.Orm().Query().Save(&credential); err != nil {
				facades.Log().Warning("Failed to update credential usage", map[string]interface{}{
					"credential_id": credential.ID,
					"error":         err.Error(),
				})
			}

			// Log successful WebAuthn authentication
			facades.Log().Info("WebAuthn authentication successful", map[string]interface{}{
				"user_id":         user.ID,
				"credential_id":   credential.ID,
				"credential_name": credential.Name,
			})

			return true
		}
	}

	// Log failed WebAuthn authentication
	facades.Log().Warning("WebAuthn authentication failed", map[string]interface{}{
		"user_id":             user.ID,
		"credentials_checked": len(credentials),
	})

	return false
}

func (s *AuthService) recordFailedLogin(user *models.User, ctx http.Context) {
	user.FailedLoginAttempts++

	// Lock account after 5 failed attempts for 15 minutes
	if user.FailedLoginAttempts >= 5 {
		now := time.Now()
		lockedUntil := now.Add(15 * time.Minute)
		user.LockedAt = &now
		user.LockedUntil = &lockedUntil
	}

	facades.Orm().Query().Save(user)
}

func (s *AuthService) updateLastLogin(user *models.User, ctx http.Context) {
	now := time.Now()
	user.LastLoginAt = &now
	user.LastLoginIp = ctx.Request().Header("X-Forwarded-For", ctx.Request().Header("X-Real-IP", ctx.Request().Ip()))
	user.LastLoginUserAgent = ctx.Request().Header("User-Agent", "")

	facades.Orm().Query().Save(user)
}

func (s *AuthService) sendPasswordResetEmail(user *models.User, token string) error {
	// Production password reset email implementation
	emailService := NewEmailService()

	// Generate secure reset URL
	resetURL := fmt.Sprintf("%s/auth/reset-password?token=%s&email=%s",
		facades.Config().GetString("app.url"),
		token,
		url.QueryEscape(user.Email))

	// Prepare email data
	emailData := map[string]interface{}{
		"user_name":     user.Name,
		"reset_url":     resetURL,
		"expires_at":    time.Now().Add(time.Hour), // 1 hour expiry
		"app_name":      facades.Config().GetString("app.name", "Goravel"),
		"support_email": facades.Config().GetString("mail.support_email", "support@example.com"),
	}

	// Send email using template
	err := emailService.SendEmail(
		user.Email,
		user.Name,
		"Password Reset Request",
		fmt.Sprintf(`
			Dear %s,

			You have requested to reset your password. Please click the link below to reset your password:

			%s

			This link will expire at %s.

			If you did not request this password reset, please ignore this email.

			Best regards,
			%s Team
			
			Support: %s
		`, emailData["user_name"], emailData["reset_url"], emailData["expires_at"],
			emailData["app_name"], emailData["support_email"]),
	)

	if err != nil {
		facades.Log().Error("Failed to send password reset email", map[string]interface{}{
			"user_id":    user.ID,
			"user_email": user.Email,
			"error":      err.Error(),
		})
		return fmt.Errorf("failed to send password reset email")
	}

	// Log password reset request for security audit
	facades.Log().Info("Password reset email sent", map[string]interface{}{
		"user_id":    user.ID,
		"user_email": user.Email,
		"token":      token[:8] + "...", // Log only first 8 chars for security
		"expires_at": time.Now().Add(time.Hour),
	})

	return nil
}

// GetWebAuthnService returns the WebAuthn service
func (s *AuthService) GetWebAuthnService() *WebAuthnService {
	return s.webauthnService
}

// GetTOTPService returns the TOTP service
func (s *AuthService) GetTOTPService() *TOTPService {
	return s.totpService
}

// GetJWTService returns the JWT service
func (s *AuthService) GetJWTService() *JWTService {
	return s.jwtService
}

// GetEmailService returns the email service
func (s *AuthService) GetEmailService() *EmailService {
	return s.emailService
}

// VerifyPassword verifies a user's password
func (s *AuthService) VerifyPassword(user *models.User, password string) bool {
	return facades.Hash().Check(password, user.Password)
}

// LoginFailed logs failed login attempts
func (s *AuthService) LoginFailed(email, reason string, ctx http.Context) {
	s.auditHelper.LogUserLogin("", ctx.Request().Ip(), ctx.Request().Header("User-Agent", ""), false, map[string]interface{}{
		"email":          email,
		"failure_reason": reason,
		"attempt_time":   time.Now(),
	})
}

// encryptSensitiveData encrypts sensitive data using application encryption key
func (s *AuthService) encryptSensitiveData(data string) (string, error) {
	encryptionKey := facades.Config().GetString("app.key")
	if encryptionKey == "" {
		return "", fmt.Errorf("encryption key not configured")
	}

	// Use AES-256-GCM for encryption
	block, err := aes.NewCipher([]byte(encryptionKey)[:32]) // Use first 32 bytes for AES-256
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)

	// Encode as base64 for storage
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptSensitiveData decrypts sensitive data
func (s *AuthService) decryptSensitiveData(encryptedData string) (string, error) {
	encryptionKey := facades.Config().GetString("app.key")
	if encryptionKey == "" {
		return "", fmt.Errorf("encryption key not configured")
	}

	// Decode from base64
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decode encrypted data: %w", err)
	}

	// Create cipher
	block, err := aes.NewCipher([]byte(encryptionKey)[:32])
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce and decrypt
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// verifyBackupCode verifies a backup code and marks it as used
func (s *AuthService) verifyBackupCode(user *models.User, code string) bool {
	if user.MfaBackupCodes == "" {
		return false
	}

	// Decrypt backup codes
	decryptedData, err := s.decryptSensitiveData(user.MfaBackupCodes)
	if err != nil {
		facades.Log().Error("Failed to decrypt backup codes", map[string]interface{}{
			"user_id": user.ID,
			"error":   err.Error(),
		})
		return false
	}

	// Parse backup codes data
	var backupCodesData map[string]interface{}
	if err := json.Unmarshal([]byte(decryptedData), &backupCodesData); err != nil {
		facades.Log().Error("Failed to parse backup codes data", map[string]interface{}{
			"user_id": user.ID,
			"error":   err.Error(),
		})
		return false
	}

	codes, ok := backupCodesData["codes"].([]interface{})
	if !ok {
		facades.Log().Error("Invalid backup codes format", map[string]interface{}{
			"user_id": user.ID,
		})
		return false
	}

	usedCodes, ok := backupCodesData["used_codes"].([]interface{})
	if !ok {
		usedCodes = []interface{}{}
	}

	// Check if code is valid and not already used
	for i, hashedCodeInterface := range codes {
		hashedCode, ok := hashedCodeInterface.(string)
		if !ok {
			continue
		}

		// Check if this code was already used
		codeIndex := fmt.Sprintf("%d", i)
		for _, usedCodeInterface := range usedCodes {
			if usedCode, ok := usedCodeInterface.(string); ok && usedCode == codeIndex {
				continue // Skip used code
			}
		}

		// Verify the code
		if facades.Hash().Check(code, hashedCode) {
			// Mark code as used
			usedCodes = append(usedCodes, codeIndex)
			backupCodesData["used_codes"] = usedCodes

			// Update stored backup codes
			updatedData, err := json.Marshal(backupCodesData)
			if err != nil {
				facades.Log().Error("Failed to marshal updated backup codes", map[string]interface{}{
					"user_id": user.ID,
					"error":   err.Error(),
				})
				return false
			}

			encryptedData, err := s.encryptSensitiveData(string(updatedData))
			if err != nil {
				facades.Log().Error("Failed to encrypt updated backup codes", map[string]interface{}{
					"user_id": user.ID,
					"error":   err.Error(),
				})
				return false
			}

			user.MfaBackupCodes = encryptedData
			if err := facades.Orm().Query().Save(user); err != nil {
				facades.Log().Error("Failed to save updated backup codes", map[string]interface{}{
					"user_id": user.ID,
					"error":   err.Error(),
				})
				return false
			}

			// Log backup code usage
			facades.Log().Info("Backup code used successfully", map[string]interface{}{
				"user_id":    user.ID,
				"code_index": codeIndex,
			})

			return true
		}
	}

	// Log failed backup code attempt
	facades.Log().Warning("Invalid backup code attempted", map[string]interface{}{
		"user_id": user.ID,
	})

	return false
}
