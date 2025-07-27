package services

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	}, nil
}

// MustNewAuthService creates a new authentication service and panics on error (for backward compatibility)
// Deprecated: Use NewAuthService() instead for proper error handling
func MustNewAuthService() *AuthService {
	service, err := NewAuthService()
	if err != nil {
		facades.Log().Error("Critical AuthService initialization failure", map[string]interface{}{
			"error": err.Error(),
		})
		panic(fmt.Sprintf("AuthService initialization failed: %v", err))
	}
	return service
}

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

	// Store backup codes (simplified - TODO: In production you'd store them securely)
	backupCodesJSON, _ := json.Marshal(backupCodes)
	user.MfaBackupCodes = string(backupCodesJSON)

	// Save user
	if err := facades.Orm().Query().Save(user); err != nil {
		return nil, err
	}

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
	// This is a simplified implementation
	// In a real implementation, you would verify the WebAuthn assertion
	return true
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
	// This is a simplified implementation
	// In a real implementation, you would send an actual email
	facades.Log().Info(fmt.Sprintf("Password reset email sent to %s with token: %s", user.Email, token))
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
