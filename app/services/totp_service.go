package services

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"goravel/app/models"

	"github.com/goravel/framework/facades"
)

type TOTPService struct{}

func NewTOTPService() *TOTPService {
	return &TOTPService{}
}

// BackupCode represents a TOTP backup code
type BackupCode struct {
	Code      string     `json:"code"`
	Used      bool       `json:"used"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// TOTPConfig represents TOTP configuration
type TOTPConfig struct {
	Issuer      string
	AccountName string
	Secret      string
	Algorithm   string
	Digits      int
	Period      int
}

// GenerateSecret generates a cryptographically secure TOTP secret
func (s *TOTPService) GenerateSecret() string {
	// Generate a random 32-byte secret for better security
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		facades.Log().Error("Failed to generate TOTP secret", map[string]interface{}{
			"error": err.Error(),
		})
		return ""
	}

	// Encode as base32 without padding for compatibility
	encoded := base32.StdEncoding.EncodeToString(secret)
	return strings.TrimRight(encoded, "=")
}

// GenerateBackupCodes generates secure backup codes for TOTP
func (s *TOTPService) GenerateBackupCodes(count int) []BackupCode {
	if count <= 0 {
		count = 10 // Default to 10 backup codes
	}

	codes := make([]BackupCode, count)
	now := time.Now()

	for i := 0; i < count; i++ {
		codes[i] = BackupCode{
			Code:      s.generateBackupCode(),
			Used:      false,
			CreatedAt: now,
		}
	}

	return codes
}

// generateBackupCode generates a single backup code
func (s *TOTPService) generateBackupCode() string {
	// Generate 8 random bytes and format as hex
	randomBytes := make([]byte, 4)
	if _, err := rand.Read(randomBytes); err != nil {
		facades.Log().Error("Failed to generate backup code", map[string]interface{}{
			"error": err.Error(),
		})
		// Fallback
		binary.BigEndian.PutUint32(randomBytes, uint32(time.Now().UnixNano()))
	}

	// Format as 8-digit code with dashes for readability
	code := fmt.Sprintf("%08d", binary.BigEndian.Uint32(randomBytes))
	return fmt.Sprintf("%s-%s", code[:4], code[4:])
}

// ValidateCode validates a TOTP code against a secret with rate limiting
func (s *TOTPService) ValidateCode(secret, code string) bool {
	return s.ValidateCodeWithWindow(secret, code, 1)
}

// ValidateCodeWithWindow validates a TOTP code with a specified time window
func (s *TOTPService) ValidateCodeWithWindow(secret, code string, window int) bool {
	// Input validation
	if secret == "" || code == "" {
		facades.Log().Warning("TOTP validation failed: empty secret or code")
		return false
	}

	// Rate limiting for TOTP validation attempts
	rateLimitKey := fmt.Sprintf("totp_validation:%s", s.hashSecret(secret))
	if !s.checkRateLimit(rateLimitKey, 10, 5*time.Minute) {
		facades.Log().Warning("TOTP validation rate limit exceeded", map[string]interface{}{
			"secret_hash": s.hashSecret(secret),
		})
		return false
	}

	// Clean and validate code format
	cleanCode := strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(cleanCode) != 6 {
		facades.Log().Warning("TOTP validation failed: invalid code format", map[string]interface{}{
			"code_length": len(cleanCode),
		})
		return false
	}

	// Decode secret
	decodedSecret, err := s.decodeSecret(secret)
	if err != nil {
		facades.Log().Error("TOTP validation failed: invalid secret", map[string]interface{}{
			"error": err.Error(),
		})
		return false
	}

	// Get current time
	now := time.Now().Unix()
	timeStep := now / 30 // 30-second time step

	// Check current time window and adjacent windows
	for i := -window; i <= window; i++ {
		testTimeStep := timeStep + int64(i)
		expectedCode := s.generateTOTPCode(decodedSecret, testTimeStep)

		if cleanCode == expectedCode {
			// Prevent replay attacks by storing used codes
			if s.isCodeRecentlyUsed(secret, cleanCode, testTimeStep) {
				facades.Log().Warning("TOTP validation failed: code recently used (replay attack)", map[string]interface{}{
					"secret_hash": s.hashSecret(secret),
					"time_step":   testTimeStep,
				})
				return false
			}

			// Mark code as used
			s.markCodeAsUsed(secret, cleanCode, testTimeStep)

			facades.Log().Info("TOTP validation successful", map[string]interface{}{
				"secret_hash": s.hashSecret(secret),
				"time_step":   testTimeStep,
				"window":      i,
			})
			return true
		}
	}

	facades.Log().Warning("TOTP validation failed: invalid code", map[string]interface{}{
		"secret_hash": s.hashSecret(secret),
		"time_step":   timeStep,
	})
	return false
}

// ValidateBackupCode validates a backup code
func (s *TOTPService) ValidateBackupCode(userID, code string) bool {
	// Input validation
	if userID == "" || code == "" {
		return false
	}

	// Rate limiting for backup code validation
	rateLimitKey := fmt.Sprintf("backup_code_validation:%s", userID)
	if !s.checkRateLimit(rateLimitKey, 5, 5*time.Minute) {
		facades.Log().Warning("Backup code validation rate limit exceeded", map[string]interface{}{
			"user_id": userID,
		})
		return false
	}

	// Get user's backup codes
	backupCodes, err := s.getUserBackupCodes(userID)
	if err != nil {
		facades.Log().Error("Failed to get backup codes", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return false
	}

	// Clean the input code
	cleanCode := strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	cleanCode = strings.ReplaceAll(cleanCode, "-", "")

	// Check each backup code
	for i, backupCode := range backupCodes {
		if backupCode.Used {
			continue
		}

		cleanBackupCode := strings.ReplaceAll(backupCode.Code, "-", "")
		if cleanCode == cleanBackupCode {
			// Mark as used
			now := time.Now()
			backupCodes[i].Used = true
			backupCodes[i].UsedAt = &now

			// Save updated backup codes
			if err := s.saveUserBackupCodes(userID, backupCodes); err != nil {
				facades.Log().Error("Failed to save backup codes", map[string]interface{}{
					"user_id": userID,
					"error":   err.Error(),
				})
				return false
			}

			facades.Log().Info("Backup code validation successful", map[string]interface{}{
				"user_id": userID,
			})
			return true
		}
	}

	facades.Log().Warning("Backup code validation failed", map[string]interface{}{
		"user_id": userID,
	})
	return false
}

// GenerateQRCodeURL generates a QR code URL for TOTP setup
func (s *TOTPService) GenerateQRCodeURL(config TOTPConfig) string {
	if config.Algorithm == "" {
		config.Algorithm = "SHA256"
	}
	if config.Digits == 0 {
		config.Digits = 6
	}
	if config.Period == 0 {
		config.Period = 30
	}

	// Construct the otpauth URL
	url := fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=%d&period=%d",
		config.Issuer,
		config.AccountName,
		config.Secret,
		config.Issuer,
		config.Algorithm,
		config.Digits,
		config.Period,
	)

	return url
}

// generateTOTPCode generates a TOTP code for a given time step
func (s *TOTPService) generateTOTPCode(secret []byte, timeStep int64) string {
	// Convert time step to byte array
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(timeStep))

	// Generate HMAC-SHA256
	mac := hmac.New(sha256.New, secret)
	mac.Write(timeBytes)
	hash := mac.Sum(nil)

	// Dynamic truncation
	offset := hash[len(hash)-1] & 0x0F
	code := binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7FFFFFFF

	// Generate 6-digit code
	return fmt.Sprintf("%06d", code%1000000)
}

// decodeSecret decodes a base32 secret
func (s *TOTPService) decodeSecret(secret string) ([]byte, error) {
	// Add padding if necessary
	padding := 8 - (len(secret) % 8)
	if padding != 8 {
		secret += strings.Repeat("=", padding)
	}

	return base32.StdEncoding.DecodeString(strings.ToUpper(secret))
}

// hashSecret creates a hash of the secret for logging/caching purposes
func (s *TOTPService) hashSecret(secret string) string {
	hash := sha256.Sum256([]byte(secret))
	return fmt.Sprintf("%x", hash[:8]) // First 8 bytes as hex
}

// checkRateLimit checks if an operation is within rate limits
func (s *TOTPService) checkRateLimit(key string, maxAttempts int, window time.Duration) bool {
	var attempts int
	err := facades.Cache().Get(key, &attempts)
	if err != nil {
		attempts = 0
	}

	if attempts >= maxAttempts {
		return false
	}

	// Increment counter
	attempts++
	facades.Cache().Put(key, attempts, window)
	return true
}

// isCodeRecentlyUsed checks if a TOTP code was recently used (replay attack prevention)
func (s *TOTPService) isCodeRecentlyUsed(secret, code string, timeStep int64) bool {
	key := fmt.Sprintf("totp_used:%s:%s:%d", s.hashSecret(secret), code, timeStep)
	var used bool
	err := facades.Cache().Get(key, &used)
	return err == nil && used
}

// markCodeAsUsed marks a TOTP code as used
func (s *TOTPService) markCodeAsUsed(secret, code string, timeStep int64) {
	key := fmt.Sprintf("totp_used:%s:%s:%d", s.hashSecret(secret), code, timeStep)
	// Store for 2 minutes (4 time windows) to prevent replay
	facades.Cache().Put(key, true, 2*time.Minute)
}

// getUserBackupCodes retrieves backup codes for a user
func (s *TOTPService) getUserBackupCodes(userID string) ([]BackupCode, error) {
	var user models.User
	err := facades.Orm().Query().Where("id", userID).First(&user)
	if err != nil {
		return nil, err
	}

	// For now, store backup codes in user's MFA secret field as JSON
	// In production, you might want a separate table
	if user.MfaBackupCodes == "" {
		return []BackupCode{}, nil
	}

	var codes []BackupCode
	// This would need proper JSON unmarshaling
	// Simplified for this example
	return codes, nil
}

// saveUserBackupCodes saves backup codes for a user
func (s *TOTPService) saveUserBackupCodes(userID string, codes []BackupCode) error {
	var user models.User
	err := facades.Orm().Query().Where("id", userID).First(&user)
	if err != nil {
		return err
	}

	// For now, store backup codes in user's MFA backup codes field as JSON
	// In production, you might want a separate table
	// This would need proper JSON marshaling
	// Simplified for this example

	return facades.Orm().Query().Save(&user)
}

// GetRemainingBackupCodes returns the number of unused backup codes
func (s *TOTPService) GetRemainingBackupCodes(userID string) (int, error) {
	codes, err := s.getUserBackupCodes(userID)
	if err != nil {
		return 0, err
	}

	remaining := 0
	for _, code := range codes {
		if !code.Used {
			remaining++
		}
	}

	return remaining, nil
}

// VerificationResult represents the result of MFA code verification
type VerificationResult struct {
	Valid                bool   `json:"valid"`
	CodeType             string `json:"code_type"` // "totp" or "backup"
	BackupCodesRemaining int    `json:"backup_codes_remaining,omitempty"`
	Message              string `json:"message,omitempty"`
}

// SetupMFAWithBackupCodes sets up MFA and generates backup codes
func (s *TOTPService) SetupMFAWithBackupCodes(user *models.User, verificationCode string) (map[string]interface{}, []BackupCode, error) {
	// Generate secret if not already present
	if user.MfaSecret == "" {
		user.MfaSecret = s.GenerateSecret()
	}

	// Validate the verification code
	if !s.ValidateCode(user.MfaSecret, verificationCode) {
		return nil, nil, fmt.Errorf("invalid verification code")
	}

	// Generate backup codes
	backupCodes := s.GenerateBackupCodes(10)

	// Store backup codes in user model (in production, store securely)
	backupCodesJSON, _ := json.Marshal(backupCodes)
	user.MfaBackupCodes = string(backupCodesJSON)
	user.MfaEnabled = true

	// Save user
	if err := facades.Orm().Query().Save(user); err != nil {
		return nil, nil, fmt.Errorf("failed to save MFA settings: %w", err)
	}

	// Generate QR code
	qrCode := s.GenerateQRCodeURL(TOTPConfig{
		Issuer:      "Goravel App",
		AccountName: user.Email,
		Secret:      user.MfaSecret,
		Algorithm:   "SHA1",
		Digits:      6,
		Period:      30,
	})

	result := map[string]interface{}{
		"secret":  user.MfaSecret,
		"qr_code": qrCode,
		"enabled": true,
	}

	return result, backupCodes, nil
}

// DisableMFACompletely disables MFA and clears all backup codes
func (s *TOTPService) DisableMFACompletely(user *models.User) error {
	user.MfaEnabled = false
	user.MfaSecret = ""
	user.MfaBackupCodes = ""

	if err := facades.Orm().Query().Save(user); err != nil {
		return fmt.Errorf("failed to disable MFA: %w", err)
	}

	return nil
}

// GenerateEnhancedMfaSetup generates enhanced MFA setup data
func (s *TOTPService) GenerateEnhancedMfaSetup(user *models.User) map[string]interface{} {
	secret := s.GenerateSecret()
	qrCode := s.GenerateQRCodeURL(TOTPConfig{
		Issuer:      "Goravel App",
		AccountName: user.Email,
		Secret:      secret,
		Algorithm:   "SHA1",
		Digits:      6,
		Period:      30,
	})

	return map[string]interface{}{
		"secret":      secret,
		"qr_code":     qrCode,
		"issuer":      "Goravel App",
		"account":     user.Email,
		"algorithm":   "SHA1",
		"digits":      6,
		"period":      30,
		"backup_info": "Backup codes will be generated after enabling MFA",
	}
}

// EnhancedVerifyCode verifies MFA code with backup code support
func (s *TOTPService) EnhancedVerifyCode(user *models.User, code string) *VerificationResult {
	// First try TOTP code
	if s.ValidateCode(user.MfaSecret, code) {
		return &VerificationResult{
			Valid:    true,
			CodeType: "totp",
			Message:  "TOTP code verified successfully",
		}
	}

	// Try backup codes
	if user.MfaBackupCodes != "" {
		var backupCodes []BackupCode
		if err := json.Unmarshal([]byte(user.MfaBackupCodes), &backupCodes); err == nil {
			for i, backupCode := range backupCodes {
				if !backupCode.Used && backupCode.Code == code {
					// Mark backup code as used
					backupCodes[i].Used = true
					now := time.Now()
					backupCodes[i].UsedAt = &now

					// Count remaining codes
					remaining := 0
					for _, bc := range backupCodes {
						if !bc.Used {
							remaining++
						}
					}

					// Save updated backup codes
					updatedCodesJSON, _ := json.Marshal(backupCodes)
					user.MfaBackupCodes = string(updatedCodesJSON)
					facades.Orm().Query().Save(user)

					return &VerificationResult{
						Valid:                true,
						CodeType:             "backup",
						BackupCodesRemaining: remaining,
						Message:              "Backup code verified successfully",
					}
				}
			}
		}
	}

	return &VerificationResult{
		Valid:   false,
		Message: "Invalid MFA code",
	}
}

// VerifyCodeOrBackup verifies either TOTP code or backup code
func (s *TOTPService) VerifyCodeOrBackup(user *models.User, code string) bool {
	result := s.EnhancedVerifyCode(user, code)
	return result.Valid
}

// RegenerateBackupCodes generates new backup codes and invalidates old ones
func (s *TOTPService) RegenerateBackupCodes(user *models.User) ([]BackupCode, error) {
	// Generate new backup codes
	newBackupCodes := s.GenerateBackupCodes(10)

	// Store new backup codes
	backupCodesJSON, err := json.Marshal(newBackupCodes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal backup codes: %w", err)
	}

	user.MfaBackupCodes = string(backupCodesJSON)
	if err := facades.Orm().Query().Save(user); err != nil {
		return nil, fmt.Errorf("failed to save new backup codes: %w", err)
	}

	return newBackupCodes, nil
}

// GenerateCode generates a TOTP code for the current time (for testing purposes)
func (s *TOTPService) GenerateCode(secret string) (string, error) {
	decodedSecret, err := s.decodeSecret(secret)
	if err != nil {
		return "", err
	}

	// Get current time step
	timeStep := time.Now().Unix() / 30

	return s.generateTOTPCode(decodedSecret, timeStep), nil
}
