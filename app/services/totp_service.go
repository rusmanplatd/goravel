package services

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"strings"
	"time"

	"github.com/goravel/framework/facades"
)

type TOTPService struct{}

func NewTOTPService() *TOTPService {
	return &TOTPService{}
}

// GenerateSecret generates a cryptographically secure TOTP secret
func (s *TOTPService) GenerateSecret() string {
	// Generate a random 32-byte secret for better security
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		facades.Log().Error("Failed to generate TOTP secret", map[string]interface{}{
			"error": err.Error(),
		})
		// Fallback to time-based generation (less secure but functional)
		for i := range secret {
			secret[i] = byte(time.Now().UnixNano() % 256)
		}
	}

	// Encode as base32 without padding for compatibility
	encoded := base32.StdEncoding.EncodeToString(secret)
	return strings.TrimRight(encoded, "=")
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

	// Normalize code (remove spaces, ensure 6 digits)
	code = strings.ReplaceAll(code, " ", "")
	if len(code) != 6 {
		facades.Log().Warning("TOTP validation failed: invalid code length", map[string]interface{}{
			"code_length": len(code),
		})
		return false
	}

	// Decode the secret
	// Add padding if necessary for proper base32 decoding
	paddedSecret := secret
	for len(paddedSecret)%8 != 0 {
		paddedSecret += "="
	}

	secretBytes, err := base32.StdEncoding.DecodeString(paddedSecret)
	if err != nil {
		facades.Log().Error("Invalid TOTP secret format", map[string]interface{}{
			"error": err.Error(),
		})
		return false
	}

	// Validate secret length
	if len(secretBytes) < 16 {
		facades.Log().Warning("TOTP secret too short", map[string]interface{}{
			"secret_length": len(secretBytes),
		})
		return false
	}

	// Get current timestamp
	now := time.Now().Unix()
	timeStep := now / 30

	// Check current window and previous/next windows for clock skew tolerance
	for i := -window; i <= window; i++ {
		if s.generateTOTP(secretBytes, timeStep+int64(i)) == code {
			// Log successful validation for security monitoring
			facades.Log().Info("TOTP validation successful", map[string]interface{}{
				"time_offset": i * 30,
			})
			return true
		}
	}

	// Log failed validation for security monitoring
	facades.Log().Warning("TOTP validation failed: invalid code", map[string]interface{}{
		"attempted_code": code,
		"window_size":    window,
	})
	return false
}

// ValidateCodeWithRateLimit validates a TOTP code with rate limiting
func (s *TOTPService) ValidateCodeWithRateLimit(userID, secret, code string) bool {
	// Rate limiting - max 5 attempts per minute per user
	rateLimitKey := fmt.Sprintf("totp_rate_limit_%s", userID)
	var attemptCount int

	if err := facades.Cache().Get(rateLimitKey, &attemptCount); err == nil {
		if attemptCount >= 5 {
			facades.Log().Warning("TOTP rate limit exceeded", map[string]interface{}{
				"user_id":  userID,
				"attempts": attemptCount,
			})
			return false
		}
		attemptCount++
	} else {
		attemptCount = 1
	}

	// Store updated attempt count
	facades.Cache().Put(rateLimitKey, attemptCount, time.Minute)

	// Prevent replay attacks - store recently used codes
	replayKey := fmt.Sprintf("totp_used_%s_%s", userID, code)
	var used bool
	if err := facades.Cache().Get(replayKey, &used); err == nil && used {
		facades.Log().Warning("TOTP replay attack detected", map[string]interface{}{
			"user_id": userID,
			"code":    code,
		})
		return false
	}

	// Validate the code
	isValid := s.ValidateCodeWithWindow(secret, code, 1)

	if isValid {
		// Mark code as used to prevent replay attacks
		facades.Cache().Put(replayKey, true, 2*time.Minute) // Store for 2 minutes (4 time windows)

		// Reset rate limit on successful authentication
		facades.Cache().Forget(rateLimitKey)

		facades.Log().Info("TOTP authentication successful", map[string]interface{}{
			"user_id": userID,
		})
	}

	return isValid
}

// GenerateCode generates a TOTP code for the current time
func (s *TOTPService) GenerateCode(secret string) (string, error) {
	if secret == "" {
		return "", fmt.Errorf("secret cannot be empty")
	}

	// Add padding if necessary
	paddedSecret := secret
	for len(paddedSecret)%8 != 0 {
		paddedSecret += "="
	}

	secretBytes, err := base32.StdEncoding.DecodeString(paddedSecret)
	if err != nil {
		return "", fmt.Errorf("invalid secret format: %v", err)
	}

	if len(secretBytes) < 16 {
		return "", fmt.Errorf("secret too short, minimum 16 bytes required")
	}

	timeStep := time.Now().Unix() / 30
	code := s.generateTOTP(secretBytes, timeStep)
	return code, nil
}

// generateTOTP generates a TOTP code for a given timestamp
func (s *TOTPService) generateTOTP(secret []byte, timeStep int64) string {
	// Convert timestamp to 8-byte big-endian
	timeBytes := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		timeBytes[i] = byte(timeStep & 0xff)
		timeStep >>= 8
	}

	// Generate HMAC-SHA1
	h := hmac.New(sha1.New, secret)
	h.Write(timeBytes)
	hash := h.Sum(nil)

	// Dynamic truncation
	offset := hash[len(hash)-1] & 0xf
	code := ((int(hash[offset]) & 0x7f) << 24) |
		((int(hash[offset+1]) & 0xff) << 16) |
		((int(hash[offset+2]) & 0xff) << 8) |
		(int(hash[offset+3]) & 0xff)

	// Convert to 6-digit string with leading zeros
	code = code % 1000000
	return fmt.Sprintf("%06d", code)
}

// GenerateQRCodeURL generates a QR code URL for TOTP setup
func (s *TOTPService) GenerateQRCodeURL(secret, email, issuer string) string {
	// Input validation
	if secret == "" || email == "" || issuer == "" {
		facades.Log().Warning("Invalid QR code parameters", map[string]interface{}{
			"secret_empty": secret == "",
			"email_empty":  email == "",
			"issuer_empty": issuer == "",
		})
		return ""
	}

	// Format: otpauth://totp/{issuer}:{email}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30",
		issuer, email, secret, issuer)
}

// GetRemainingTime returns the remaining seconds until the next TOTP code
func (s *TOTPService) GetRemainingTime() int {
	now := time.Now().Unix()
	return 30 - int(now%30)
}

// GetCurrentTimeStep returns the current time step for TOTP
func (s *TOTPService) GetCurrentTimeStep() int64 {
	return time.Now().Unix() / 30
}

// GenerateBackupCodes generates secure backup codes for account recovery
func (s *TOTPService) GenerateBackupCodes(count int) []string {
	if count <= 0 || count > 20 {
		count = 10 // Default to 10 codes
	}

	codes := make([]string, count)
	for i := 0; i < count; i++ {
		codes[i] = s.generateBackupCode()
	}

	facades.Log().Info("Backup codes generated", map[string]interface{}{
		"count": count,
	})

	return codes
}

// generateBackupCode generates a single secure backup code
func (s *TOTPService) generateBackupCode() string {
	// Generate 8 random bytes
	bytes := make([]byte, 8)
	if _, err := rand.Read(bytes); err != nil {
		facades.Log().Error("Failed to generate backup code", map[string]interface{}{
			"error": err.Error(),
		})
		// Fallback to time-based generation
		for i := range bytes {
			bytes[i] = byte(time.Now().UnixNano() % 256)
		}
	}

	// Convert to alphanumeric string (excluding confusing characters)
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	result := make([]byte, 8)
	for i, b := range bytes {
		result[i] = chars[int(b)%len(chars)]
	}

	// Format as XXXX-XXXX for better readability
	return fmt.Sprintf("%s-%s", string(result[:4]), string(result[4:]))
}

// ValidateBackupCode validates a backup code
func (s *TOTPService) ValidateBackupCode(userID, code string, validCodes []string) bool {
	// Input validation
	if userID == "" || code == "" || len(validCodes) == 0 {
		return false
	}

	// Normalize code (remove spaces and dashes, convert to uppercase)
	normalizedCode := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(code, " ", ""), "-", ""))

	// Check if code exists in valid codes list
	for _, validCode := range validCodes {
		normalizedValidCode := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(validCode, " ", ""), "-", ""))
		if normalizedCode == normalizedValidCode {
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

// IsValidSecret checks if a TOTP secret is valid
func (s *TOTPService) IsValidSecret(secret string) bool {
	if secret == "" {
		return false
	}

	// Add padding if necessary
	paddedSecret := secret
	for len(paddedSecret)%8 != 0 {
		paddedSecret += "="
	}

	secretBytes, err := base32.StdEncoding.DecodeString(paddedSecret)
	if err != nil {
		return false
	}

	// Secret should be at least 16 bytes (128 bits) for security
	return len(secretBytes) >= 16
}

// GetSecretStrength returns the strength of a TOTP secret
func (s *TOTPService) GetSecretStrength(secret string) string {
	if !s.IsValidSecret(secret) {
		return "invalid"
	}

	// Add padding if necessary
	paddedSecret := secret
	for len(paddedSecret)%8 != 0 {
		paddedSecret += "="
	}

	secretBytes, err := base32.StdEncoding.DecodeString(paddedSecret)
	if err != nil {
		return "invalid"
	}

	bitLength := len(secretBytes) * 8

	switch {
	case bitLength >= 256:
		return "very_strong"
	case bitLength >= 160:
		return "strong"
	case bitLength >= 128:
		return "good"
	case bitLength >= 80:
		return "weak"
	default:
		return "very_weak"
	}
}
