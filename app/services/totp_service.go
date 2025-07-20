package services

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"time"

	"github.com/goravel/framework/facades"
)

type TOTPService struct{}

func NewTOTPService() *TOTPService {
	return &TOTPService{}
}

// GenerateSecret generates a new TOTP secret
func (s *TOTPService) GenerateSecret() string {
	// Generate a random 32-byte secret and encode as base32
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(time.Now().UnixNano() % 256)
	}
	return base32.StdEncoding.EncodeToString(secret)
}

// ValidateCode validates a TOTP code against a secret
func (s *TOTPService) ValidateCode(secret, code string) bool {
	// Decode the secret
	secretBytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		facades.Log().Error("Invalid TOTP secret", map[string]interface{}{
			"error": err.Error(),
		})
		return false
	}

	// Get current timestamp
	now := time.Now().Unix()

	// Check current window and previous/next windows for clock skew tolerance
	for i := -1; i <= 1; i++ {
		if s.generateTOTP(secretBytes, now+int64(i*30)) == code {
			return true
		}
	}

	return false
}

// GenerateCode generates a TOTP code for the current time
func (s *TOTPService) GenerateCode(secret string) (string, error) {
	secretBytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("invalid secret: %v", err)
	}

	code := s.generateTOTP(secretBytes, time.Now().Unix())
	return code, nil
}

// generateTOTP generates a TOTP code for a given timestamp
func (s *TOTPService) generateTOTP(secret []byte, timestamp int64) string {
	// Convert timestamp to 8-byte big-endian
	timeBytes := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		timeBytes[i] = byte(timestamp & 0xff)
		timestamp >>= 8
	}

	// Generate HMAC-SHA1
	h := hmac.New(sha1.New, secret)
	h.Write(timeBytes)
	hash := h.Sum(nil)

	// Generate 4-byte code
	offset := hash[len(hash)-1] & 0xf
	code := ((int(hash[offset]) & 0x7f) << 24) |
		((int(hash[offset+1]) & 0xff) << 16) |
		((int(hash[offset+2]) & 0xff) << 8) |
		(int(hash[offset+3]) & 0xff)

	// Convert to 6-digit string
	code = code % 1000000
	return fmt.Sprintf("%06d", code)
}

// GenerateQRCodeURL generates a QR code URL for TOTP setup
func (s *TOTPService) GenerateQRCodeURL(secret, email, issuer string) string {
	// Format: otpauth://totp/{issuer}:{email}?secret={secret}&issuer={issuer}
	return fmt.Sprintf("otpauth://totp/%s:%s?secret=%s&issuer=%s", issuer, email, secret, issuer)
}

// GetRemainingTime returns the remaining seconds until the next TOTP code
func (s *TOTPService) GetRemainingTime() int {
	now := time.Now().Unix()
	return 30 - int(now%30)
}

// ValidateSecret validates if a secret is properly formatted
func (s *TOTPService) ValidateSecret(secret string) bool {
	_, err := base32.StdEncoding.DecodeString(secret)
	return err == nil
}
