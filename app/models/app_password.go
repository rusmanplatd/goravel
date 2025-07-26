package models

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// AppPassword represents an app-specific password for legacy applications
// DEPRECATED: This model is deprecated and should be replaced with OAuth2 personal access tokens
// for better security and standards compliance. Consider using OAuth2 Client Credentials flow
// or Personal Access Tokens instead.
type AppPassword struct {
	ID         string     `json:"id" gorm:"primaryKey;type:char(26)"`
	UserID     string     `json:"user_id" gorm:"type:char(26);index;not null"`
	Name       string     `json:"name" gorm:"type:varchar(255);not null"`
	Password   string     `json:"-" gorm:"type:varchar(255);not null"` // Hidden from JSON
	LastUsedAt *time.Time `json:"last_used_at"`
	Revoked    bool       `json:"revoked" gorm:"default:false"`
	ExpiresAt  *time.Time `json:"expires_at"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`

	// Relationships
	User *User `json:"user,omitempty" gorm:"foreignKey:UserID"`
}

// TableName specifies the table name for AppPassword
func (AppPassword) TableName() string {
	return "app_passwords"
}

// GeneratePassword creates a new app password with the format: xxxx-xxxx-xxxx-xxxx
// DEPRECATED: Use OAuth2 Personal Access Tokens instead
func (a *AppPassword) GeneratePassword() (string, error) {
	// Generate 16 random bytes
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}

	// Convert to hex and format as xxxx-xxxx-xxxx-xxxx
	hex := hex.EncodeToString(bytes)
	password := hex[0:4] + "-" + hex[4:8] + "-" + hex[8:12] + "-" + hex[12:16]

	a.Password = password
	return password, nil
}

// IsActive returns true if the app password is active (not revoked and not expired)
func (a *AppPassword) IsActive() bool {
	if a.Revoked {
		return false
	}

	// Check if password has expired
	if a.ExpiresAt != nil && time.Now().After(*a.ExpiresAt) {
		return false
	}

	return true
}

// IsExpired returns true if the app password has expired
func (a *AppPassword) IsExpired() bool {
	return a.ExpiresAt != nil && time.Now().After(*a.ExpiresAt)
}

// Revoke marks the app password as revoked
func (a *AppPassword) Revoke() {
	a.Revoked = true
	a.UpdatedAt = time.Now()
}

// UpdateLastUsed updates the last used timestamp
func (a *AppPassword) UpdateLastUsed() {
	now := time.Now()
	a.LastUsedAt = &now
	a.UpdatedAt = now
}

// GetMaskedPassword returns a masked version of the password for display
func (a *AppPassword) GetMaskedPassword() string {
	if len(a.Password) < 19 { // xxxx-xxxx-xxxx-xxxx format
		return "****-****-****-****"
	}

	// Show first 4 characters and mask the rest
	return a.Password[0:4] + "-****-****-****"
}
