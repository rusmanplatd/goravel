package models

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/goravel/framework/facades"
)

// OAuthUserIdentity represents a user's identity from an OAuth provider
// @Description OAuth User Identity model for linking users with their IdP accounts
type OAuthUserIdentity struct {
	BaseModel

	// Reference to users table
	// @example 01HXZ1234567890ABCDEFGHIJK
	UserID string `gorm:"not null;index" json:"user_id" example:"01HXZ1234567890ABCDEFGHIJK"`

	// Reference to oauth_identity_providers table
	// @example 1
	ProviderID uint `gorm:"not null;index" json:"provider_id" example:"1"`

	// User ID from the OAuth provider
	// @example 123456789012345678901
	ProviderUserID string `gorm:"not null;index" json:"provider_user_id" example:"123456789012345678901"`

	// Username from the OAuth provider
	// @example johndoe
	ProviderUsername *string `json:"provider_username,omitempty" example:"johndoe"`

	// Email from the OAuth provider
	// @example john.doe@example.com
	ProviderEmail string `gorm:"not null;index" json:"provider_email" example:"john.doe@example.com"`

	// Display name from the OAuth provider
	// @example John Doe
	ProviderName string `gorm:"not null" json:"provider_name" example:"John Doe"`

	// Avatar URL from the OAuth provider
	// @example https://lh3.googleusercontent.com/a/default-user
	ProviderAvatar *string `json:"provider_avatar,omitempty" example:"https://lh3.googleusercontent.com/a/default-user"`

	// Additional provider data as JSON
	// @example {"locale": "en", "verified_email": true}
	ProviderData *string `gorm:"type:text" json:"provider_data,omitempty" example:"{\"locale\": \"en\", \"verified_email\": true}"`

	// OAuth access token (encrypted in production)
	// @example eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
	AccessToken *string `gorm:"type:text" json:"access_token,omitempty" example:"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."`

	// OAuth refresh token (encrypted in production)
	// @example 1//04567890abcdef
	RefreshToken *string `gorm:"type:text" json:"refresh_token,omitempty" example:"1//04567890abcdef"`

	// Access token expiration
	// @example 2024-01-15T11:30:00Z
	TokenExpiresAt *time.Time `json:"token_expires_at,omitempty" example:"2024-01-15T11:30:00Z"`

	// Last login using this provider
	// @example 2024-01-15T10:30:00Z
	LastLoginAt *time.Time `gorm:"index" json:"last_login_at,omitempty" example:"2024-01-15T10:30:00Z"`

	// Relationships
	User     User                  `gorm:"foreignKey:UserID" json:"user,omitempty"`
	Provider OAuthIdentityProvider `gorm:"foreignKey:ProviderID" json:"provider,omitempty"`
}

// TableName returns the table name for the model
func (OAuthUserIdentity) TableName() string {
	return "oauth_user_identities"
}

// GetProviderData returns the provider data as a map
func (u *OAuthUserIdentity) GetProviderData() (map[string]interface{}, error) {
	var data map[string]interface{}
	if u.ProviderData == nil || *u.ProviderData == "" {
		return data, nil
	}
	err := json.Unmarshal([]byte(*u.ProviderData), &data)
	return data, err
}

// SetProviderData sets the provider data from a map
func (u *OAuthUserIdentity) SetProviderData(data map[string]interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	jsonStr := string(jsonData)
	u.ProviderData = &jsonStr
	return nil
}

// SetAccessToken encrypts and stores the access token
func (i *OAuthUserIdentity) SetAccessToken(token string) error {
	if token == "" {
		i.AccessToken = nil
		return nil
	}

	encrypted, err := facades.Crypt().EncryptString(token)
	if err != nil {
		return fmt.Errorf("failed to encrypt access token: %w", err)
	}

	i.AccessToken = &encrypted
	return nil
}

// GetAccessToken decrypts and returns the access token
func (i *OAuthUserIdentity) GetAccessToken() (string, error) {
	if i.AccessToken == nil || *i.AccessToken == "" {
		return "", nil
	}

	decrypted, err := facades.Crypt().DecryptString(*i.AccessToken)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt access token: %w", err)
	}

	return decrypted, nil
}

// SetRefreshToken encrypts and stores the refresh token
func (i *OAuthUserIdentity) SetRefreshToken(token string) error {
	if token == "" {
		i.RefreshToken = nil
		return nil
	}

	encrypted, err := facades.Crypt().EncryptString(token)
	if err != nil {
		return fmt.Errorf("failed to encrypt refresh token: %w", err)
	}

	i.RefreshToken = &encrypted
	return nil
}

// GetRefreshToken decrypts and returns the refresh token
func (i *OAuthUserIdentity) GetRefreshToken() (string, error) {
	if i.RefreshToken == nil || *i.RefreshToken == "" {
		return "", nil
	}

	decrypted, err := facades.Crypt().DecryptString(*i.RefreshToken)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt refresh token: %w", err)
	}

	return decrypted, nil
}

// IsTokenExpired checks if the access token has expired
func (i *OAuthUserIdentity) IsTokenExpired() bool {
	if i.TokenExpiresAt == nil {
		return false // Assume non-expiring if no expiration set
	}

	return time.Now().After(*i.TokenExpiresAt)
}

// NeedsTokenRefresh checks if the token needs to be refreshed (expires within 5 minutes)
func (i *OAuthUserIdentity) NeedsTokenRefresh() bool {
	if i.TokenExpiresAt == nil {
		return false
	}

	// Refresh if expires within 5 minutes
	return time.Now().Add(5 * time.Minute).After(*i.TokenExpiresAt)
}

// ClearTokens securely clears both access and refresh tokens
func (i *OAuthUserIdentity) ClearTokens() {
	i.AccessToken = nil
	i.RefreshToken = nil
	i.TokenExpiresAt = nil
}

// UpdateLastLogin updates the last login timestamp
func (u *OAuthUserIdentity) UpdateLastLogin() {
	now := time.Now()
	u.LastLoginAt = &now
}
