package models

import (
	"encoding/json"
	"time"
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

	// OAuth access token (should be encrypted in production)
	// @example eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
	AccessToken *string `gorm:"type:text" json:"access_token,omitempty" example:"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."`

	// OAuth refresh token (should be encrypted in production)
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

// IsTokenExpired checks if the access token is expired
func (u *OAuthUserIdentity) IsTokenExpired() bool {
	if u.TokenExpiresAt == nil {
		return false
	}
	return time.Now().After(*u.TokenExpiresAt)
}

// UpdateLastLogin updates the last login timestamp
func (u *OAuthUserIdentity) UpdateLastLogin() {
	now := time.Now()
	u.LastLoginAt = &now
}
