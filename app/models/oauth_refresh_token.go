package models

import (
	"time"

	"github.com/goravel/framework/facades"
)

// OAuthRefreshToken represents an OAuth2 refresh token
type OAuthRefreshToken struct {
	ID            string    `json:"id" gorm:"primaryKey;type:varchar(100)"`
	AccessTokenID string    `json:"access_token_id" gorm:"type:varchar(100);index"`
	Revoked       bool      `json:"revoked" gorm:"default:false"`
	ExpiresAt     time.Time `json:"expires_at"`

	// Relationships
	AccessToken *OAuthAccessToken `json:"access_token,omitempty" gorm:"foreignKey:AccessTokenID"`
}

// TableName specifies the table name for OAuthRefreshToken
func (OAuthRefreshToken) TableName() string {
	return "oauth_refresh_tokens"
}

// IsExpired returns true if the refresh token is expired
func (t *OAuthRefreshToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}

// IsRevoked returns true if the refresh token is revoked
func (t *OAuthRefreshToken) IsRevoked() bool {
	return t.Revoked
}

// Revoke marks the refresh token as revoked
func (t *OAuthRefreshToken) Revoke() error {
	t.Revoked = true
	return facades.Orm().Query().Save(t)
}

// GetAccessToken returns the access token associated with this refresh token
func (t *OAuthRefreshToken) GetAccessToken() *OAuthAccessToken {
	var accessToken OAuthAccessToken
	if err := facades.Orm().Query().Where("id", t.AccessTokenID).First(&accessToken); err != nil {
		return nil
	}
	return &accessToken
}

// GetUser returns the user associated with this refresh token
func (t *OAuthRefreshToken) GetUser() *User {
	accessToken := t.GetAccessToken()
	if accessToken == nil {
		return nil
	}
	return accessToken.GetUser()
}

// GetClient returns the client associated with this refresh token
func (t *OAuthRefreshToken) GetClient() *OAuthClient {
	accessToken := t.GetAccessToken()
	if accessToken == nil {
		return nil
	}
	return accessToken.GetClient()
}
