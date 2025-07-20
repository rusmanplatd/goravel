package models

import (
	"encoding/json"
	"time"

	"github.com/goravel/framework/facades"
)

// OAuthDeviceCode represents an OAuth2 device authorization code
type OAuthDeviceCode struct {
	ID         string    `json:"id" gorm:"primaryKey;type:varchar(100)"`
	UserID     *string   `json:"user_id" gorm:"type:varchar(26);index"`
	ClientID   string    `json:"client_id" gorm:"type:varchar(26);index"`
	Scopes     *string   `json:"scopes" gorm:"type:text"`
	UserCode   string    `json:"user_code" gorm:"type:varchar(10);uniqueIndex"`
	Revoked    bool      `json:"revoked" gorm:"default:false"`
	Authorized bool      `json:"authorized" gorm:"default:false"`
	ExpiresAt  time.Time `json:"expires_at"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`

	// Relationships
	User   *User        `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Client *OAuthClient `json:"client,omitempty" gorm:"foreignKey:ClientID"`
}

// TableName specifies the table name for OAuthDeviceCode
func (OAuthDeviceCode) TableName() string {
	return "oauth_device_codes"
}

// GetScopes returns the scopes as a slice
func (c *OAuthDeviceCode) GetScopes() []string {
	var scopes []string
	if c.Scopes != nil && *c.Scopes != "" {
		json.Unmarshal([]byte(*c.Scopes), &scopes)
	}
	return scopes
}

// SetScopes sets the scopes from a slice
func (c *OAuthDeviceCode) SetScopes(scopes []string) {
	if data, err := json.Marshal(scopes); err == nil {
		scopesStr := string(data)
		c.Scopes = &scopesStr
	}
}

// IsRevoked returns true if the code is revoked
func (c *OAuthDeviceCode) IsRevoked() bool {
	return c.Revoked
}

// IsExpired returns true if the code is expired
func (c *OAuthDeviceCode) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// IsAuthorized returns true if the device authorization is complete
func (c *OAuthDeviceCode) IsAuthorized() bool {
	return c.Authorized && c.UserID != nil
}

// Revoke marks the code as revoked
func (c *OAuthDeviceCode) Revoke() error {
	c.Revoked = true
	return facades.Orm().Query().Save(c)
}

// GetUser returns the user associated with this code
func (c *OAuthDeviceCode) GetUser() *User {
	if c.UserID == nil {
		return nil
	}

	var user User
	if err := facades.Orm().Query().Where("id", *c.UserID).First(&user); err != nil {
		return nil
	}
	return &user
}

// GetClient returns the client associated with this code
func (c *OAuthDeviceCode) GetClient() *OAuthClient {
	var client OAuthClient
	if err := facades.Orm().Query().Where("id", c.ClientID).First(&client); err != nil {
		return nil
	}
	return &client
}
