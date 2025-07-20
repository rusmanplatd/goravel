package models

import (
	"encoding/json"
	"time"

	"github.com/goravel/framework/facades"
)

// OAuthClient represents an OAuth2 client
type OAuthClient struct {
	ID                   string    `json:"id" gorm:"primaryKey;type:varchar(26)"`
	UserID               *string   `json:"user_id" gorm:"type:varchar(26);index"`
	Name                 string    `json:"name" gorm:"type:varchar(255)"`
	Secret               *string   `json:"secret" gorm:"type:varchar(100)"`
	Provider             *string   `json:"provider" gorm:"type:varchar(255)"`
	Redirect             string    `json:"redirect" gorm:"type:text"`
	PersonalAccessClient bool      `json:"personal_access_client" gorm:"default:false"`
	PasswordClient       bool      `json:"password_client" gorm:"default:false"`
	Revoked              bool      `json:"revoked" gorm:"default:false"`
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`

	// Relationships
	User         *User              `json:"user,omitempty" gorm:"foreignKey:UserID"`
	AccessTokens []OAuthAccessToken `json:"access_tokens,omitempty" gorm:"foreignKey:ClientID"`
	AuthCodes    []OAuthAuthCode    `json:"auth_codes,omitempty" gorm:"foreignKey:ClientID"`
}

// TableName specifies the table name for OAuthClient
func (OAuthClient) TableName() string {
	return "oauth_clients"
}

// GetRedirectURIs returns the redirect URIs as a slice
func (c *OAuthClient) GetRedirectURIs() []string {
	var uris []string
	if c.Redirect != "" {
		json.Unmarshal([]byte(c.Redirect), &uris)
	}
	return uris
}

// SetRedirectURIs sets the redirect URIs from a slice
func (c *OAuthClient) SetRedirectURIs(uris []string) {
	if data, err := json.Marshal(uris); err == nil {
		c.Redirect = string(data)
	}
}

// IsConfidential returns true if the client is confidential (has a secret)
func (c *OAuthClient) IsConfidential() bool {
	return c.Secret != nil && *c.Secret != ""
}

// IsPublic returns true if the client is public (no secret)
func (c *OAuthClient) IsPublic() bool {
	return !c.IsConfidential()
}

// IsPersonalAccessClient returns true if this is a personal access client
func (c *OAuthClient) IsPersonalAccessClient() bool {
	return c.PersonalAccessClient
}

// IsPasswordClient returns true if this is a password client
func (c *OAuthClient) IsPasswordClient() bool {
	return c.PasswordClient
}

// IsRevoked returns true if the client is revoked
func (c *OAuthClient) IsRevoked() bool {
	return c.Revoked
}

// Revoke marks the client as revoked
func (c *OAuthClient) Revoke() error {
	c.Revoked = true
	return facades.Orm().Query().Save(c)
}

// Unrevoke marks the client as not revoked
func (c *OAuthClient) Unrevoke() error {
	c.Revoked = false
	return facades.Orm().Query().Save(c)
}

// GetUser returns the user associated with this client
func (c *OAuthClient) GetUser() *User {
	if c.UserID == nil {
		return nil
	}

	var user User
	if err := facades.Orm().Query().Where("id", *c.UserID).First(&user); err != nil {
		return nil
	}
	return &user
}
