package models

import (
	"encoding/json"

	"github.com/goravel/framework/facades"
)

// OAuthClient represents an OAuth2 client
// @Description OAuth2 client model for application registration and authentication
type OAuthClient struct {
	BaseModel

	// Client unique identifier (ULID)
	// @example 01HXYZ123456789ABCDEFGHIJK
	ID string `json:"id" gorm:"primaryKey;type:char(26)" example:"01HXYZ123456789ABCDEFGHIJK"`

	// User ID who owns this client (optional)
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID *string `json:"user_id" gorm:"type:char(26);index" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Client name
	// @example My OAuth App
	Name string `json:"name" gorm:"type:varchar(255)" example:"My OAuth App"`

	// Client secret (confidential clients only)
	// @example abc123def456ghi789
	Secret *string `json:"secret,omitempty" gorm:"type:varchar(100)" example:"abc123def456ghi789"`

	// OAuth provider type
	// @example custom
	Provider *string `json:"provider" gorm:"type:varchar(255)" example:"custom"`

	// Redirect URIs (JSON array)
	// @example ["https://example.com/callback","https://app.example.com/auth"]
	Redirect string `json:"redirect" gorm:"type:text" example:"[\"https://example.com/callback\",\"https://app.example.com/auth\"]"`

	// Whether this is a personal access client
	// @example false
	PersonalAccessClient bool `json:"personal_access_client" gorm:"default:false" example:"false"`

	// Whether this is a password client
	// @example false
	PasswordClient bool `json:"password_client" gorm:"default:false" example:"false"`

	// Whether the client is revoked
	// @example false
	Revoked bool `json:"revoked" gorm:"default:false" example:"false"`

	// Relationships
	// @Description User who owns this client
	User *User `json:"user,omitempty" gorm:"foreignKey:UserID"`

	// @Description Access tokens issued to this client
	AccessTokens []OAuthAccessToken `json:"access_tokens,omitempty" gorm:"foreignKey:ClientID"`

	// @Description Authorization codes issued to this client
	AuthCodes []OAuthAuthCode `json:"auth_codes,omitempty" gorm:"foreignKey:ClientID"`
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
