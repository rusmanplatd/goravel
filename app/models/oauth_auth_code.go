package models

import (
	"encoding/json"
	"time"

	"github.com/goravel/framework/facades"
)

// OAuthAuthCode represents an OAuth2 authorization code
type OAuthAuthCode struct {
	ID                  string    `json:"id" gorm:"primaryKey;type:varchar(100)"`
	UserID              string    `json:"user_id" gorm:"type:varchar(26);index"`
	ClientID            string    `json:"client_id" gorm:"type:varchar(26);index"`
	Scopes              *string   `json:"scopes" gorm:"type:text"`
	Revoked             bool      `json:"revoked" gorm:"default:false"`
	ExpiresAt           time.Time `json:"expires_at"`
	CodeChallenge       *string   `json:"code_challenge" gorm:"type:varchar(255)"`
	CodeChallengeMethod *string   `json:"code_challenge_method" gorm:"type:varchar(10)"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`

	// Relationships
	User   *User        `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Client *OAuthClient `json:"client,omitempty" gorm:"foreignKey:ClientID"`
}

// TableName specifies the table name for OAuthAuthCode
func (OAuthAuthCode) TableName() string {
	return "oauth_auth_codes"
}

// GetScopes returns the scopes as a slice
func (c *OAuthAuthCode) GetScopes() []string {
	var scopes []string
	if c.Scopes != nil && *c.Scopes != "" {
		json.Unmarshal([]byte(*c.Scopes), &scopes)
	}
	return scopes
}

// SetScopes sets the scopes from a slice
func (c *OAuthAuthCode) SetScopes(scopes []string) {
	if data, err := json.Marshal(scopes); err == nil {
		scopesStr := string(data)
		c.Scopes = &scopesStr
	}
}

// HasScope checks if the auth code has a specific scope
func (c *OAuthAuthCode) HasScope(scope string) bool {
	scopes := c.GetScopes()
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAnyScope checks if the auth code has any of the specified scopes
func (c *OAuthAuthCode) HasAnyScope(scopes []string) bool {
	codeScopes := c.GetScopes()
	for _, scope := range scopes {
		for _, codeScope := range codeScopes {
			if scope == codeScope {
				return true
			}
		}
	}
	return false
}

// HasAllScopes checks if the auth code has all of the specified scopes
func (c *OAuthAuthCode) HasAllScopes(scopes []string) bool {
	codeScopes := c.GetScopes()
	for _, scope := range scopes {
		found := false
		for _, codeScope := range codeScopes {
			if scope == codeScope {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// IsExpired returns true if the auth code is expired
func (c *OAuthAuthCode) IsExpired() bool {
	return time.Now().After(c.ExpiresAt)
}

// IsRevoked returns true if the auth code is revoked
func (c *OAuthAuthCode) IsRevoked() bool {
	return c.Revoked
}

// Revoke marks the auth code as revoked
func (c *OAuthAuthCode) Revoke() error {
	c.Revoked = true
	return facades.Orm().Query().Save(c)
}

// GetUser returns the user associated with this auth code
func (c *OAuthAuthCode) GetUser() *User {
	var user User
	if err := facades.Orm().Query().Where("id", c.UserID).First(&user); err != nil {
		return nil
	}
	return &user
}

// GetClient returns the client associated with this auth code
func (c *OAuthAuthCode) GetClient() *OAuthClient {
	var client OAuthClient
	if err := facades.Orm().Query().Where("id", c.ClientID).First(&client); err != nil {
		return nil
	}
	return &client
}
