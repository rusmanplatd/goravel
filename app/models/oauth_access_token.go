package models

import (
	"encoding/json"
	"time"

	"github.com/goravel/framework/facades"
)

// OAuthAccessToken represents an OAuth2 access token
type OAuthAccessToken struct {
	ID        string    `json:"id" gorm:"primaryKey;type:varchar(100)"`
	UserID    *string   `json:"user_id" gorm:"type:char(26);index"`
	ClientID  string    `json:"client_id" gorm:"type:char(26);index"`
	Name      *string   `json:"name" gorm:"type:varchar(255)"`
	Scopes    *string   `json:"scopes" gorm:"type:text"`
	Revoked   bool      `json:"revoked" gorm:"default:false"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relationships
	User         *User              `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Client       *OAuthClient       `json:"client,omitempty" gorm:"foreignKey:ClientID"`
	RefreshToken *OAuthRefreshToken `json:"refresh_token,omitempty" gorm:"foreignKey:AccessTokenID"`
}

// TableName specifies the table name for OAuthAccessToken
func (OAuthAccessToken) TableName() string {
	return "oauth_access_tokens"
}

// GetScopes returns the scopes as a slice
func (t *OAuthAccessToken) GetScopes() []string {
	var scopes []string
	if t.Scopes != nil && *t.Scopes != "" {
		json.Unmarshal([]byte(*t.Scopes), &scopes)
	}
	return scopes
}

// SetScopes sets the scopes from a slice
func (t *OAuthAccessToken) SetScopes(scopes []string) {
	if data, err := json.Marshal(scopes); err == nil {
		scopesStr := string(data)
		t.Scopes = &scopesStr
	}
}

// HasScope checks if the token has a specific scope
func (t *OAuthAccessToken) HasScope(scope string) bool {
	scopes := t.GetScopes()
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// HasAnyScope checks if the token has any of the specified scopes
func (t *OAuthAccessToken) HasAnyScope(scopes []string) bool {
	tokenScopes := t.GetScopes()
	for _, scope := range scopes {
		for _, tokenScope := range tokenScopes {
			if scope == tokenScope {
				return true
			}
		}
	}
	return false
}

// HasAllScopes checks if the token has all of the specified scopes
func (t *OAuthAccessToken) HasAllScopes(scopes []string) bool {
	tokenScopes := t.GetScopes()
	for _, scope := range scopes {
		found := false
		for _, tokenScope := range tokenScopes {
			if scope == tokenScope {
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

// IsRevoked returns true if the token is revoked
func (t *OAuthAccessToken) IsRevoked() bool {
	return t.Revoked
}

// Revoke marks the token as revoked
func (t *OAuthAccessToken) Revoke() error {
	t.Revoked = true
	return facades.Orm().Query().Save(t)
}

// GetUser returns the user associated with this token
func (t *OAuthAccessToken) GetUser() *User {
	if t.UserID == nil {
		return nil
	}

	var user User
	if err := facades.Orm().Query().Where("id", *t.UserID).First(&user); err != nil {
		return nil
	}
	return &user
}

// GetClient returns the client associated with this token
func (t *OAuthAccessToken) GetClient() *OAuthClient {
	var client OAuthClient
	if err := facades.Orm().Query().Where("id", t.ClientID).First(&client); err != nil {
		return nil
	}
	return &client
}
