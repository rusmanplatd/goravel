package models

import (
	"encoding/json"
	"time"
)

// OAuthConsent represents a user's consent/authorization for an OAuth client
type OAuthConsent struct {
	ID        string     `json:"id" gorm:"primaryKey;type:char(26)"`
	UserID    string     `json:"user_id" gorm:"type:char(26);index;not null"`
	ClientID  string     `json:"client_id" gorm:"type:char(26);index;not null"`
	Scopes    *string    `json:"scopes" gorm:"type:text"`
	Granted   bool       `json:"granted" gorm:"default:true"`
	Revoked   bool       `json:"revoked" gorm:"default:false"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`

	// Relationships
	User   *User        `json:"user,omitempty" gorm:"foreignKey:UserID"`
	Client *OAuthClient `json:"client,omitempty" gorm:"foreignKey:ClientID"`
}

// TableName specifies the table name for OAuthConsent
func (OAuthConsent) TableName() string {
	return "oauth_consents"
}

// GetScopes returns the scopes as a slice
func (c *OAuthConsent) GetScopes() []string {
	var scopes []string
	if c.Scopes != nil && *c.Scopes != "" {
		json.Unmarshal([]byte(*c.Scopes), &scopes)
	}
	return scopes
}

// SetScopes sets the scopes from a slice
func (c *OAuthConsent) SetScopes(scopes []string) {
	if data, err := json.Marshal(scopes); err == nil {
		scopesStr := string(data)
		c.Scopes = &scopesStr
	}
}

// HasScope checks if the consent has a specific scope
func (c *OAuthConsent) HasScope(scope string) bool {
	scopes := c.GetScopes()
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// IsActive returns true if the consent is active (granted and not revoked)
func (c *OAuthConsent) IsActive() bool {
	if !c.Granted || c.Revoked {
		return false
	}

	// Check if consent has expired
	if c.ExpiresAt != nil && time.Now().After(*c.ExpiresAt) {
		return false
	}

	return true
}

// Revoke marks the consent as revoked
func (c *OAuthConsent) Revoke() {
	c.Revoked = true
	c.UpdatedAt = time.Now()
}

// IsExpired returns true if the consent has expired
func (c *OAuthConsent) IsExpired() bool {
	return c.ExpiresAt != nil && time.Now().After(*c.ExpiresAt)
}
