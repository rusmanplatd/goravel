package models

import (
	"encoding/json"
	"time"
)

// OAuthIdentityProvider represents an OAuth identity provider configuration
// @Description OAuth Identity Provider model for storing IdP configurations like Google, GitHub, Microsoft, etc.
type OAuthIdentityProvider struct {
	ID uint `gorm:"primaryKey" json:"id"`

	// Provider name (google, github, microsoft, etc.)
	// @example google
	Name string `gorm:"not null;index" json:"name" example:"google"`

	// Human readable provider name
	// @example Google
	DisplayName string `gorm:"not null" json:"display_name" example:"Google"`

	// OAuth client ID
	// @example 123456789.apps.googleusercontent.com
	ClientID string `gorm:"not null" json:"client_id" example:"123456789.apps.googleusercontent.com"`

	// OAuth client secret
	// @example secret123
	ClientSecret string `gorm:"not null" json:"client_secret,omitempty" example:"secret123"`

	// OAuth redirect URL
	// @example http://localhost:7000/auth/google/callback
	RedirectURL string `gorm:"not null" json:"redirect_url" example:"http://localhost:7000/auth/google/callback"`

	// JSON array of OAuth scopes
	// @example ["openid", "profile", "email"]
	Scopes string `gorm:"type:text" json:"scopes" example:"[\"openid\", \"profile\", \"email\"]"`

	// OAuth authorization endpoint
	// @example https://accounts.google.com/o/oauth2/auth
	AuthorizationURL string `gorm:"not null" json:"authorization_url" example:"https://accounts.google.com/o/oauth2/auth"`

	// OAuth token endpoint
	// @example https://oauth2.googleapis.com/token
	TokenURL string `gorm:"not null" json:"token_url" example:"https://oauth2.googleapis.com/token"`

	// User info endpoint
	// @example https://www.googleapis.com/oauth2/v2/userinfo
	UserinfoURL string `gorm:"not null" json:"userinfo_url" example:"https://www.googleapis.com/oauth2/v2/userinfo"`

	// JSON mapping for user info fields
	// @example {"id": "id", "email": "email", "name": "name", "picture": "avatar"}
	UserinfoMapping string `gorm:"type:text" json:"userinfo_mapping" example:"{\"id\": \"id\", \"email\": \"email\", \"name\": \"name\", \"picture\": \"avatar\"}"`

	// Provider icon URL
	// @example https://developers.google.com/identity/images/g-logo.png
	IconURL *string `json:"icon_url,omitempty" example:"https://developers.google.com/identity/images/g-logo.png"`

	// Button color for UI
	// @example #4285f4
	ButtonColor *string `json:"button_color,omitempty" example:"#4285f4"`

	// Whether this provider is enabled
	// @example true
	Enabled bool `gorm:"default:false;index" json:"enabled" example:"true"`

	// Display order
	// @example 1
	SortOrder int `gorm:"default:0;index" json:"sort_order" example:"1"`

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Note: UserIdentities relationship is defined in OAuthUserIdentity model to avoid circular imports
}

// TableName returns the table name for the model
func (OAuthIdentityProvider) TableName() string {
	return "oauth_identity_providers"
}

// GetScopes returns the scopes as a slice
func (p *OAuthIdentityProvider) GetScopes() ([]string, error) {
	var scopes []string
	if p.Scopes == "" {
		return scopes, nil
	}
	err := json.Unmarshal([]byte(p.Scopes), &scopes)
	return scopes, err
}

// SetScopes sets the scopes from a slice
func (p *OAuthIdentityProvider) SetScopes(scopes []string) error {
	data, err := json.Marshal(scopes)
	if err != nil {
		return err
	}
	p.Scopes = string(data)
	return nil
}

// GetUserinfoMapping returns the userinfo mapping as a map
func (p *OAuthIdentityProvider) GetUserinfoMapping() (map[string]string, error) {
	var mapping map[string]string
	if p.UserinfoMapping == "" {
		return mapping, nil
	}
	err := json.Unmarshal([]byte(p.UserinfoMapping), &mapping)
	return mapping, err
}

// SetUserinfoMapping sets the userinfo mapping from a map
func (p *OAuthIdentityProvider) SetUserinfoMapping(mapping map[string]string) error {
	data, err := json.Marshal(mapping)
	if err != nil {
		return err
	}
	p.UserinfoMapping = string(data)
	return nil
}

// IsActive checks if the provider is enabled
func (p *OAuthIdentityProvider) IsActive() bool {
	return p.Enabled
}
