package models

import (
	"encoding/json"
	"time"
)

// OAuthPushedAuthRequest represents a Pushed Authorization Request (RFC 9126)
// @Description OAuth Pushed Authorization Request model for RFC 9126 PAR support
type OAuthPushedAuthRequest struct {
	ID string `gorm:"primaryKey;type:char(26)" json:"id"`

	// Client ID that created this PAR request
	// @example abc123def456
	ClientID string `gorm:"not null;index" json:"client_id" example:"abc123def456"`

	// Request URI to be used in authorization request
	// @example urn:ietf:params:oauth:request_uri:xyz789
	RequestURI string `gorm:"not null;unique;index" json:"request_uri" example:"urn:ietf:params:oauth:request_uri:xyz789"`

	// JSON-encoded authorization parameters
	// @example {"response_type": "code", "client_id": "abc123", "redirect_uri": "https://example.com/callback"}
	Parameters string `gorm:"type:text" json:"parameters,omitempty" example:"{\"response_type\": \"code\", \"client_id\": \"abc123\", \"redirect_uri\": \"https://example.com/callback\"}"`

	// Whether this PAR request has been used
	// @example false
	Used bool `gorm:"default:false;index" json:"used" example:"false"`

	// When this PAR request expires
	// @example 2023-12-01T12:00:00Z
	ExpiresAt time.Time `gorm:"not null;index" json:"expires_at" example:"2023-12-01T12:00:00Z"`

	// Timestamps
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Relationships
	Client *OAuthClient `json:"client,omitempty" gorm:"foreignKey:ClientID"`
}

// TableName returns the table name for the model
func (OAuthPushedAuthRequest) TableName() string {
	return "oauth_pushed_auth_requests"
}

// GetParameters returns the authorization parameters as a map
func (par *OAuthPushedAuthRequest) GetParameters() (map[string]string, error) {
	var params map[string]string
	if par.Parameters == "" {
		return make(map[string]string), nil
	}
	err := json.Unmarshal([]byte(par.Parameters), &params)
	return params, err
}

// SetParameters sets the authorization parameters from a map
func (par *OAuthPushedAuthRequest) SetParameters(params map[string]string) error {
	data, err := json.Marshal(params)
	if err != nil {
		return err
	}
	par.Parameters = string(data)
	return nil
}

// IsExpired returns true if the PAR request has expired
func (par *OAuthPushedAuthRequest) IsExpired() bool {
	return time.Now().After(par.ExpiresAt)
}

// IsUsed returns true if the PAR request has been used
func (par *OAuthPushedAuthRequest) IsUsed() bool {
	return par.Used
}

// IsValid returns true if the PAR request is valid (not expired and not used)
func (par *OAuthPushedAuthRequest) IsValid() bool {
	return !par.IsExpired() && !par.IsUsed()
}

// GetClient returns the associated OAuth client
func (par *OAuthPushedAuthRequest) GetClient() *OAuthClient {
	return par.Client
}
