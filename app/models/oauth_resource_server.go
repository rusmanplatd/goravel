package models

import (
	"encoding/json"
)

// OAuthResourceServer represents an OAuth2 resource server configuration
// @Description OAuth2 resource server model for storing resource server configurations
type OAuthResourceServer struct {
	BaseModel

	// Resource server name
	// @example API Server
	Name string `gorm:"not null" json:"name" example:"API Server"`

	// Resource server URI identifier
	// @example https://api.example.com
	URI string `gorm:"not null;uniqueIndex" json:"uri" example:"https://api.example.com"`

	// Resource server description
	// @example Main API server for the application
	Description string `json:"description" example:"Main API server for the application"`

	// Resource server category
	// @example api
	Category string `json:"category" example:"api"`

	// Supported OAuth scopes (JSON array)
	// @example ["read", "write", "admin"]
	SupportedScopes string `gorm:"type:text" json:"supported_scopes" example:"[\"read\", \"write\", \"admin\"]"`

	// Required OAuth scopes (JSON array)
	// @example ["read"]
	RequiredScopes string `gorm:"type:text" json:"required_scopes" example:"[\"read\"]"`

	// Default OAuth scopes (JSON array)
	// @example ["read"]
	DefaultScopes string `gorm:"type:text" json:"default_scopes" example:"[\"read\"]"`

	// Maximum scope lifetime in seconds
	// @example 3600
	MaxScopeLifetime int64 `gorm:"default:3600" json:"max_scope_lifetime" example:"3600"`

	// Token format (jwt, opaque)
	// @example jwt
	TokenFormat string `gorm:"default:'jwt'" json:"token_format" example:"jwt"`

	// Token signing algorithm
	// @example RS256
	TokenSigningAlgorithm string `gorm:"default:'RS256'" json:"token_signing_algorithm" example:"RS256"`

	// Audience list (JSON array)
	// @example ["https://api.example.com"]
	Audience string `gorm:"type:text" json:"audience" example:"[\"https://api.example.com\"]"`

	// Token issuer
	// @example https://auth.example.com
	Issuer string `json:"issuer" example:"https://auth.example.com"`

	// JWKS URI for token verification
	// @example https://auth.example.com/.well-known/jwks.json
	JWKSURI string `json:"jwks_uri" example:"https://auth.example.com/.well-known/jwks.json"`

	// Token introspection endpoint
	// @example https://auth.example.com/oauth/introspect
	IntrospectionEndpoint string `json:"introspection_endpoint" example:"https://auth.example.com/oauth/introspect"`

	// Whether the resource server is active
	// @example true
	Active bool `gorm:"default:true" json:"active" example:"true"`

	// Additional metadata (JSON)
	// @example {"version": "1.0", "contact": "admin@example.com"}
	Metadata string `gorm:"type:json" json:"metadata" example:"{\"version\": \"1.0\", \"contact\": \"admin@example.com\"}"`

	// Security policy configuration (JSON)
	// @example {"require_mtls": false, "require_dpop": true}
	SecurityPolicy string `gorm:"type:json" json:"security_policy" example:"{\"require_mtls\": false, \"require_dpop\": true}"`
}

// TableName specifies the table name for OAuthResourceServer
func (OAuthResourceServer) TableName() string {
	return "oauth_resource_servers"
}

// GetSupportedScopes returns the supported scopes as a slice
func (r *OAuthResourceServer) GetSupportedScopes() []string {
	var scopes []string
	if r.SupportedScopes != "" {
		json.Unmarshal([]byte(r.SupportedScopes), &scopes)
	}
	return scopes
}

// SetSupportedScopes sets the supported scopes from a slice
func (r *OAuthResourceServer) SetSupportedScopes(scopes []string) {
	if data, err := json.Marshal(scopes); err == nil {
		r.SupportedScopes = string(data)
	}
}

// GetRequiredScopes returns the required scopes as a slice
func (r *OAuthResourceServer) GetRequiredScopes() []string {
	var scopes []string
	if r.RequiredScopes != "" {
		json.Unmarshal([]byte(r.RequiredScopes), &scopes)
	}
	return scopes
}

// SetRequiredScopes sets the required scopes from a slice
func (r *OAuthResourceServer) SetRequiredScopes(scopes []string) {
	if data, err := json.Marshal(scopes); err == nil {
		r.RequiredScopes = string(data)
	}
}

// GetDefaultScopes returns the default scopes as a slice
func (r *OAuthResourceServer) GetDefaultScopes() []string {
	var scopes []string
	if r.DefaultScopes != "" {
		json.Unmarshal([]byte(r.DefaultScopes), &scopes)
	}
	return scopes
}

// SetDefaultScopes sets the default scopes from a slice
func (r *OAuthResourceServer) SetDefaultScopes(scopes []string) {
	if data, err := json.Marshal(scopes); err == nil {
		r.DefaultScopes = string(data)
	}
}

// GetAudience returns the audience as a slice
func (r *OAuthResourceServer) GetAudience() []string {
	var audience []string
	if r.Audience != "" {
		json.Unmarshal([]byte(r.Audience), &audience)
	}
	return audience
}

// SetAudience sets the audience from a slice
func (r *OAuthResourceServer) SetAudience(audience []string) {
	if data, err := json.Marshal(audience); err == nil {
		r.Audience = string(data)
	}
}

// GetMetadata returns the metadata as a map
func (r *OAuthResourceServer) GetMetadata() map[string]interface{} {
	var metadata map[string]interface{}
	if r.Metadata != "" {
		json.Unmarshal([]byte(r.Metadata), &metadata)
	}
	return metadata
}

// SetMetadata sets the metadata from a map
func (r *OAuthResourceServer) SetMetadata(metadata map[string]interface{}) {
	if data, err := json.Marshal(metadata); err == nil {
		r.Metadata = string(data)
	}
}

// GetSecurityPolicy returns the security policy as a map
func (r *OAuthResourceServer) GetSecurityPolicy() map[string]interface{} {
	var policy map[string]interface{}
	if r.SecurityPolicy != "" {
		json.Unmarshal([]byte(r.SecurityPolicy), &policy)
	}
	return policy
}

// SetSecurityPolicy sets the security policy from a map
func (r *OAuthResourceServer) SetSecurityPolicy(policy map[string]interface{}) {
	if data, err := json.Marshal(policy); err == nil {
		r.SecurityPolicy = string(data)
	}
}

// IsActive returns whether the resource server is active
func (r *OAuthResourceServer) IsActive() bool {
	return r.Active
}

// HasScope checks if the resource server supports a specific scope
func (r *OAuthResourceServer) HasScope(scope string) bool {
	scopes := r.GetSupportedScopes()
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// RequiresScope checks if the resource server requires a specific scope
func (r *OAuthResourceServer) RequiresScope(scope string) bool {
	scopes := r.GetRequiredScopes()
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}
