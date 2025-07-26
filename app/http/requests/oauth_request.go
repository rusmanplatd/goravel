package requests

// OAuthClientRequest represents the request for creating/updating OAuth clients
// @Description Request model for OAuth client management
type OAuthClientRequest struct {
	// Client name
	// @example My OAuth Client
	Name string `json:"name" binding:"required" example:"My OAuth Client" validate:"required"`

	// User ID (optional, for personal clients)
	// @example 01HXYZ123456789ABCDEFGHIJK
	UserID *string `json:"user_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Redirect URIs (JSON array)
	// @example ["https://example.com/callback", "https://app.example.com/callback"]
	RedirectURIs []string `json:"redirect_uris" example:"[\"https://example.com/callback\", \"https://app.example.com/callback\"]"`

	// Whether this is a personal access client
	// @example false
	PersonalAccessClient bool `json:"personal_access_client" example:"false"`

	// Whether this is a password client
	// @example false
	PasswordClient bool `json:"password_client" example:"false"`
}

// OAuthTokenRequest represents the request for OAuth2 token endpoints
// @Description Request model for OAuth2 token requests
type OAuthTokenRequest struct {
	// Grant type
	// @example password
	GrantType string `json:"grant_type" binding:"required" example:"password" validate:"required,oneof=password client_credentials authorization_code refresh_token"`

	// Client ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ClientID string `json:"client_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK" validate:"required"`

	// Client secret (for confidential clients)
	// @example abc123def456
	ClientSecret string `json:"client_secret,omitempty" example:"abc123def456"`

	// Username (for password grant)
	// @example user@example.com
	Username string `json:"username,omitempty" example:"user@example.com"`

	// Password (for password grant)
	// @example password123
	Password string `json:"password,omitempty" example:"password123"`

	// Authorization code (for authorization code grant)
	// @example abc123def456
	Code string `json:"code,omitempty" example:"abc123def456"`

	// Redirect URI (for authorization code grant)
	// @example https://example.com/callback
	RedirectURI string `json:"redirect_uri,omitempty" example:"https://example.com/callback"`

	// Refresh token (for refresh token grant)
	// @example abc123def456
	RefreshToken string `json:"refresh_token,omitempty" example:"abc123def456"`

	// Scopes (space-separated)
	// @example read write
	Scope string `json:"scope,omitempty" example:"read write"`

	// State parameter (for authorization code grant)
	// @example abc123def456
	State string `json:"state,omitempty" example:"abc123def456"`

	// Code verifier (for PKCE)
	// @example abc123def456
	CodeVerifier string `json:"code_verifier,omitempty" example:"abc123def456"`

	// Device code (for device authorization grant)
	// @example abc123def456
	DeviceCode string `json:"device_code,omitempty" example:"abc123def456"`

	// Subject token (for token exchange grant)
	// @example abc123def456
	SubjectToken string `json:"subject_token,omitempty" example:"abc123def456"`

	// Subject token type (for token exchange grant)
	// @example access_token
	SubjectTokenType string `json:"subject_token_type,omitempty" example:"access_token"`

	// Requested token type (for token exchange grant)
	// @example access_token
	RequestedTokenType string `json:"requested_token_type,omitempty" example:"access_token"`

	// Client assertion (for client attestation)
	// @example eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
	ClientAssertion string `json:"client_assertion,omitempty" example:"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."`

	// Client assertion type (for client attestation)
	// @example urn:ietf:params:oauth:client-assertion-type:jwt-bearer
	ClientAssertionType string `json:"client_assertion_type,omitempty" example:"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"`
}

// OAuthAuthorizationRequest represents the request for OAuth2 authorization endpoint
// @Description Request model for OAuth2 authorization requests
type OAuthAuthorizationRequest struct {
	// Response type
	// @example code
	ResponseType string `json:"response_type" binding:"required" example:"code" validate:"required,oneof=code token"`

	// Client ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ClientID string `json:"client_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK" validate:"required"`

	// Redirect URI
	// @example https://example.com/callback
	RedirectURI string `json:"redirect_uri" binding:"required" example:"https://example.com/callback" validate:"required,url"`

	// Scopes (space-separated)
	// @example read write
	Scope string `json:"scope,omitempty" example:"read write"`

	// State parameter
	// @example abc123def456
	State string `json:"state,omitempty" example:"abc123def456"`

	// Code challenge (for PKCE)
	// @example abc123def456
	CodeChallenge string `json:"code_challenge,omitempty" example:"abc123def456"`

	// Code challenge method (for PKCE)
	// @example S256
	CodeChallengeMethod string `json:"code_challenge_method,omitempty" example:"S256" validate:"omitempty,oneof=S256 plain"`
}

// OAuthTokenIntrospectionRequest represents the request for OAuth2 token introspection
// @Description Request model for OAuth2 token introspection
type OAuthTokenIntrospectionRequest struct {
	// Token to introspect
	// @example abc123def456
	Token string `json:"token" binding:"required" example:"abc123def456" validate:"required"`

	// Token type hint
	// @example access_token
	TokenTypeHint string `json:"token_type_hint,omitempty" example:"access_token" validate:"omitempty,oneof=access_token refresh_token"`
}

// OAuthTokenRevocationRequest represents the request for OAuth2 token revocation
// @Description Request model for OAuth2 token revocation
type OAuthTokenRevocationRequest struct {
	// Token to revoke
	// @example abc123def456
	Token string `json:"token" binding:"required" example:"abc123def456" validate:"required"`

	// Token type hint
	// @example access_token
	TokenTypeHint string `json:"token_type_hint,omitempty" example:"access_token" validate:"omitempty,oneof=access_token refresh_token"`

	// Client ID (for confidential clients)
	// @example 01HXYZ123456789ABCDEFGHIJK
	ClientID string `json:"client_id,omitempty" example:"01HXYZ123456789ABCDEFGHIJK"`

	// Client secret (for confidential clients)
	// @example abc123def456
	ClientSecret string `json:"client_secret,omitempty" example:"abc123def456"`
}

// OAuthPersonalAccessTokenRequest represents the request for creating personal access tokens
// @Description Request model for personal access token creation
type OAuthPersonalAccessTokenRequest struct {
	// Token name
	// @example My Personal Token
	Name string `json:"name" binding:"required" example:"My Personal Token" validate:"required"`

	// Scopes (space-separated)
	// @example read write
	Scope string `json:"scope,omitempty" example:"read write"`

	// Expiration date (optional)
	// @example 2024-12-31T23:59:59Z
	ExpiresAt *string `json:"expires_at,omitempty" example:"2024-12-31T23:59:59Z"`
}

// OAuthClientUpdateRequest represents the request for updating OAuth clients
// @Description Request model for updating OAuth clients
type OAuthClientUpdateRequest struct {
	// Client name
	// @example Updated Client Name
	Name string `json:"name" binding:"required" example:"Updated Client Name" validate:"required"`

	// Redirect URIs (JSON array)
	// @example ["https://example.com/callback", "https://app.example.com/callback"]
	RedirectURIs []string `json:"redirect_uris" example:"[\"https://example.com/callback\", \"https://app.example.com/callback\"]"`
}

// OAuthScopeRequest represents the request for OAuth scope validation
// @Description Request model for OAuth scope validation
type OAuthScopeRequest struct {
	// Scopes to validate (space-separated)
	// @example read write delete
	Scope string `json:"scope" binding:"required" example:"read write delete" validate:"required"`
}

// OAuthRedirectURIRequest represents the request for OAuth redirect URI validation
// @Description Request model for OAuth redirect URI validation
type OAuthRedirectURIRequest struct {
	// Redirect URI to validate
	// @example https://example.com/callback
	RedirectURI string `json:"redirect_uri" binding:"required" example:"https://example.com/callback" validate:"required,url"`

	// Client ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ClientID string `json:"client_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK" validate:"required"`
}

// OAuthDeviceAuthorizationRequest represents the request for OAuth2 device authorization
// @Description Request model for OAuth2 device authorization
type OAuthDeviceAuthorizationRequest struct {
	// Client ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ClientID string `json:"client_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK" validate:"required"`

	// Scopes (space-separated)
	// @example read write
	Scope string `json:"scope,omitempty" example:"read write"`
}

// OAuthDeviceTokenRequest represents the request for OAuth2 device token
// @Description Request model for OAuth2 device token requests
type OAuthDeviceTokenRequest struct {
	// Grant type
	// @example urn:ietf:params:oauth:grant-type:device_code
	GrantType string `json:"grant_type" binding:"required" example:"urn:ietf:params:oauth:grant-type:device_code" validate:"required"`

	// Device code
	// @example abc123def456
	DeviceCode string `json:"device_code" binding:"required" example:"abc123def456" validate:"required"`

	// Client ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ClientID string `json:"client_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK" validate:"required"`
}

// OAuthCompleteDeviceAuthorizationRequest represents the request for completing device authorization
// @Description Request model for completing device authorization
type OAuthCompleteDeviceAuthorizationRequest struct {
	// User code
	// @example ABCD
	UserCode string `json:"user_code" binding:"required" example:"ABCD" validate:"required"`

	// User email
	// @example user@example.com
	Email string `json:"email" binding:"required" example:"user@example.com" validate:"required,email"`

	// User password
	// @example password123
	Password string `json:"password" binding:"required" example:"password123" validate:"required"`
}

// OAuthTokenExchangeRequest represents the request for OAuth2 token exchange
// @Description Request model for OAuth2 token exchange
type OAuthTokenExchangeRequest struct {
	// Grant type
	// @example urn:ietf:params:oauth:grant-type:token-exchange
	GrantType string `json:"grant_type" binding:"required" example:"urn:ietf:params:oauth:grant-type:token-exchange" validate:"required"`

	// Subject token
	// @example abc123def456
	SubjectToken string `json:"subject_token" binding:"required" example:"abc123def456" validate:"required"`

	// Subject token type
	// @example access_token
	SubjectTokenType string `json:"subject_token_type" binding:"required" example:"access_token" validate:"required,oneof=access_token refresh_token"`

	// Requested token type
	// @example access_token
	RequestedTokenType string `json:"requested_token_type" binding:"required" example:"access_token" validate:"required,oneof=access_token"`

	// Client ID
	// @example 01HXYZ123456789ABCDEFGHIJK
	ClientID string `json:"client_id" binding:"required" example:"01HXYZ123456789ABCDEFGHIJK" validate:"required"`

	// Client secret (for confidential clients)
	// @example abc123def456
	ClientSecret string `json:"client_secret,omitempty" example:"abc123def456"`

	// Scopes (space-separated)
	// @example read write
	Scope string `json:"scope,omitempty" example:"read write"`
}

// OAuthConsentRequest represents the request for OAuth2 consent processing
// @Description Request model for OAuth2 consent processing
type OAuthConsentRequest struct {
	// Consent ID from the consent preparation
	// @example consent_1234567890_abcdefgh
	ConsentID string `json:"consent_id" binding:"required" example:"consent_1234567890_abcdefgh" validate:"required"`

	// Whether the user granted consent
	// @example true
	Granted bool `json:"granted" example:"true"`

	// Scopes that the user granted (subset of requested scopes)
	// @example ["profile", "email"]
	GrantedScopes []string `json:"granted_scopes" example:"[\"profile\", \"email\"]"`
}
