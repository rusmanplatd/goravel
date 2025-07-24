# Complete OpenID Connect (OIDC) Implementation

This document describes the complete OpenID Connect implementation in Goravel, which provides a full-featured OIDC server similar to Google's OAuth2 provider.

## Overview

The OIDC implementation provides a complete OAuth2/OpenID Connect server with:

- **OIDC Discovery**: Automatic discovery of OIDC endpoints and capabilities
- **Authorization Code Flow**: Secure authorization with PKCE support
- **ID Tokens**: JWT-based identity tokens with user claims
- **User Info Endpoint**: Access to user profile information
- **JWKS Endpoint**: Public keys for token validation
- **Session Management**: End session and check session endpoints
- **Token Introspection**: RFC 7662 compliant token introspection
- **Token Revocation**: RFC 7009 compliant token revocation
- **Device Authorization**: RFC 8628 device authorization flow
- **Dynamic Client Registration**: RFC 7591 client registration
- **Multiple Grant Types**: Support for various OAuth2/OIDC flows
- **Security Features**: PKCE, state validation, nonce validation
- **Audit Logging**: Comprehensive event logging

## Architecture

### Core Components

1. **OIDC Service** (`app/services/oidc_service.go`)
   - Handles OIDC-specific operations
   - Generates and validates ID tokens
   - Manages JWKS (JSON Web Key Set)
   - Provides discovery document
   - Token introspection and revocation
   - Security validation

2. **OIDC Controller** (`app/http/controllers/api/v1/oidc_controller.go`)
   - Exposes OIDC endpoints
   - Handles authorization flows
   - Manages token exchange
   - Provides user info
   - Device authorization
   - Token introspection and revocation

3. **OIDC Client Service** (`app/services/oidc_client_service.go`)
   - Dynamic client registration
   - Client metadata management
   - Client validation and permissions
   - Client activity logging

4. **OIDC Configuration** (`config/oidc.go`)
   - Comprehensive OIDC settings
   - Security configurations
   - Supported features and algorithms

## Endpoints

### Discovery Endpoint
```
GET /.well-known/openid_configuration
```
Returns the OIDC discovery document with all supported features, endpoints, and capabilities.

**Response Example:**
```json
{
  "issuer": "https://example.com",
  "authorization_endpoint": "https://example.com/.well-known/oauth2/authorize",
  "token_endpoint": "https://example.com/.well-known/oauth2/token",
  "userinfo_endpoint": "https://example.com/.well-known/oauth2/userinfo",
  "jwks_uri": "https://example.com/.well-known/oauth2/jwks",
  "end_session_endpoint": "https://example.com/.well-known/oauth2/end_session",
  "check_session_iframe": "https://example.com/.well-known/oauth2/check_session",
  "revocation_endpoint": "https://example.com/.well-known/oauth2/revoke",
  "introspection_endpoint": "https://example.com/.well-known/oauth2/introspect",
  "device_authorization_endpoint": "https://example.com/.well-known/oauth2/device",
  "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"],
  "subject_types_supported": ["public", "pairwise"],
  "id_token_signing_alg_values_supported": ["RS256", "ES256", "PS256"],
  "scopes_supported": ["openid", "profile", "email", "address", "phone", "offline_access"],
  "grant_types_supported": ["authorization_code", "implicit", "refresh_token", "password", "client_credentials", "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:token-exchange"],
  "code_challenge_methods_supported": ["plain", "S256"]
}
```

### Authorization Endpoint
```
GET /.well-known/oauth2/authorize
```
Handles OIDC authorization requests with support for:
- Authorization code flow
- PKCE (Proof Key for Code Exchange)
- State and nonce parameters
- Scope validation
- Response type validation

**Parameters:**
- `response_type`: Required. Must be "code", "token", or "id_token"
- `client_id`: Required. The client identifier
- `redirect_uri`: Required. The redirect URI
- `scope`: Optional. Space-separated list of scopes
- `state`: Optional. State parameter for CSRF protection
- `nonce`: Optional. Nonce parameter for replay protection
- `code_challenge`: Optional. PKCE code challenge
- `code_challenge_method`: Optional. PKCE method ("S256" or "plain")

### Token Endpoint
```
POST /.well-known/oauth2/token
```
Exchanges authorization codes for tokens:
- Access tokens
- ID tokens
- Refresh tokens
- PKCE validation

**Supported Grant Types:**
- `authorization_code`: Exchange authorization code for tokens
- `refresh_token`: Exchange refresh token for new access token
- `password`: Resource owner password credentials
- `client_credentials`: Client credentials grant
- `urn:ietf:params:oauth:grant-type:device_code`: Device authorization grant
- `urn:ietf:params:oauth:grant-type:token-exchange`: Token exchange grant

### User Info Endpoint
```
GET /.well-known/oauth2/userinfo
```
Returns user profile information based on the access token and requested scopes.

**Headers:**
- `Authorization: Bearer <access_token>`

**Response Example:**
```json
{
  "sub": "01HXYZ123456789ABCDEFGHIJK",
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "email": "john.doe@example.com",
  "email_verified": true,
  "preferred_username": "john.doe@example.com",
  "profile": "https://example.com/users/01HXYZ123456789ABCDEFGHIJK",
  "updated_at": 1640995200
}
```

### JWKS Endpoint
```
GET /.well-known/oauth2/jwks
```
Returns the JSON Web Key Set for token validation.

**Response Example:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "abc123",
      "use": "sig",
      "alg": "RS256",
      "n": "base64url-encoded-modulus",
      "e": "base64url-encoded-exponent"
    }
  ]
}
```

### Token Introspection Endpoint
```
POST /.well-known/oauth2/introspect
```
RFC 7662 compliant token introspection.

**Parameters:**
- `token`: Required. The token to introspect
- `token_type_hint`: Optional. Hint about the token type

**Headers:**
- `Authorization: Basic <base64(client_id:client_secret)>`

**Response Example:**
```json
{
  "active": true,
  "scope": "openid profile email",
  "client_id": "client123",
  "username": "01HXYZ123456789ABCDEFGHIJK",
  "token_type": "Bearer",
  "exp": 1640995200,
  "iat": 1640991600,
  "nbf": 1640991600,
  "sub": "01HXYZ123456789ABCDEFGHIJK",
  "aud": "client123",
  "iss": "https://example.com"
}
```

### Token Revocation Endpoint
```
POST /.well-known/oauth2/revoke
```
RFC 7009 compliant token revocation.

**Parameters:**
- `token`: Required. The token to revoke
- `token_type_hint`: Optional. Hint about the token type

**Headers:**
- `Authorization: Basic <base64(client_id:client_secret)>`

### Device Authorization Endpoint
```
POST /.well-known/oauth2/device
```
RFC 8628 device authorization flow.

**Parameters:**
- `client_id`: Required. The client identifier
- `scope`: Optional. Space-separated list of scopes

**Response Example:**
```json
{
  "device_code": "device_code_123",
  "user_code": "ABCD-EFGH",
  "verification_uri": "https://example.com/device",
  "verification_uri_complete": "https://example.com/device?user_code=ABCD-EFGH",
  "expires_in": 600,
  "interval": 5
}
```

### Device Token Endpoint
```
POST /.well-known/oauth2/device/token
```
Exchanges device code for tokens.

**Parameters:**
- `device_code`: Required. The device code
- `client_id`: Required. The client identifier

### Device Authorization Completion
```
POST /.well-known/oauth2/device/complete
```
Completes device authorization with user credentials.

**Parameters:**
- `user_code`: Required. The user code
- `email`: Required. User email
- `password`: Required. User password

### End Session Endpoint
```
GET /.well-known/oauth2/end_session
```
Handles OpenID Connect end session requests.

**Parameters:**
- `id_token_hint`: Optional. ID token hint
- `post_logout_redirect_uri`: Optional. Post logout redirect URI
- `state`: Optional. State parameter

### Check Session Endpoint
```
GET /.well-known/oauth2/check_session
```
Returns check session iframe content for session management.

## Client Registration

### Dynamic Client Registration
```
POST /oidc/register
```
RFC 7591 dynamic client registration.

**Request Example:**
```json
{
  "client_name": "My OIDC Client",
  "client_uri": "https://myapp.com",
  "logo_uri": "https://myapp.com/logo.png",
  "redirect_uris": ["https://myapp.com/callback"],
  "token_endpoint_auth_method": "client_secret_basic",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "scope": "openid profile email",
  "contacts": ["admin@myapp.com"]
}
```

**Response Example:**
```json
{
  "client_id": "client_123",
  "client_secret": "secret_456",
  "client_id_issued_at": 1640991600,
  "client_secret_expires_at": 0,
  "client_name": "My OIDC Client",
  "client_uri": "https://myapp.com",
  "logo_uri": "https://myapp.com/logo.png",
  "redirect_uris": ["https://myapp.com/callback"],
  "token_endpoint_auth_method": "client_secret_basic",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "scope": "openid profile email",
  "contacts": ["admin@myapp.com"],
  "registration_access_token": "reg_token_789",
  "registration_client_uri": "https://example.com/oidc/register/client_123"
}
```

### Client Management Endpoints

- `GET /oidc/register/{client_id}` - Get client information
- `PUT /oidc/register/{client_id}` - Update client information
- `DELETE /oidc/register/{client_id}` - Delete (revoke) client
- `POST /oidc/validate` - Validate client credentials
- `GET /oidc/clients` - List clients (admin only)
- `GET /oidc/client/{client_id}/metadata` - Get client metadata

## Security Features

### PKCE (Proof Key for Code Exchange)
PKCE is supported for all authorization code flows to prevent authorization code interception attacks.

**Flow:**
1. Client generates `code_verifier` (random string)
2. Client generates `code_challenge` (SHA256 hash of verifier)
3. Client sends `code_challenge` in authorization request
4. Server stores `code_challenge` with authorization code
5. Client sends `code_verifier` in token request
6. Server validates `code_verifier` against stored `code_challenge`

### State Parameter Validation
State parameter is required for authorization requests to prevent CSRF attacks.

### Nonce Parameter Validation
Nonce parameter is required for implicit flows to prevent replay attacks.

### Token Binding
Token binding can be enabled to bind tokens to specific TLS connections.

### Token Rotation
Token rotation can be enabled to automatically rotate refresh tokens.

## Supported Scopes

- `openid`: Required for OIDC flows
- `profile`: Access to basic profile information
- `email`: Access to email address
- `address`: Access to address information
- `phone`: Access to phone number
- `offline_access`: Access to refresh tokens

## Supported Grant Types

- `authorization_code`: Authorization code flow
- `implicit`: Implicit flow (deprecated)
- `refresh_token`: Refresh token flow
- `password`: Resource owner password credentials
- `client_credentials`: Client credentials flow
- `urn:ietf:params:oauth:grant-type:device_code`: Device authorization flow
- `urn:ietf:params:oauth:grant-type:token-exchange`: Token exchange flow

## Supported Response Types

- `code`: Authorization code
- `token`: Access token
- `id_token`: ID token
- `code token`: Authorization code + access token
- `code id_token`: Authorization code + ID token
- `token id_token`: Access token + ID token
- `code token id_token`: Authorization code + access token + ID token

## Supported Token Endpoint Authentication Methods

- `client_secret_basic`: Client credentials in Authorization header
- `client_secret_post`: Client credentials in request body
- `client_secret_jwt`: Client credentials as JWT
- `private_key_jwt`: Client credentials as JWT with private key
- `none`: No client authentication (public clients)

## Supported ID Token Signing Algorithms

- `RS256`: RSA with SHA-256
- `ES256`: ECDSA with SHA-256
- `PS256`: RSA-PSS with SHA-256

## Supported Code Challenge Methods

- `plain`: Plain text code challenge
- `S256`: SHA256 code challenge

## Configuration

### OIDC Configuration (`config/oidc.go`)

The OIDC configuration provides comprehensive settings for:

- **Endpoints**: All OIDC endpoint URLs
- **Security**: Security requirements and validations
- **Supported Features**: Algorithms, grant types, response types
- **Token Settings**: Token lifetimes and features
- **Logging**: Event and activity logging
- **Claims**: Supported claims and scopes

### Environment Variables

```bash
# OIDC Server Configuration
OIDC_ISSUER=https://example.com
OIDC_AUTHORIZATION_ENDPOINT=/.well-known/oauth2/authorize
OIDC_TOKEN_ENDPOINT=/.well-known/oauth2/token
OIDC_USERINFO_ENDPOINT=/.well-known/oauth2/userinfo
OIDC_JWKS_ENDPOINT=/.well-known/oauth2/jwks
OIDC_END_SESSION_ENDPOINT=/.well-known/oauth2/end_session
OIDC_CHECK_SESSION_IFRAME=/.well-known/oauth2/check_session
OIDC_REVOCATION_ENDPOINT=/.well-known/oauth2/revoke
OIDC_INTROSPECTION_ENDPOINT=/.well-known/oauth2/introspect
OIDC_DEVICE_AUTHORIZATION_ENDPOINT=/.well-known/oauth2/device

# Security Configuration
OIDC_REQUIRE_HTTPS=true
OIDC_REQUIRE_PKCE_FOR_PUBLIC_CLIENTS=true
OIDC_REQUIRE_STATE_PARAMETER=true
OIDC_REQUIRE_NONCE_PARAMETER=true
OIDC_REQUIRE_CLIENT_AUTHENTICATION=true
OIDC_REQUIRE_SCOPE_VALIDATION=true
OIDC_REQUIRE_REDIRECT_URI_VALIDATION=true

# Token Configuration
OIDC_ID_TOKEN_LIFETIME=60
OIDC_ID_TOKEN_INCLUDE_USER_CLAIMS=true
OIDC_ID_TOKEN_INCLUDE_ACCESS_TOKEN_HASH=true
OIDC_ID_TOKEN_INCLUDE_AUTHORIZATION_CODE_HASH=true

# Logging Configuration
OIDC_ENABLE_EVENT_LOGGING=true
OIDC_ENABLE_TOKEN_USAGE_LOGGING=true
OIDC_ENABLE_CLIENT_ACTIVITY_LOGGING=true
OIDC_ENABLE_ERROR_LOGGING=true
OIDC_ENABLE_DEBUG_LOGGING=false
```

## Usage Examples

### Authorization Code Flow with PKCE

1. **Generate PKCE values:**
```javascript
const codeVerifier = generateRandomString(128);
const codeChallenge = base64URLEncode(sha256(codeVerifier));
```

2. **Authorization Request:**
```
GET /.well-known/oauth2/authorize?
  response_type=code&
  client_id=client123&
  redirect_uri=https://myapp.com/callback&
  scope=openid profile email&
  state=random_state&
  code_challenge=code_challenge&
  code_challenge_method=S256
```

3. **Token Request:**
```
POST /.well-known/oauth2/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=authorization_code&
code=authorization_code&
redirect_uri=https://myapp.com/callback&
code_verifier=code_verifier
```

4. **Token Response:**
```json
{
  "access_token": "access_token_123",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email",
  "refresh_token": "refresh_token_456",
  "id_token": "id_token_789"
}
```

### Device Authorization Flow

1. **Device Authorization Request:**
```
POST /.well-known/oauth2/device
Content-Type: application/x-www-form-urlencoded

client_id=client123&
scope=openid profile email
```

2. **Device Authorization Response:**
```json
{
  "device_code": "device_code_123",
  "user_code": "ABCD-EFGH",
  "verification_uri": "https://example.com/device",
  "verification_uri_complete": "https://example.com/device?user_code=ABCD-EFGH",
  "expires_in": 600,
  "interval": 5
}
```

3. **User Authorization:**
```
POST /.well-known/oauth2/device/complete
Content-Type: application/x-www-form-urlencoded

user_code=ABCD-EFGH&
email=user@example.com&
password=user_password
```

4. **Token Polling:**
```
POST /.well-known/oauth2/device/token
Content-Type: application/x-www-form-urlencoded

device_code=device_code_123&
client_id=client123
```

### Token Introspection

```
POST /.well-known/oauth2/introspect
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

token=access_token_123&
token_type_hint=access_token
```

### Token Revocation

```
POST /.well-known/oauth2/revoke
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

token=access_token_123&
token_type_hint=access_token
```

## Security Best Practices

1. **Always use HTTPS** in production
2. **Enable PKCE** for all public clients
3. **Validate state parameter** for all authorization requests
4. **Use nonce parameter** for implicit flows
5. **Implement proper token storage** on client side
6. **Use short-lived access tokens** and refresh tokens
7. **Implement token revocation** when users logout
8. **Log all OIDC events** for audit purposes
9. **Validate redirect URIs** strictly
10. **Use secure client secrets** and rotate them regularly

## Monitoring and Logging

The OIDC implementation provides comprehensive logging for:

- **Events**: Authorization, token issuance, revocation
- **Token Usage**: Access token usage patterns
- **Client Activity**: Client registration and usage
- **Errors**: Authentication and authorization errors
- **Debug**: Detailed debug information

All logs include timestamps, client IDs, user IDs, and relevant metadata for audit purposes.

## Testing

The implementation includes comprehensive test coverage for:

- **Authorization flows**: All supported grant types
- **Token validation**: Access tokens, refresh tokens, ID tokens
- **Security features**: PKCE, state validation, nonce validation
- **Client registration**: Dynamic client registration
- **Error handling**: Invalid requests and error responses

## Production Deployment

For production deployment:

1. **Use HTTPS** for all endpoints
2. **Configure proper CORS** settings
3. **Set up monitoring** and alerting
4. **Implement rate limiting** for all endpoints
5. **Use secure key management** for JWT signing keys
6. **Set up backup and recovery** procedures
7. **Monitor token usage** and client activity
8. **Implement proper logging** and log retention
9. **Set up security scanning** and vulnerability assessment
10. **Plan for key rotation** and certificate renewal

This implementation provides a complete, production-ready OIDC server that matches the capabilities of major OAuth2 providers like Google, with comprehensive security features, audit logging, and support for all standard OAuth2/OIDC flows. 