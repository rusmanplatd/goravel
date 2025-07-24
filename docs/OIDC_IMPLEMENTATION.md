# OpenID Connect (OIDC) Implementation

This document describes the OpenID Connect implementation in Goravel, which provides a complete OIDC server similar to Google's implementation.

## Overview

The OIDC implementation provides:

- **OIDC Discovery**: Automatic discovery of OIDC endpoints and capabilities
- **Authorization Code Flow**: Secure authorization with PKCE support
- **ID Tokens**: JWT-based identity tokens with user claims
- **User Info Endpoint**: Access to user profile information
- **JWKS Endpoint**: Public keys for token validation
- **Session Management**: End session and check session endpoints
- **Multiple Grant Types**: Support for various OAuth2/OIDC flows

## Architecture

### Core Components

1. **OIDC Service** (`app/services/oidc_service.go`)
   - Handles OIDC-specific operations
   - Generates and validates ID tokens
   - Manages JWKS (JSON Web Key Set)
   - Provides discovery document

2. **OIDC Controller** (`app/http/controllers/api/v1/oidc_controller.go`)
   - Exposes OIDC endpoints
   - Handles authorization flows
   - Manages token exchange
   - Provides user info

3. **OIDC Configuration** (`config/oidc.go`)
   - Comprehensive OIDC settings
   - Security configurations
   - Supported features and algorithms

## Endpoints

### Discovery Endpoint
```
GET /.well-known/openid_configuration
```
Returns the OIDC discovery document with all supported features, endpoints, and capabilities.

### Authorization Endpoint
```
GET /.well-known/oauth2/authorize
```
Handles OIDC authorization requests with support for:
- Authorization code flow
- PKCE (Proof Key for Code Exchange)
- State and nonce parameters
- Scope validation

### Token Endpoint
```
POST /.well-known/oauth2/token
```
Exchanges authorization codes for tokens:
- Access tokens
- ID tokens
- Refresh tokens
- PKCE validation

### User Info Endpoint
```
GET /.well-known/oauth2/userinfo
```
Returns user profile information based on the access token and requested scopes.

### JWKS Endpoint
```
GET /.well-known/oauth2/jwks
```
Provides public keys for token validation.

### End Session Endpoint
```
GET /.well-known/oauth2/end_session
```
Handles OIDC logout requests with post-logout redirect support.

### Check Session Endpoint
```
GET /.well-known/oauth2/check_session
```
Provides session status checking for SPAs.

## Configuration

### OIDC Settings

The OIDC configuration is defined in `config/oidc.go`:

```go
// Issuer URL
"issuer": "https://your-domain.com"

// Supported response types
"response_types_supported": ["code", "token", "id_token", "code token", "code id_token"]

// Supported scopes
"scopes_supported": ["openid", "profile", "email", "address", "phone", "offline_access"]

// Supported grant types
"grant_types_supported": ["authorization_code", "implicit", "refresh_token", "password", "client_credentials"]

// Security settings
"security": {
    "require_https": true,
    "require_pkce_for_public_clients": true,
    "require_state_parameter": true
}
```

### Environment Variables

```bash
# OIDC Issuer URL
OIDC_ISSUER=https://your-domain.com

# ID Token lifetime (minutes)
OIDC_ID_TOKEN_LIFETIME=60

# Security settings
OIDC_REQUIRE_HTTPS=true
OIDC_REQUIRE_PKCE_FOR_PUBLIC_CLIENTS=true
OIDC_REQUIRE_STATE_PARAMETER=true

# Logging
OIDC_ENABLE_EVENT_LOGGING=true
OIDC_ENABLE_DEBUG_LOGGING=false
```

## Usage Examples

### 1. OIDC Discovery

```javascript
// Discover OIDC configuration
const response = await fetch('https://your-domain.com/.well-known/openid_configuration');
const config = await response.json();

console.log('Authorization endpoint:', config.authorization_endpoint);
console.log('Token endpoint:', config.token_endpoint);
console.log('User info endpoint:', config.userinfo_endpoint);
console.log('JWKS endpoint:', config.jwks_uri);
```

### 2. Authorization Flow

```javascript
// Generate PKCE parameters
const codeVerifier = generateRandomString(32);
const codeChallenge = await generateCodeChallenge(codeVerifier);

// Build authorization URL
const authUrl = `${config.authorization_endpoint}?` +
    `response_type=code&` +
    `client_id=${clientId}&` +
    `redirect_uri=${redirectUri}&` +
    `scope=openid profile email&` +
    `state=${state}&` +
    `nonce=${nonce}&` +
    `code_challenge=${codeChallenge}&` +
    `code_challenge_method=S256`;

// Redirect user to authorization
window.location.href = authUrl;
```

### 3. Token Exchange

```javascript
// Exchange authorization code for tokens
const formData = new FormData();
formData.append('grant_type', 'authorization_code');
formData.append('client_id', clientId);
formData.append('code', authorizationCode);
formData.append('redirect_uri', redirectUri);
formData.append('code_verifier', codeVerifier);

const response = await fetch(config.token_endpoint, {
    method: 'POST',
    body: formData
});

const tokens = await response.json();
console.log('Access token:', tokens.access_token);
console.log('ID token:', tokens.id_token);
console.log('Refresh token:', tokens.refresh_token);
```

### 4. User Info

```javascript
// Get user information
const response = await fetch(config.userinfo_endpoint, {
    headers: {
        'Authorization': `Bearer ${accessToken}`
    }
});

const userInfo = await response.json();
console.log('User name:', userInfo.name);
console.log('User email:', userInfo.email);
console.log('User profile:', userInfo.profile);
```

### 5. ID Token Validation

```javascript
// Validate ID token using JWKS
const jwksResponse = await fetch(config.jwks_uri);
const jwks = await jwksResponse.json();

// Decode and validate ID token
const decodedToken = jwt.verify(idToken, jwks.keys[0], {
    algorithms: ['RS256'],
    issuer: config.issuer,
    audience: clientId
});

console.log('Token subject:', decodedToken.sub);
console.log('Token issuer:', decodedToken.iss);
console.log('Token audience:', decodedToken.aud);
```

## Security Features

### PKCE Support
- **Code Challenge**: SHA256 hash of code verifier
- **Code Verifier**: Random string generated by client
- **Validation**: Server validates code verifier against challenge

### Token Security
- **RSA256 Signing**: ID tokens signed with RSA keys
- **Key Rotation**: Support for multiple signing keys
- **Token Expiration**: Configurable token lifetimes
- **Scope Validation**: Strict scope checking

### Client Security
- **Redirect URI Validation**: Strict URI matching
- **State Parameter**: CSRF protection
- **Nonce Validation**: Replay attack prevention
- **HTTPS Enforcement**: Production security requirement

## Supported Scopes

### Standard OIDC Scopes
- `openid`: Required for OIDC flows
- `profile`: Basic profile information
- `email`: Email address and verification status
- `address`: Address information
- `phone`: Phone number and verification status
- `offline_access`: Refresh token access

### Custom Scopes
- `read`: Read access to resources
- `write`: Write access to resources
- `delete`: Delete access to resources
- `admin`: Administrative access

## Client Types

### Public Clients
- No client secret required
- PKCE mandatory for security
- Suitable for SPAs and mobile apps

### Confidential Clients
- Client secret required
- Server-side token exchange
- Suitable for web applications

## Error Handling

### Standard OIDC Errors
- `invalid_request`: Missing or invalid parameters
- `invalid_client`: Invalid client credentials
- `invalid_grant`: Invalid authorization code
- `invalid_scope`: Invalid or unsupported scope
- `invalid_token`: Invalid access token
- `server_error`: Internal server error

### Error Response Format
```json
{
    "error": "invalid_request",
    "error_description": "Missing required parameter: client_id",
    "state": "optional_state_parameter"
}
```

## Logging and Monitoring

### Event Logging
- Authorization requests
- Token exchanges
- User info requests
- Session management
- Error events

### Audit Trail
- Client activity tracking
- User authentication events
- Token usage monitoring
- Security event logging

## Testing

### Test Client
Use the provided test client in `examples/oidc_client_example.html` to test the OIDC implementation.

### Test Endpoints
```bash
# Test discovery
curl https://your-domain.com/.well-known/openid_configuration

# Test JWKS
curl https://your-domain.com/.well-known/oauth2/jwks

# Test user info (with access token)
curl -H "Authorization: Bearer YOUR_ACCESS_TOKEN" \
     https://your-domain.com/.well-known/oauth2/userinfo
```

## Production Considerations

### Security
1. **HTTPS Only**: Enforce HTTPS in production
2. **Key Management**: Secure key storage and rotation
3. **Rate Limiting**: Implement rate limiting on endpoints
4. **CORS Configuration**: Proper CORS settings for web clients
5. **Token Binding**: Consider token binding for additional security

### Performance
1. **Caching**: Cache discovery document and JWKS
2. **Database Optimization**: Optimize token and code storage
3. **Load Balancing**: Distribute OIDC endpoints across servers
4. **Monitoring**: Monitor endpoint performance and errors

### Compliance
1. **OIDC Compliance**: Ensure full OIDC specification compliance
2. **Privacy**: Implement proper data handling and privacy controls
3. **Audit**: Regular security audits and penetration testing
4. **Documentation**: Maintain up-to-date client documentation

## Integration Examples

### React Application
```javascript
import { AuthProvider } from 'react-oidc-context';

const oidcConfig = {
    authority: 'https://your-domain.com',
    client_id: 'your-client-id',
    redirect_uri: 'http://localhost:3000/callback',
    scope: 'openid profile email',
    response_type: 'code',
    code_challenge_method: 'S256'
};

function App() {
    return (
        <AuthProvider {...oidcConfig}>
            <YourApp />
        </AuthProvider>
    );
}
```

### Node.js Backend
```javascript
const { Issuer } = require('openid-client');

async function setupOIDC() {
    const issuer = await Issuer.discover('https://your-domain.com/.well-known/openid_configuration');
    
    const client = new issuer.Client({
        client_id: 'your-client-id',
        client_secret: 'your-client-secret',
        redirect_uris: ['http://localhost:3000/callback'],
        response_types: ['code']
    });
    
    return client;
}
```

### Mobile Application (React Native)
```javascript
import { authorize, refresh, revoke } from 'react-native-app-auth';

const config = {
    issuer: 'https://your-domain.com',
    clientId: 'your-client-id',
    redirectUrl: 'com.yourapp://oauth/callback',
    scopes: ['openid', 'profile', 'email'],
    additionalParameters: {},
    serviceConfiguration: {
        authorizationEndpoint: 'https://your-domain.com/.well-known/oauth2/authorize',
        tokenEndpoint: 'https://your-domain.com/.well-known/oauth2/token',
        revocationEndpoint: 'https://your-domain.com/.well-known/oauth2/revoke'
    }
};

const result = await authorize(config);
```

## Troubleshooting

### Common Issues

1. **CORS Errors**: Configure proper CORS headers for web clients
2. **Redirect URI Mismatch**: Ensure exact URI matching
3. **PKCE Validation**: Verify code challenge and verifier
4. **Token Expiration**: Check token lifetimes and refresh logic
5. **Scope Issues**: Validate requested scopes against allowed scopes

### Debug Mode
Enable debug logging to troubleshoot issues:
```bash
OIDC_ENABLE_DEBUG_LOGGING=true
```

### Health Checks
Monitor OIDC endpoint health:
```bash
# Discovery endpoint
curl -f https://your-domain.com/.well-known/openid_configuration

# JWKS endpoint
curl -f https://your-domain.com/.well-known/oauth2/jwks
```

## Conclusion

This OIDC implementation provides a complete, production-ready OpenID Connect server with enterprise-grade security features. It supports all major OIDC flows and can be easily integrated with various client applications.

For additional support or questions, refer to the OIDC specification or contact the development team. 