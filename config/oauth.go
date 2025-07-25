package config

import (
	"github.com/goravel/framework/facades"
)

func init() {
	config := facades.Config()
	config.Add("oauth", map[string]interface{}{
		// OAuth2 Defaults
		//
		// This option controls the default OAuth2 settings for your application.
		// You may change these defaults as required, but they're a perfect start
		// for most applications.

		// Access Token TTL in minutes (default: 60 minutes)
		"access_token_ttl": config.Env("OAUTH_ACCESS_TOKEN_TTL", 60),

		// Refresh Token TTL in minutes (default: 14 days)
		"refresh_token_ttl": config.Env("OAUTH_REFRESH_TOKEN_TTL", 20160),

		// Authorization Code TTL in minutes (default: 10 minutes)
		"auth_code_ttl": config.Env("OAUTH_AUTH_CODE_TTL", 10),

		// Personal Access Token TTL in minutes (default: 60 minutes)
		"personal_access_token_ttl": config.Env("OAUTH_PERSONAL_ACCESS_TOKEN_TTL", 60),

		// Client Secret Length (default: 40 characters)
		"client_secret_length": config.Env("OAUTH_CLIENT_SECRET_LENGTH", 40),

		// Token ID Length (default: 40 characters)
		"token_id_length": config.Env("OAUTH_TOKEN_ID_LENGTH", 40),

		// Default Scopes
		"default_scopes": []string{
			"profile",
			"email",
		},

		// Allowed Scopes (Google-like scope structure)
		"allowed_scopes": []string{
			// Basic profile scopes
			"profile",
			"email",
			"openid",

			// User management scopes
			"user:read",
			"user:write",
			"user:delete",

			// Application scopes
			"read",
			"write",
			"delete",
			"admin",

			// Calendar scopes
			"calendar:read",
			"calendar:write",
			"calendar:events",

			// Chat scopes
			"chat:read",
			"chat:write",
			"chat:rooms",

			// Task management scopes
			"tasks:read",
			"tasks:write",
			"tasks:manage",

			// Organization scopes
			"org:read",
			"org:write",
			"org:admin",
		},

		// Enable Password Grant (default: true)
		"enable_password_grant": config.Env("OAUTH_ENABLE_PASSWORD_GRANT", true),

		// Enable Client Credentials Grant (default: true)
		"enable_client_credentials_grant": config.Env("OAUTH_ENABLE_CLIENT_CREDENTIALS_GRANT", true),

		// Enable Authorization Code Grant (default: true)
		"enable_authorization_code_grant": config.Env("OAUTH_ENABLE_AUTHORIZATION_CODE_GRANT", true),

		// Enable Refresh Token Grant (default: true)
		"enable_refresh_token_grant": config.Env("OAUTH_ENABLE_REFRESH_TOKEN_GRANT", true),

		// Enable Personal Access Tokens (default: true)
		"enable_personal_access_tokens": config.Env("OAUTH_ENABLE_PERSONAL_ACCESS_TOKENS", true),

		// Require Client Secret for Public Clients (default: false)
		"require_client_secret_for_public_clients": config.Env("OAUTH_REQUIRE_CLIENT_SECRET_FOR_PUBLIC_CLIENTS", false),

		// Enable Token Revocation (default: true)
		"enable_token_revocation": config.Env("OAUTH_ENABLE_TOKEN_REVOCATION", true),

		// Enable Token Introspection (default: true)
		"enable_token_introspection": config.Env("OAUTH_ENABLE_TOKEN_INTROSPECTION", true),

		// Enable Scope Validation (default: true)
		"enable_scope_validation": config.Env("OAUTH_ENABLE_SCOPE_VALIDATION", true),

		// Enable Redirect URI Validation (default: true)
		"enable_redirect_uri_validation": config.Env("OAUTH_ENABLE_REDIRECT_URI_VALIDATION", true),

		// Enable State Parameter (default: true)
		"enable_state_parameter": config.Env("OAUTH_ENABLE_STATE_PARAMETER", true),

		// Enable PKCE (Proof Key for Code Exchange) (default: true)
		"enable_pkce": config.Env("OAUTH_ENABLE_PKCE", true),

		// Enable Implicit Grant (default: false - deprecated)
		"enable_implicit_grant": config.Env("OAUTH_ENABLE_IMPLICIT_GRANT", false),

		// Enable Device Authorization Grant (default: true)
		"enable_device_authorization_grant": config.Env("OAUTH_ENABLE_DEVICE_AUTHORIZATION_GRANT", true),

		// Enable Token Exchange (default: true)
		"enable_token_exchange": config.Env("OAUTH_ENABLE_TOKEN_EXCHANGE", true),

		// Device Authorization Settings
		"device_code_ttl":         config.Env("OAUTH_DEVICE_CODE_TTL", 600),       // 10 minutes in seconds
		"device_polling_interval": config.Env("OAUTH_DEVICE_POLLING_INTERVAL", 5), // 5 seconds
		"device_verification_uri": config.Env("OAUTH_DEVICE_VERIFICATION_URI", "https://example.com/device"),

		// Enable Token Revocation on Logout (default: true)
		"enable_token_revocation_on_logout": config.Env("OAUTH_ENABLE_TOKEN_REVOCATION_ON_LOGOUT", true),

		// Enable Token Refresh on Access Token Expiry (default: true)
		"enable_token_refresh_on_expiry": config.Env("OAUTH_ENABLE_TOKEN_REFRESH_ON_EXPIRY", true),

		// Enable Token Rotation (default: false)
		"enable_token_rotation": config.Env("OAUTH_ENABLE_TOKEN_ROTATION", false),

		// Enable Token Binding (default: false)
		"enable_token_binding": config.Env("OAUTH_ENABLE_TOKEN_BINDING", false),

		// Enable Token Introspection Caching (default: true)
		"enable_token_introspection_caching": config.Env("OAUTH_ENABLE_TOKEN_INTROSPECTION_CACHING", true),

		// Token Introspection Cache TTL in minutes (default: 5 minutes)
		"token_introspection_cache_ttl": config.Env("OAUTH_TOKEN_INTROSPECTION_CACHE_TTL", 5),

		// Enable Rate Limiting (default: true)
		"enable_rate_limiting": config.Env("OAUTH_ENABLE_RATE_LIMITING", true),

		// Rate Limiting Settings
		"rate_limiting": map[string]interface{}{
			// Authorization endpoint rate limit
			"authorization_requests_per_minute": config.Env("OAUTH_RATE_LIMIT_AUTHORIZATION", 60),

			// Token endpoint rate limit
			"token_requests_per_minute": config.Env("OAUTH_RATE_LIMIT_TOKEN", 60),

			// Introspection endpoint rate limit
			"introspection_requests_per_minute": config.Env("OAUTH_RATE_LIMIT_INTROSPECTION", 120),

			// Revocation endpoint rate limit
			"revocation_requests_per_minute": config.Env("OAUTH_RATE_LIMIT_REVOCATION", 60),

			// Client registration rate limit
			"client_registration_requests_per_minute": config.Env("OAUTH_RATE_LIMIT_CLIENT_REGISTRATION", 10),
		},

		// Security Settings
		"security": map[string]interface{}{
			// Require HTTPS for all OAuth endpoints (default: true in production)
			"require_https": config.Env("OAUTH_REQUIRE_HTTPS", true),

			// Require PKCE for public clients (default: true)
			"require_pkce_for_public_clients": config.Env("OAUTH_REQUIRE_PKCE_FOR_PUBLIC_CLIENTS", true),

			// Require state parameter for authorization code grant (default: true)
			"require_state_parameter": config.Env("OAUTH_REQUIRE_STATE_PARAMETER", true),

			// Require nonce parameter for implicit grant (default: true)
			"require_nonce_parameter": config.Env("OAUTH_REQUIRE_NONCE_PARAMETER", true),

			// Require client authentication for confidential clients (default: true)
			"require_client_authentication": config.Env("OAUTH_REQUIRE_CLIENT_AUTHENTICATION", true),

			// Require scope validation (default: true)
			"require_scope_validation": config.Env("OAUTH_REQUIRE_SCOPE_VALIDATION", true),

			// Require redirect URI validation (default: true)
			"require_redirect_uri_validation": config.Env("OAUTH_REQUIRE_REDIRECT_URI_VALIDATION", true),

			// Require token binding (default: false)
			"require_token_binding": config.Env("OAUTH_REQUIRE_TOKEN_BINDING", false),

			// Require token rotation (default: false)
			"require_token_rotation": config.Env("OAUTH_REQUIRE_TOKEN_ROTATION", false),
		},

		// JWT Settings
		"jwt": map[string]interface{}{
			// Enable JWT access tokens (default: true)
			"enable_jwt_tokens": config.Env("OAUTH_ENABLE_JWT_TOKENS", true),

			// JWT signing algorithm (default: RS256)
			"signing_algorithm": config.Env("OAUTH_JWT_ALGORITHM", "RS256"),

			// RSA private key for JWT signing (PEM format)
			"rsa_private_key": config.Env("OAUTH_RSA_PRIVATE_KEY", ""),

			// RSA public key for JWT verification (PEM format)
			"rsa_public_key": config.Env("OAUTH_RSA_PUBLIC_KEY", ""),

			// JWT issuer claim
			"issuer": config.Env("OAUTH_JWT_ISSUER", config.Env("APP_URL")),
		},

		// Advanced Security Settings
		"advanced_security": map[string]interface{}{
			// Enable suspicious activity detection (default: true)
			"enable_suspicious_activity_detection": config.Env("OAUTH_ENABLE_SUSPICIOUS_ACTIVITY_DETECTION", true),

			// Suspicious activity threshold score (default: 50)
			"suspicious_activity_threshold": config.Env("OAUTH_SUSPICIOUS_ACTIVITY_THRESHOLD", 50),

			// Enable geo-blocking (default: false)
			"enable_geo_blocking": config.Env("OAUTH_ENABLE_GEO_BLOCKING", false),

			// Allowed countries for geo-blocking (comma-separated)
			"allowed_countries": config.Env("OAUTH_ALLOWED_COUNTRIES", ""),

			// Enable device fingerprinting (default: false)
			"enable_device_fingerprinting": config.Env("OAUTH_ENABLE_DEVICE_FINGERPRINTING", false),

			// Maximum failed attempts before temporary lockout
			"max_failed_attempts": config.Env("OAUTH_MAX_FAILED_ATTEMPTS", 5),

			// Lockout duration in minutes
			"lockout_duration_minutes": config.Env("OAUTH_LOCKOUT_DURATION", 30),
		},

		// OAuth2 Playground Settings
		"playground": map[string]interface{}{
			// Enable OAuth2 playground (default: true in development)
			"enabled": config.Env("OAUTH_PLAYGROUND_ENABLED", config.Env("APP_ENV") == "local"),

			// Default redirect URI for playground
			"default_redirect_uri": config.Env("OAUTH_PLAYGROUND_REDIRECT_URI", "http://localhost:8080/oauth/playground/callback"),

			// Auto-create playground client (default: true)
			"auto_create_client": config.Env("OAUTH_PLAYGROUND_AUTO_CREATE_CLIENT", true),
		},

		// Device Authorization Enhanced Settings
		"device_authorization": map[string]interface{}{
			// Enable QR code generation for device flow
			"enable_qr_codes": config.Env("OAUTH_DEVICE_ENABLE_QR_CODES", true),

			// QR code service URL template
			"qr_code_service": config.Env("OAUTH_DEVICE_QR_CODE_SERVICE", "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=%s"),

			// Custom verification URI
			"verification_uri": config.Env("OAUTH_DEVICE_VERIFICATION_URI", config.Env("APP_URL", "http://localhost").(string)+"/device"),

			// Device code format (default: 8 characters, uppercase)
			"user_code_format": config.Env("OAUTH_DEVICE_USER_CODE_FORMAT", "XXXXXXXX"),
		},

		// Analytics and Monitoring
		"analytics": map[string]interface{}{
			// Enable OAuth2 analytics (default: true)
			"enabled": config.Env("OAUTH_ANALYTICS_ENABLED", true),

			// Analytics data retention in days
			"retention_days": config.Env("OAUTH_ANALYTICS_RETENTION_DAYS", 90),

			// Enable real-time metrics
			"enable_real_time_metrics": config.Env("OAUTH_ENABLE_REAL_TIME_METRICS", true),

			// Metrics collection interval in seconds
			"metrics_interval_seconds": config.Env("OAUTH_METRICS_INTERVAL", 60),
		},

		// Webhook Settings
		"webhooks": map[string]interface{}{
			// Enable webhook notifications (default: false)
			"enabled": config.Env("OAUTH_WEBHOOKS_ENABLED", false),

			// Webhook endpoints for different events
			"endpoints": map[string]string{
				"token_created":       config.Env("OAUTH_WEBHOOK_TOKEN_CREATED", "").(string),
				"token_revoked":       config.Env("OAUTH_WEBHOOK_TOKEN_REVOKED", "").(string),
				"client_created":      config.Env("OAUTH_WEBHOOK_CLIENT_CREATED", "").(string),
				"suspicious_activity": config.Env("OAUTH_WEBHOOK_SUSPICIOUS_ACTIVITY", "").(string),
			},

			// Webhook timeout in seconds
			"timeout_seconds": config.Env("OAUTH_WEBHOOK_TIMEOUT", 30),

			// Webhook retry attempts
			"retry_attempts": config.Env("OAUTH_WEBHOOK_RETRY_ATTEMPTS", 3),
		},

		// Multi-tenant Settings
		"multi_tenant": map[string]interface{}{
			// Enable multi-tenant OAuth2 (default: false)
			"enabled": config.Env("OAUTH_MULTI_TENANT_ENABLED", false),

			// Tenant isolation mode: "strict" or "shared"
			"isolation_mode": config.Env("OAUTH_TENANT_ISOLATION_MODE", "strict"),

			// Enable cross-tenant access (default: false)
			"enable_cross_tenant_access": config.Env("OAUTH_ENABLE_CROSS_TENANT_ACCESS", false),
		},

		// Logging Settings
		"logging": map[string]interface{}{
			// Enable OAuth event logging (default: true)
			"enable_event_logging": config.Env("OAUTH_ENABLE_EVENT_LOGGING", true),

			// Enable token usage logging (default: true)
			"enable_token_usage_logging": config.Env("OAUTH_ENABLE_TOKEN_USAGE_LOGGING", true),

			// Enable client activity logging (default: true)
			"enable_client_activity_logging": config.Env("OAUTH_ENABLE_CLIENT_ACTIVITY_LOGGING", true),

			// Enable error logging (default: true)
			"enable_error_logging": config.Env("OAUTH_ENABLE_ERROR_LOGGING", true),

			// Enable debug logging (default: false)
			"enable_debug_logging": config.Env("OAUTH_ENABLE_DEBUG_LOGGING", false),
		},
	})
}
