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

		// Allowed Scopes (Google-like scope structure with hierarchical support)
		"allowed_scopes": []string{
			// OpenID Connect scopes
			"openid",
			"profile",
			"email",
			"address",
			"phone",

			// Google-like hierarchical user scopes
			"user:read",
			"user:write",
			"user:delete",
			"user:profile",
			"user:email",
			"user:phone",
			"user:address",

			// Application-level scopes
			"read",
			"write",
			"delete",
			"admin",

			// Calendar scopes (Google Calendar-like)
			"calendar",
			"calendar:read",
			"calendar:write",
			"calendar:events",
			"calendar:events:read",
			"calendar:events:write",
			"calendar:events:delete",

			// Chat scopes (Google Chat-like)
			"chat",
			"chat:read",
			"chat:write",
			"chat:rooms",
			"chat:rooms:read",
			"chat:rooms:write",
			"chat:messages",
			"chat:messages:read",
			"chat:messages:write",

			// Task management scopes (Google Tasks-like)
			"tasks",
			"tasks:read",
			"tasks:write",
			"tasks:manage",
			"tasks:delete",

			// Organization scopes (Google Workspace-like)
			"org",
			"org:read",
			"org:write",
			"org:admin",
			"org:members",
			"org:members:read",
			"org:members:write",

			// Drive-like file scopes
			"files",
			"files:read",
			"files:write",
			"files:delete",
			"files:share",

			// Analytics scopes
			"analytics",
			"analytics:read",
			"analytics:reports",

			// Audit and security scopes
			"audit",
			"audit:read",
			"security",
			"security:read",
			"security:write",
		},

		// Scope hierarchies (parent scopes automatically include child scopes)
		"scope_hierarchies": map[string][]string{
			"user":                  {"user:read", "user:write", "user:profile", "user:email", "user:phone", "user:address"},
			"user:write":            {"user:read"},
			"calendar":              {"calendar:read", "calendar:write", "calendar:events"},
			"calendar:write":        {"calendar:read"},
			"calendar:events":       {"calendar:events:read", "calendar:events:write", "calendar:events:delete"},
			"calendar:events:write": {"calendar:events:read"},
			"chat":                  {"chat:read", "chat:write", "chat:rooms", "chat:messages"},
			"chat:write":            {"chat:read"},
			"chat:rooms":            {"chat:rooms:read", "chat:rooms:write"},
			"chat:rooms:write":      {"chat:rooms:read"},
			"chat:messages":         {"chat:messages:read", "chat:messages:write"},
			"chat:messages:write":   {"chat:messages:read"},
			"tasks":                 {"tasks:read", "tasks:write", "tasks:manage", "tasks:delete"},
			"tasks:write":           {"tasks:read"},
			"tasks:manage":          {"tasks:read", "tasks:write"},
			"org":                   {"org:read", "org:write", "org:members"},
			"org:write":             {"org:read"},
			"org:admin":             {"org:read", "org:write", "org:members"},
			"org:members":           {"org:members:read", "org:members:write"},
			"org:members:write":     {"org:members:read"},
			"files":                 {"files:read", "files:write", "files:delete", "files:share"},
			"files:write":           {"files:read"},
			"analytics":             {"analytics:read", "analytics:reports"},
			"audit":                 {"audit:read"},
			"security":              {"security:read", "security:write"},
			"security:write":        {"security:read"},
			"admin":                 {"user", "calendar", "chat", "tasks", "org", "files", "analytics", "audit", "security"},
		},

		// Scope descriptions for consent screens
		"scope_descriptions": map[string]map[string]string{
			"openid": {
				"title":       "Sign you in",
				"description": "Allow this app to sign you in and access your basic profile information",
				"sensitive":   "false",
			},
			"profile": {
				"title":       "View your profile",
				"description": "View your name, profile picture, and other basic profile information",
				"sensitive":   "false",
			},
			"email": {
				"title":       "View your email address",
				"description": "View your email address",
				"sensitive":   "false",
			},
			"user:read": {
				"title":       "View your user information",
				"description": "View your user profile, settings, and preferences",
				"sensitive":   "false",
			},
			"user:write": {
				"title":       "Modify your user information",
				"description": "Update your user profile, settings, and preferences",
				"sensitive":   "true",
			},
			"calendar:read": {
				"title":       "View your calendar",
				"description": "View your calendar events and availability",
				"sensitive":   "false",
			},
			"calendar:write": {
				"title":       "Manage your calendar",
				"description": "Create, update, and delete calendar events",
				"sensitive":   "true",
			},
			"chat:read": {
				"title":       "View your messages",
				"description": "View your chat messages and conversation history",
				"sensitive":   "true",
			},
			"chat:write": {
				"title":       "Send messages",
				"description": "Send messages and participate in conversations",
				"sensitive":   "true",
			},
			"org:admin": {
				"title":       "Administer organization",
				"description": "Full administrative access to organization settings and members",
				"sensitive":   "true",
			},
			"admin": {
				"title":       "Full administrative access",
				"description": "Complete access to all features and data",
				"sensitive":   "true",
			},
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

		// Implicit Grant has been removed for security reasons
		// Use Authorization Code flow with PKCE instead
		// "enable_implicit_grant": false, // REMOVED - deprecated and insecure

		// Enable Device Authorization Grant (default: true)
		"enable_device_authorization_grant": config.Env("OAUTH_ENABLE_DEVICE_AUTHORIZATION_GRANT", true),

		// Enable Token Exchange (default: true)
		"enable_token_exchange": config.Env("OAUTH_ENABLE_TOKEN_EXCHANGE", true),

		// Enable Pushed Authorization Requests (PAR) RFC 9126 (default: true)
		"enable_pushed_authorization_requests": config.Env("OAUTH_ENABLE_PAR", true),

		// JWT Bearer Grant (default: true)
		"enable_jwt_bearer_grant": config.Env("OAUTH_ENABLE_JWT_BEARER_GRANT", true),

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
			// Require HTTPS for all OAuth endpoints (enforced in production)
			"require_https": config.Env("OAUTH_REQUIRE_HTTPS", config.Env("APP_ENV", "local") == "production"),

			// Require PKCE for public clients (default: true) - Google-like enforcement
			"require_pkce_for_public_clients": config.Env("OAUTH_REQUIRE_PKCE_FOR_PUBLIC_CLIENTS", true),

			// Require PKCE for all clients (default: false) - Ultra-strict mode
			"require_pkce_for_all_clients": config.Env("OAUTH_REQUIRE_PKCE_FOR_ALL_CLIENTS", false),

			// Discourage plain PKCE method in favor of S256 (default: true) - Google-like preference
			"discourage_plain_pkce": config.Env("OAUTH_DISCOURAGE_PLAIN_PKCE", true),

			// Risk Assessment Settings (Google-like)
			"enable_risk_assessment": config.Env("OAUTH_ENABLE_RISK_ASSESSMENT", true),
			"risk_threshold_mfa":     config.Env("OAUTH_RISK_THRESHOLD_MFA", 30),   // Require MFA above this score
			"risk_threshold_block":   config.Env("OAUTH_RISK_THRESHOLD_BLOCK", 80), // Block access above this score
			"bad_ips":                []string{},                                   // List of known bad IPs
			"high_risk_countries":    []string{"CN", "RU", "KP", "IR"},             // High-risk country codes

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

		// Device Authorization Enhanced Settings
		"device_authorization": map[string]interface{}{
			"verification_uri":          config.Env("OAUTH_DEVICE_VERIFICATION_URI", "http://localhost:3000/device"),
			"verification_uri_complete": config.Env("OAUTH_DEVICE_VERIFICATION_URI_COMPLETE", ""),
			"user_code_charset":         config.Env("OAUTH_DEVICE_USER_CODE_CHARSET", "BCDFGHJKLMNPQRSTVWXZ"),
			"user_code_length":          config.Env("OAUTH_DEVICE_USER_CODE_LENGTH", 8),
			"polling_interval":          config.Env("OAUTH_DEVICE_POLLING_INTERVAL", 5),
		},

		// Pushed Authorization Requests (PAR) Settings
		"par": map[string]interface{}{
			"request_ttl":      config.Env("OAUTH_PAR_REQUEST_TTL", 600),       // 10 minutes default
			"require_par":      config.Env("OAUTH_REQUIRE_PAR", false),         // Require PAR for all authorization requests
			"cleanup_interval": config.Env("OAUTH_PAR_CLEANUP_INTERVAL", 3600), // 1 hour cleanup interval
		},

		// Client Attestation Settings (Google-like mobile app security)
		"client_attestation": map[string]interface{}{
			"enabled":                    config.Env("OAUTH_CLIENT_ATTESTATION_ENABLED", false),
			"require_for_public_clients": config.Env("OAUTH_CLIENT_ATTESTATION_REQUIRE_PUBLIC", true),
			"require_for_all_clients":    config.Env("OAUTH_CLIENT_ATTESTATION_REQUIRE_ALL", false),
			"max_age_seconds":            config.Env("OAUTH_CLIENT_ATTESTATION_MAX_AGE", 300),       // 5 minutes
			"challenge_ttl_seconds":      config.Env("OAUTH_CLIENT_ATTESTATION_CHALLENGE_TTL", 600), // 10 minutes
			"trusted_issuers":            []string{},                                                // Add trusted attestation service issuers
			"custom_required_claims":     []string{},                                                // Required claims for custom attestation
			"android_package_names":      []string{},                                                // Allowed Android package names
			"ios_bundle_ids":             []string{},                                                // Allowed iOS bundle IDs
		},

		// Hierarchical Scopes Settings (Google-like fine-grained permissions)
		"hierarchical_scopes": map[string]interface{}{
			"enabled":                      config.Env("OAUTH_HIERARCHICAL_SCOPES_ENABLED", true),
			"auto_optimize":                config.Env("OAUTH_HIERARCHICAL_SCOPES_AUTO_OPTIMIZE", true),
			"strict_validation":            config.Env("OAUTH_HIERARCHICAL_SCOPES_STRICT_VALIDATION", true),
			"include_permissions_in_token": config.Env("OAUTH_HIERARCHICAL_SCOPES_INCLUDE_PERMISSIONS", true),
			"include_resources_in_token":   config.Env("OAUTH_HIERARCHICAL_SCOPES_INCLUDE_RESOURCES", true),
			"log_scope_validation":         config.Env("OAUTH_HIERARCHICAL_SCOPES_LOG_VALIDATION", true),
			"cache_hierarchy":              config.Env("OAUTH_HIERARCHICAL_SCOPES_CACHE", true),
			"hierarchy_version":            config.Env("OAUTH_HIERARCHICAL_SCOPES_VERSION", "1.0"),
		},

		// Token Binding Settings (RFC 8473)
		"token_binding": map[string]interface{}{
			"enabled":                      config.Env("OAUTH_TOKEN_BINDING_ENABLED", false),
			"require_for_sensitive_scopes": config.Env("OAUTH_TOKEN_BINDING_REQUIRE_SENSITIVE", false),
			"support_mtls":                 config.Env("OAUTH_TOKEN_BINDING_SUPPORT_MTLS", true),
			"support_dpop":                 config.Env("OAUTH_TOKEN_BINDING_SUPPORT_DPOP", true),
			"support_token_binding":        config.Env("OAUTH_TOKEN_BINDING_SUPPORT_TB", false),
			"default_binding_method":       config.Env("OAUTH_TOKEN_BINDING_DEFAULT_METHOD", "dpop"),
			"binding_ttl":                  config.Env("OAUTH_TOKEN_BINDING_TTL", 3600), // 1 hour
			"cleanup_interval":             config.Env("OAUTH_TOKEN_BINDING_CLEANUP_INTERVAL", 3600),
			"log_validation":               config.Env("OAUTH_TOKEN_BINDING_LOG_VALIDATION", true),
			"supported_key_parameters": []string{
				"rsa2048", "ecdsap256", "ecdsap384",
			},
		},

		// Resource Indicators Settings (RFC 8707)
		"resource_indicators": map[string]interface{}{
			"enabled":                      config.Env("OAUTH_RESOURCE_INDICATORS_ENABLED", true),
			"multiple_resources_supported": config.Env("OAUTH_RESOURCE_INDICATORS_MULTIPLE", true),
			"resource_scoping_supported":   config.Env("OAUTH_RESOURCE_INDICATORS_SCOPING", true),
			"resource_specific_tokens":     config.Env("OAUTH_RESOURCE_INDICATORS_SPECIFIC_TOKENS", true),
			"default_token_format":         config.Env("OAUTH_RESOURCE_INDICATORS_TOKEN_FORMAT", "jwt"),
			"max_resources_per_request":    config.Env("OAUTH_RESOURCE_INDICATORS_MAX_RESOURCES", 10),
			"resource_discovery_enabled":   config.Env("OAUTH_RESOURCE_INDICATORS_DISCOVERY", true),
			"auto_register_resources":      config.Env("OAUTH_RESOURCE_INDICATORS_AUTO_REGISTER", false),
			"require_explicit_consent":     config.Env("OAUTH_RESOURCE_INDICATORS_REQUIRE_CONSENT", false),
			"log_authorization":            config.Env("OAUTH_RESOURCE_INDICATORS_LOG_AUTH", true),
			"supported_token_formats": []string{
				"jwt", "opaque",
			},
			"supported_binding_methods": []string{
				"mtls", "dpop", "token_binding",
			},
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

		// Multi-organization Settings
		"multi_organization": map[string]interface{}{
			// Enable multi-organization OAuth2 (default: false)
			"enabled": config.Env("OAUTH_MULTI_TENANT_ENABLED", false),

			// Organization isolation mode: "strict" or "shared"
			"isolation_mode": config.Env("OAUTH_TENANT_ISOLATION_MODE", "strict"),

			// Enable cross-organization access (default: false)
			"enable_cross_organization_access": config.Env("OAUTH_ENABLE_CROSS_TENANT_ACCESS", false),
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

		// DPoP (Demonstrating Proof-of-Possession) Configuration
		"dpop": map[string]interface{}{
			"enabled":              config.Env("OAUTH_DPOP_ENABLED", false),    // Enable DPoP support
			"max_age":              config.Env("OAUTH_DPOP_MAX_AGE", 60),       // Maximum age of DPoP proof in seconds
			"supported_algorithms": []string{"ES256", "RS256", "PS256"},        // Supported signing algorithms
			"require_ath":          config.Env("OAUTH_DPOP_REQUIRE_ATH", true), // Require access token hash in DPoP proof for resource servers
		},

		// JARM (JWT Secured Authorization Response Mode) Configuration
		"jarm": map[string]interface{}{
			"enabled":              config.Env("OAUTH_JARM_ENABLED", false),       // Enable JARM support
			"default_signing_alg":  config.Env("OAUTH_JARM_DEFAULT_ALG", "RS256"), // Default signing algorithm for JARM responses
			"supported_algorithms": []string{"RS256", "ES256", "PS256"},           // Supported signing algorithms
			"response_lifetime":    config.Env("OAUTH_JARM_LIFETIME", 600),        // JARM response lifetime in seconds
		},
	})
}
