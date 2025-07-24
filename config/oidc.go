package config

import (
	"github.com/goravel/framework/facades"
)

func init() {
	config := facades.Config()
	config.Add("oidc", map[string]interface{}{
		// OIDC Server Configuration
		//
		// This configuration controls the OpenID Connect server settings.
		// These settings are similar to Google's OIDC implementation.

		// Issuer URL (default: app URL)
		"issuer": config.Env("OIDC_ISSUER", config.GetString("app.url")),

		// Authorization endpoint
		"authorization_endpoint": config.Env("OIDC_AUTHORIZATION_ENDPOINT", "/.well-known/oauth2/authorize"),

		// Token endpoint
		"token_endpoint": config.Env("OIDC_TOKEN_ENDPOINT", "/.well-known/oauth2/token"),

		// Userinfo endpoint
		"userinfo_endpoint": config.Env("OIDC_USERINFO_ENDPOINT", "/.well-known/oauth2/userinfo"),

		// JWKS endpoint
		"jwks_endpoint": config.Env("OIDC_JWKS_ENDPOINT", "/.well-known/oauth2/jwks"),

		// End session endpoint
		"end_session_endpoint": config.Env("OIDC_END_SESSION_ENDPOINT", "/.well-known/oauth2/end_session"),

		// Check session iframe endpoint
		"check_session_iframe": config.Env("OIDC_CHECK_SESSION_IFRAME", "/.well-known/oauth2/check_session"),

		// Revocation endpoint
		"revocation_endpoint": config.Env("OIDC_REVOCATION_ENDPOINT", "/.well-known/oauth2/revoke"),

		// Introspection endpoint
		"introspection_endpoint": config.Env("OIDC_INTROSPECTION_ENDPOINT", "/.well-known/oauth2/introspect"),

		// Device authorization endpoint
		"device_authorization_endpoint": config.Env("OIDC_DEVICE_AUTHORIZATION_ENDPOINT", "/.well-known/oauth2/device"),

		// Supported response types
		"response_types_supported": []string{
			"code",
			"token",
			"id_token",
			"code token",
			"code id_token",
			"token id_token",
			"code token id_token",
		},

		// Supported subject types
		"subject_types_supported": []string{
			"public",
			"pairwise",
		},

		// Supported ID token signing algorithms
		"id_token_signing_alg_values_supported": []string{
			"RS256",
			"ES256",
			"PS256",
		},

		// Supported ID token encryption algorithms
		"id_token_encryption_alg_values_supported": []string{
			"RSA1_5",
			"RSA-OAEP",
			"A128KW",
			"A192KW",
			"A256KW",
		},

		// Supported ID token encryption encodings
		"id_token_encryption_enc_values_supported": []string{
			"A128CBC-HS256",
			"A192CBC-HS384",
			"A256CBC-HS512",
			"A128GCM",
			"A192GCM",
			"A256GCM",
		},

		// Supported userinfo signing algorithms
		"userinfo_signing_alg_values_supported": []string{
			"RS256",
			"ES256",
			"PS256",
		},

		// Supported userinfo encryption algorithms
		"userinfo_encryption_alg_values_supported": []string{
			"RSA1_5",
			"RSA-OAEP",
			"A128KW",
			"A192KW",
			"A256KW",
		},

		// Supported userinfo encryption encodings
		"userinfo_encryption_enc_values_supported": []string{
			"A128CBC-HS256",
			"A192CBC-HS384",
			"A256CBC-HS512",
			"A128GCM",
			"A192GCM",
			"A256GCM",
		},

		// Supported request object signing algorithms
		"request_object_signing_alg_values_supported": []string{
			"none",
			"RS256",
			"ES256",
			"PS256",
		},

		// Supported request object encryption algorithms
		"request_object_encryption_alg_values_supported": []string{
			"RSA1_5",
			"RSA-OAEP",
			"A128KW",
			"A192KW",
			"A256KW",
		},

		// Supported request object encryption encodings
		"request_object_encryption_enc_values_supported": []string{
			"A128CBC-HS256",
			"A192CBC-HS384",
			"A256CBC-HS512",
			"A128GCM",
			"A192GCM",
			"A256GCM",
		},

		// Supported token endpoint authentication methods
		"token_endpoint_auth_methods_supported": []string{
			"client_secret_post",
			"client_secret_basic",
			"client_secret_jwt",
			"private_key_jwt",
			"none",
		},

		// Supported token endpoint authentication signing algorithms
		"token_endpoint_auth_signing_alg_values_supported": []string{
			"RS256",
			"ES256",
			"PS256",
		},

		// Supported display values
		"display_values_supported": []string{
			"page",
			"popup",
			"touch",
			"wap",
		},

		// Supported claim types
		"claim_types_supported": []string{
			"normal",
			"aggregated",
			"distributed",
		},

		// Supported claims
		"claims_supported": []string{
			"sub",
			"iss",
			"name",
			"given_name",
			"family_name",
			"middle_name",
			"nickname",
			"preferred_username",
			"profile",
			"picture",
			"website",
			"email",
			"email_verified",
			"gender",
			"birthdate",
			"zoneinfo",
			"locale",
			"phone_number",
			"phone_number_verified",
			"address",
			"updated_at",
		},

		// Supported scopes
		"scopes_supported": []string{
			"openid",
			"profile",
			"email",
			"address",
			"phone",
			"offline_access",
		},

		// Supported grant types
		"grant_types_supported": []string{
			"authorization_code",
			"implicit",
			"refresh_token",
			"password",
			"client_credentials",
			"urn:ietf:params:oauth:grant-type:device_code",
			"urn:ietf:params:oauth:grant-type:token-exchange",
		},

		// Supported response modes
		"response_modes_supported": []string{
			"query",
			"fragment",
			"form_post",
		},

		// Supported code challenge methods
		"code_challenge_methods_supported": []string{
			"plain",
			"S256",
		},

		// Supported request parameter encryption algorithms
		"request_parameter_encryption_alg_values_supported": []string{
			"RSA1_5",
			"RSA-OAEP",
			"A128KW",
			"A192KW",
			"A256KW",
		},

		// Supported request parameter encryption encodings
		"request_parameter_encryption_enc_values_supported": []string{
			"A128CBC-HS256",
			"A192CBC-HS384",
			"A256CBC-HS512",
			"A128GCM",
			"A192GCM",
			"A256GCM",
		},

		// Service documentation URL
		"service_documentation": config.Env("OIDC_SERVICE_DOCUMENTATION", ""),

		// Claims locales supported
		"claims_locales_supported": []string{
			"en-US",
			"en-GB",
			"es-ES",
			"fr-FR",
			"de-DE",
			"it-IT",
			"pt-BR",
			"ja-JP",
			"ko-KR",
			"zh-CN",
			"zh-TW",
		},

		// UI locales supported
		"ui_locales_supported": []string{
			"en-US",
			"en-GB",
			"es-ES",
			"fr-FR",
			"de-DE",
			"it-IT",
			"pt-BR",
			"ja-JP",
			"ko-KR",
			"zh-CN",
			"zh-TW",
		},

		// Claims parameter supported
		"claims_parameter_supported": config.Env("OIDC_CLAIMS_PARAMETER_SUPPORTED", true),

		// Request parameter supported
		"request_parameter_supported": config.Env("OIDC_REQUEST_PARAMETER_SUPPORTED", true),

		// Request URI parameter supported
		"request_uri_parameter_supported": config.Env("OIDC_REQUEST_URI_PARAMETER_SUPPORTED", true),

		// Require request URI registration
		"require_request_uri_registration": config.Env("OIDC_REQUIRE_REQUEST_URI_REGISTRATION", false),

		// OP policy URI
		"op_policy_uri": config.Env("OIDC_OP_POLICY_URI", ""),

		// OP terms of service URI
		"op_terms_of_service_uri": config.Env("OIDC_OP_TERMS_OF_SERVICE_URI", ""),

		// OP logo URI
		"op_logo_uri": config.Env("OIDC_OP_LOGO_URI", ""),

		// OP contacts
		"op_contacts": []string{
			config.Env("OIDC_OP_CONTACT_EMAIL", "").(string),
		},

		// OP claims
		"op_claims": map[string]interface{}{
			"name": map[string]interface{}{
				"essential": true,
			},
			"email": map[string]interface{}{
				"essential": true,
			},
			"email_verified": map[string]interface{}{
				"essential": true,
			},
		},

		// ID Token Configuration
		"id_token": map[string]interface{}{
			// ID token lifetime in minutes (default: 60 minutes)
			"lifetime": config.Env("OIDC_ID_TOKEN_LIFETIME", 60),

			// Include user claims in ID token (default: true)
			"include_user_claims": config.Env("OIDC_ID_TOKEN_INCLUDE_USER_CLAIMS", true),

			// Include access token hash in ID token (default: true)
			"include_access_token_hash": config.Env("OIDC_ID_TOKEN_INCLUDE_ACCESS_TOKEN_HASH", true),

			// Include authorization code hash in ID token (default: true)
			"include_authorization_code_hash": config.Env("OIDC_ID_TOKEN_INCLUDE_AUTHORIZATION_CODE_HASH", true),

			// Include nonce in ID token (default: true)
			"include_nonce": config.Env("OIDC_ID_TOKEN_INCLUDE_NONCE", true),

			// Include authentication time in ID token (default: true)
			"include_auth_time": config.Env("OIDC_ID_TOKEN_INCLUDE_AUTH_TIME", true),

			// Include authentication context class reference in ID token (default: true)
			"include_acr": config.Env("OIDC_ID_TOKEN_INCLUDE_ACR", true),

			// Include authentication methods references in ID token (default: true)
			"include_amr": config.Env("OIDC_ID_TOKEN_INCLUDE_AMR", true),
		},

		// Userinfo Configuration
		"userinfo": map[string]interface{}{
			// Include user claims in userinfo (default: true)
			"include_user_claims": config.Env("OIDC_USERINFO_INCLUDE_USER_CLAIMS", true),

			// Include address claims in userinfo (default: true)
			"include_address_claims": config.Env("OIDC_USERINFO_INCLUDE_ADDRESS_CLAIMS", true),

			// Include phone claims in userinfo (default: true)
			"include_phone_claims": config.Env("OIDC_USERINFO_INCLUDE_PHONE_CLAIMS", true),

			// Include profile claims in userinfo (default: true)
			"include_profile_claims": config.Env("OIDC_USERINFO_INCLUDE_PROFILE_CLAIMS", true),
		},

		// Security Configuration
		"security": map[string]interface{}{
			// Require HTTPS for all OIDC endpoints (default: true in production)
			"require_https": config.Env("OIDC_REQUIRE_HTTPS", true),

			// Require PKCE for public clients (default: true)
			"require_pkce_for_public_clients": config.Env("OIDC_REQUIRE_PKCE_FOR_PUBLIC_CLIENTS", true),

			// Require state parameter for authorization code grant (default: true)
			"require_state_parameter": config.Env("OIDC_REQUIRE_STATE_PARAMETER", true),

			// Require nonce parameter for implicit grant (default: true)
			"require_nonce_parameter": config.Env("OIDC_REQUIRE_NONCE_PARAMETER", true),

			// Require client authentication for confidential clients (default: true)
			"require_client_authentication": config.Env("OIDC_REQUIRE_CLIENT_AUTHENTICATION", true),

			// Require scope validation (default: true)
			"require_scope_validation": config.Env("OIDC_REQUIRE_SCOPE_VALIDATION", true),

			// Require redirect URI validation (default: true)
			"require_redirect_uri_validation": config.Env("OIDC_REQUIRE_REDIRECT_URI_VALIDATION", true),

			// Require token binding (default: false)
			"require_token_binding": config.Env("OIDC_REQUIRE_TOKEN_BINDING", false),

			// Require token rotation (default: false)
			"require_token_rotation": config.Env("OIDC_REQUIRE_TOKEN_ROTATION", false),

			// Maximum age for authentication (default: 0 - no limit)
			"max_age": config.Env("OIDC_MAX_AGE", 0),

			// Require authentication time (default: false)
			"require_auth_time": config.Env("OIDC_REQUIRE_AUTH_TIME", false),
		},

		// Logging Configuration
		"logging": map[string]interface{}{
			// Enable OIDC event logging (default: true)
			"enable_event_logging": config.Env("OIDC_ENABLE_EVENT_LOGGING", true),

			// Enable token usage logging (default: true)
			"enable_token_usage_logging": config.Env("OIDC_ENABLE_TOKEN_USAGE_LOGGING", true),

			// Enable client activity logging (default: true)
			"enable_client_activity_logging": config.Env("OIDC_ENABLE_CLIENT_ACTIVITY_LOGGING", true),

			// Enable error logging (default: true)
			"enable_error_logging": config.Env("OIDC_ENABLE_ERROR_LOGGING", true),

			// Enable debug logging (default: false)
			"enable_debug_logging": config.Env("OIDC_ENABLE_DEBUG_LOGGING", false),
		},
	})
}
