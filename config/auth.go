package config

import (
	"github.com/goravel/framework/facades"
)

func init() {
	config := facades.Config()
	config.Add("auth", map[string]interface{}{
		// Authentication Defaults
		//
		// This option controls the default authentication "guard" and password
		// reset options for your application. You may change these defaults
		// as required, but they're a perfect start for most applications.

		"defaults": map[string]interface{}{
			"guard": config.Env("AUTH_GUARD", "users"),
		},

		// Authentication Guards
		//
		// Here you may define every authentication guard for your application.
		// Of course, a great default configuration has been defined for you
		// here which uses session storage and the User provider.
		//
		// All authentication drivers have a user provider. This defines how the
		// users are actually retrieved out of your database or other storage
		// mechanisms used by this application to persist your user's data.

		"guards": map[string]interface{}{
			"users": map[string]interface{}{
				"driver": "session",
			},
		},

		// User Providers
		//
		// All authentication drivers have a user provider. This defines how the
		// users are actually retrieved out of your database or other storage
		// mechanisms used by this application to persist your user's data.

		"providers": map[string]interface{}{
			"users": map[string]interface{}{
				"driver": "database",
				"table":  "users",
			},
		},

		// Password Reset
		//
		// You may specify multiple password reset configurations if you have more
		// than one user table or model in the application and you want to have
		// separate password reset settings based on the specific user types.

		"passwords": map[string]interface{}{
			"users": map[string]interface{}{
				"provider": "users",
				"table":    "password_reset_tokens",
				"expire":   60,
				"throttle": 60,
			},
		},

		// Password validation rules
		"password_rules": map[string]interface{}{
			"min_length":        8,
			"require_uppercase": true,
			"require_lowercase": true,
			"require_numbers":   true,
			"require_symbols":   false,
			"check_compromised": true,
			"max_attempts":      5,
			"lockout_duration":  30, // minutes
		},

		// Session settings
		"session": map[string]interface{}{
			"lifetime":        config.Env("SESSION_LIFETIME", 120),
			"expire_on_close": config.Env("SESSION_EXPIRE_ON_CLOSE", false),
			"encrypt":         config.Env("SESSION_ENCRYPT", false),
			"files":           config.Env("SESSION_FILES", "storage/framework/sessions"),
			"connection":      config.Env("SESSION_CONNECTION", ""),
			"table":           config.Env("SESSION_TABLE", "sessions"),
			"store":           config.Env("SESSION_STORE", ""),
			"lottery":         []int{2, 100},
			"cookie":          config.Env("SESSION_COOKIE", "goravel_session"),
			"path":            config.Env("SESSION_PATH", "/"),
			"domain":          config.Env("SESSION_DOMAIN", ""),
			"secure":          config.Env("SESSION_SECURE_COOKIE", false),
			"http_only":       true,
			"same_site":       "lax",
		},

		// Google OAuth2 Configuration
		"google_oauth": map[string]interface{}{
			"client_id":     config.Env("GOOGLE_CLIENT_ID", ""),
			"client_secret": config.Env("GOOGLE_CLIENT_SECRET", ""),
			"redirect_url":  config.Env("GOOGLE_REDIRECT_URL", "http://localhost:3000/auth/google/callback"),
			"scopes": []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			},
			"enabled": config.Env("GOOGLE_OAUTH_ENABLED", false),
		},

		// OAuth Provider Settings
		"oauth_providers": map[string]interface{}{
			"google": map[string]interface{}{
				"enabled":       config.Env("GOOGLE_OAUTH_ENABLED", false),
				"client_id":     config.Env("GOOGLE_CLIENT_ID", ""),
				"client_secret": config.Env("GOOGLE_CLIENT_SECRET", ""),
				"redirect_url":  config.Env("GOOGLE_REDIRECT_URL", "http://localhost:3000/auth/google/callback"),
				"scopes": []string{
					"https://www.googleapis.com/auth/userinfo.email",
					"https://www.googleapis.com/auth/userinfo.profile",
				},
			},
		},

		// Multi-Factor Authentication
		"mfa": map[string]interface{}{
			"enabled":      config.Env("MFA_ENABLED", true),
			"issuer":       config.Env("MFA_ISSUER", "Goravel App"),
			"digits":       config.Env("MFA_DIGITS", 6),
			"period":       config.Env("MFA_PERIOD", 30),
			"backup_codes": config.Env("MFA_BACKUP_CODES", 8),
		},

		// WebAuthn Configuration
		"webauthn": map[string]interface{}{
			"enabled":   config.Env("WEBAUTHN_ENABLED", true),
			"rp_id":     config.Env("WEBAUTHN_RP_ID", "localhost"),
			"rp_name":   config.Env("WEBAUTHN_RP_NAME", "Goravel App"),
			"rp_origin": config.Env("WEBAUTHN_RP_ORIGIN", "http://localhost:3000"),
			"timeout":   config.Env("WEBAUTHN_TIMEOUT", 60000),
		},
	})
}
