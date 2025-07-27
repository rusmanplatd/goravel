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
			"guard": VaultConfig("secret/auth/config", "guard", "users").(string),
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
				"driver": VaultConfig("secret/auth/config", "guard_driver", "session").(string),
			},
		},

		// User Providers
		//
		// All authentication drivers have a user provider. This defines how the
		// users are actually retrieved out of your database or other storage
		// mechanisms used by this application to persist your user's data.

		"providers": map[string]interface{}{
			"users": map[string]interface{}{
				"driver": VaultConfig("secret/auth/config", "provider_driver", "database").(string),
				"table":  VaultConfig("secret/auth/config", "provider_table", "users").(string),
			},
		},

		// Password Reset
		//
		// You may specify multiple password reset configurations if you have more
		// than one user table or model in the application and you want to have
		// separate password reset settings based on the specific user types.

		"passwords": map[string]interface{}{
			"users": map[string]interface{}{
				"provider": VaultConfig("secret/auth/config", "password_provider", "users").(string),
				"table":    VaultConfig("secret/auth/config", "password_table", "password_reset_tokens").(string),
				"expire":   VaultConfig("secret/auth/config", "password_expire", 60).(int),
				"throttle": VaultConfig("secret/auth/config", "password_throttle", 60).(int),
			},
		},

		// Password validation rules
		"password_rules": map[string]interface{}{
			"min_length":        VaultConfig("secret/auth/password_rules", "min_length", 8).(int),
			"require_uppercase": VaultConfig("secret/auth/password_rules", "require_uppercase", true).(bool),
			"require_lowercase": VaultConfig("secret/auth/password_rules", "require_lowercase", true).(bool),
			"require_numbers":   VaultConfig("secret/auth/password_rules", "require_numbers", true).(bool),
			"require_symbols":   VaultConfig("secret/auth/password_rules", "require_symbols", false).(bool),
			"check_compromised": VaultConfig("secret/auth/password_rules", "check_compromised", true).(bool),
			"max_attempts":      VaultConfig("secret/auth/password_rules", "max_attempts", 5).(int),
			"lockout_duration":  VaultConfig("secret/auth/password_rules", "lockout_duration", 30).(int), // minutes
		},

		// Session settings
		"session": map[string]interface{}{
			"lifetime":        VaultConfig("secret/auth/session", "lifetime", 120).(int),
			"expire_on_close": VaultConfig("secret/auth/session", "expire_on_close", false).(bool),
			"encrypt":         VaultConfig("secret/auth/session", "encrypt", false).(bool),
			"files":           VaultConfig("secret/auth/session", "files", "storage/framework/sessions").(string),
			"connection":      VaultConfig("secret/auth/session", "connection", "").(string),
			"table":           VaultConfig("secret/auth/session", "table", "sessions").(string),
			"store":           VaultConfig("secret/auth/session", "store", "").(string),
			"lottery":         []int{2, 100},
			"cookie":          VaultConfig("secret/auth/session", "cookie", "goravel_session").(string),
			"path":            VaultConfig("secret/auth/session", "path", "/").(string),
			"domain":          VaultConfig("secret/auth/session", "domain", "").(string),
			"secure":          VaultConfig("secret/auth/session", "secure", false).(bool),
			"http_only":       true,
			"same_site":       VaultConfig("secret/auth/session", "same_site", "lax").(string),
		},

		// Google OAuth2 Configuration
		"google_oauth": map[string]interface{}{
			"client_id":     VaultConfig("secret/services/oauth/google", "client_id", "").(string),
			"client_secret": VaultConfig("secret/services/oauth/google", "client_secret", "").(string),
			"redirect_url":  VaultConfig("secret/services/oauth/google", "redirect_url", "http://localhost:3000/auth/google/callback").(string),
			"scopes": VaultStringSlice("secret/services/oauth/google", "scopes", []string{
				"https://www.googleapis.com/auth/userinfo.email",
				"https://www.googleapis.com/auth/userinfo.profile",
			}),
			"enabled": VaultConfig("secret/services/oauth/google", "enabled", false).(bool),
		},

		// OAuth Provider Settings
		"oauth_providers": map[string]interface{}{
			"google": map[string]interface{}{
				"enabled":       VaultConfig("secret/services/oauth/google", "enabled", false).(bool),
				"client_id":     VaultConfig("secret/services/oauth/google", "client_id", "").(string),
				"client_secret": VaultConfig("secret/services/oauth/google", "client_secret", "").(string),
				"redirect_url":  VaultConfig("secret/services/oauth/google", "redirect_url", "http://localhost:3000/auth/oauth/google/callback").(string),
				"scopes": VaultStringSlice("secret/services/oauth/google", "scopes", []string{
					"https://www.googleapis.com/auth/userinfo.email",
					"https://www.googleapis.com/auth/userinfo.profile",
				}),
			},
			"github": map[string]interface{}{
				"enabled":       VaultConfig("secret/services/oauth/github", "enabled", false).(bool),
				"client_id":     VaultConfig("secret/services/oauth/github", "client_id", "").(string),
				"client_secret": VaultConfig("secret/services/oauth/github", "client_secret", "").(string),
				"redirect_url":  VaultConfig("secret/services/oauth/github", "redirect_url", "http://localhost:3000/auth/oauth/github/callback").(string),
				"scopes": VaultStringSlice("secret/services/oauth/github", "scopes", []string{
					"user:email",
					"read:user",
				}),
			},
			"microsoft": map[string]interface{}{
				"enabled":       VaultConfig("secret/services/oauth/microsoft", "enabled", false).(bool),
				"client_id":     VaultConfig("secret/services/oauth/microsoft", "client_id", "").(string),
				"client_secret": VaultConfig("secret/services/oauth/microsoft", "client_secret", "").(string),
				"redirect_url":  VaultConfig("secret/services/oauth/microsoft", "redirect_url", "http://localhost:3000/auth/oauth/microsoft/callback").(string),
				"scopes": VaultStringSlice("secret/services/oauth/microsoft", "scopes", []string{
					"openid",
					"profile",
					"email",
				}),
			},
			"discord": map[string]interface{}{
				"enabled":       VaultConfig("secret/services/oauth/discord", "enabled", false).(bool),
				"client_id":     VaultConfig("secret/services/oauth/discord", "client_id", "").(string),
				"client_secret": VaultConfig("secret/services/oauth/discord", "client_secret", "").(string),
				"redirect_url":  VaultConfig("secret/services/oauth/discord", "redirect_url", "http://localhost:3000/auth/oauth/discord/callback").(string),
				"scopes": VaultStringSlice("secret/services/oauth/discord", "scopes", []string{
					"identify",
					"email",
				}),
			},
		},

		// Allowed redirect hosts for OAuth callbacks
		"allowed_redirect_hosts": VaultStringSlice("secret/auth/config", "allowed_redirect_hosts", []string{
			"localhost:3000",
			"127.0.0.1:3000",
		}),

		// Multi-Factor Authentication
		"mfa": map[string]interface{}{
			"enabled":      VaultConfig("secret/auth/mfa", "enabled", true).(bool),
			"issuer":       VaultConfig("secret/auth/mfa", "issuer", "Goravel App").(string),
			"digits":       VaultConfig("secret/auth/mfa", "digits", 6).(int),
			"period":       VaultConfig("secret/auth/mfa", "period", 30).(int),
			"backup_codes": VaultConfig("secret/auth/mfa", "backup_codes", 8).(int),
		},

		// WebAuthn Configuration
		"webauthn": map[string]interface{}{
			"enabled":   VaultConfig("secret/services/webauthn", "enabled", true).(bool),
			"rp_id":     VaultConfig("secret/services/webauthn", "rp_id", "localhost").(string),
			"rp_name":   VaultConfig("secret/services/webauthn", "rp_name", "Goravel App").(string),
			"rp_origin": VaultConfig("secret/services/webauthn", "rp_origin", "http://localhost:3000").(string),
			"timeout":   VaultConfig("secret/services/webauthn", "timeout", 60000).(int),
		},
	})
}
