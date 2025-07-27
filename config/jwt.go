package config

import (
	"github.com/goravel/framework/facades"
)

func init() {
	config := facades.Config()
	config.Add("jwt", map[string]interface{}{
		"secret":      VaultConfig("secret/app/jwt-secret", "jwt_secret", "your-secret-key-change-in-production").(string),
		"ttl":         VaultConfig("secret/app/jwt-secret", "access_token_ttl", 60).(int),     // Access token TTL in minutes
		"refresh_ttl": VaultConfig("secret/app/jwt-secret", "refresh_token_ttl", 20160).(int), // Refresh token TTL in minutes (14 days)
		"issuer":      VaultConfig("secret/app/jwt-secret", "issuer", "goravel").(string),
		"audience":    VaultConfig("secret/app/jwt-secret", "audience", "goravel-users").(string),
	})
}
