package config

import (
	"github.com/goravel/framework/facades"
)

func init() {
	config := facades.Config()
	config.Add("jwt", map[string]interface{}{
		"secret":      config.Env("JWT_SECRET", "your-secret-key-change-in-production"),
		"ttl":         config.Env("JWT_TTL", 60),            // Access token TTL in minutes
		"refresh_ttl": config.Env("JWT_REFRESH_TTL", 20160), // Refresh token TTL in minutes (14 days)
		"issuer":      config.Env("JWT_ISSUER", "goravel"),
		"audience":    config.Env("JWT_AUDIENCE", "goravel-users"),
	})
}
