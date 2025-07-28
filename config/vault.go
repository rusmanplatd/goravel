package config

import (
	"github.com/goravel/framework/facades"
)

func init() {
	config := facades.Config()
	config.Add("vault", map[string]interface{}{
		// Vault server configuration
		"addr": config.Env("E2EE_VAULT_ADDR", ""),

		// Authentication configuration
		"token":     config.Env("E2EE_VAULT_TOKEN", ""),
		"role_id":   config.Env("E2EE_VAULT_ROLE_ID", ""),
		"secret_id": config.Env("E2EE_VAULT_SECRET_ID", ""),

		// Optional configuration
		"namespace":   config.Env("E2EE_VAULT_NAMESPACE", ""),
		"secret_path": config.Env("E2EE_VAULT_SECRET_PATH", "secret/data/e2ee"),

		// Connection settings
		"timeout":     config.Env("E2EE_VAULT_TIMEOUT", "30s"),
		"max_retries": config.Env("E2EE_VAULT_MAX_RETRIES", 3),

		// TLS configuration
		"tls_skip_verify": config.Env("E2EE_VAULT_TLS_SKIP_VERIFY", false),
		"ca_cert":         config.Env("E2EE_VAULT_CA_CERT", ""),
		"client_cert":     config.Env("E2EE_VAULT_CLIENT_CERT", ""),
		"client_key":      config.Env("E2EE_VAULT_CLIENT_KEY", ""),
	})
}
