package config

import (
	"github.com/goravel/framework/facades"
)

func init() {
	config := facades.Config()
	config.Add("vault", map[string]any{
		// HashiCorp Vault Configuration
		//
		// This configuration enables HashiCorp Vault integration for secure
		// secret management across the application.

		// Connection Settings
		"address":   config.Env("VAULT_ADDR", "http://localhost:8200"),
		"namespace": config.Env("VAULT_NAMESPACE", ""), // For Vault Enterprise
		"timeout":   config.Env("VAULT_TIMEOUT", 60),   // Connection timeout in seconds

		// TLS Configuration
		"tls": map[string]any{
			"enabled":         config.Env("VAULT_TLS_ENABLED", true),
			"ca_cert":         config.Env("VAULT_CA_CERT", ""),
			"ca_path":         config.Env("VAULT_CA_PATH", ""),
			"client_cert":     config.Env("VAULT_CLIENT_CERT", ""),
			"client_key":      config.Env("VAULT_CLIENT_KEY", ""),
			"tls_server_name": config.Env("VAULT_TLS_SERVER_NAME", ""),
			"insecure":        config.Env("VAULT_TLS_INSECURE", false),
			"skip_verify":     config.Env("VAULT_TLS_SKIP_VERIFY", false),
		},

		// Authentication Configuration
		"auth": map[string]any{
			// Primary authentication method
			"method": config.Env("VAULT_AUTH_METHOD", "token"), // token, approle, kubernetes, userpass, ldap, aws, gcp, azure

			// Token Authentication
			"token": config.Env("VAULT_TOKEN", ""),

			// AppRole Authentication
			"approle": map[string]any{
				"role_id":   config.Env("VAULT_ROLE_ID", ""),
				"secret_id": config.Env("VAULT_SECRET_ID", ""),
				"mount":     config.Env("VAULT_APPROLE_MOUNT", "approle"),
			},

			// Kubernetes Authentication
			"kubernetes": map[string]any{
				"role":     config.Env("VAULT_K8S_ROLE", ""),
				"jwt_path": config.Env("VAULT_K8S_JWT_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
				"mount":    config.Env("VAULT_K8S_MOUNT", "kubernetes"),
			},

			// UserPass Authentication
			"userpass": map[string]any{
				"username": config.Env("VAULT_USERNAME", ""),
				"password": config.Env("VAULT_PASSWORD", ""),
				"mount":    config.Env("VAULT_USERPASS_MOUNT", "userpass"),
			},

			// LDAP Authentication
			"ldap": map[string]any{
				"username": config.Env("VAULT_LDAP_USERNAME", ""),
				"password": config.Env("VAULT_LDAP_PASSWORD", ""),
				"mount":    config.Env("VAULT_LDAP_MOUNT", "ldap"),
			},

			// AWS Authentication
			"aws": map[string]any{
				"role":         config.Env("VAULT_AWS_ROLE", ""),
				"mount":        config.Env("VAULT_AWS_MOUNT", "aws"),
				"header_value": config.Env("VAULT_AWS_HEADER_VALUE", ""),
				"region":       config.Env("VAULT_AWS_REGION", ""),
				"iam_endpoint": config.Env("VAULT_AWS_IAM_ENDPOINT", ""),
				"sts_endpoint": config.Env("VAULT_AWS_STS_ENDPOINT", ""),
			},

			// GCP Authentication
			"gcp": map[string]any{
				"role":            config.Env("VAULT_GCP_ROLE", ""),
				"mount":           config.Env("VAULT_GCP_MOUNT", "gcp"),
				"service_account": config.Env("VAULT_GCP_SERVICE_ACCOUNT", ""),
				"project":         config.Env("VAULT_GCP_PROJECT", ""),
			},

			// Azure Authentication
			"azure": map[string]any{
				"role":         config.Env("VAULT_AZURE_ROLE", ""),
				"mount":        config.Env("VAULT_AZURE_MOUNT", "azure"),
				"resource":     config.Env("VAULT_AZURE_RESOURCE", "https://management.azure.com/"),
				"subscription": config.Env("VAULT_AZURE_SUBSCRIPTION", ""),
				"tenant":       config.Env("VAULT_AZURE_TENANT", ""),
			},
		},

		// Secret Engines Configuration
		"secrets": map[string]any{
			// KV (Key-Value) Secret Engine v2
			"kv": map[string]any{
				"mount":   config.Env("VAULT_KV_MOUNT", "secret"),
				"version": config.Env("VAULT_KV_VERSION", 2),
			},

			// Database Secret Engine
			"database": map[string]any{
				"mount":   config.Env("VAULT_DB_MOUNT", "database"),
				"enabled": config.Env("VAULT_DB_ENABLED", false),
			},

			// PKI Secret Engine
			"pki": map[string]any{
				"mount":   config.Env("VAULT_PKI_MOUNT", "pki"),
				"enabled": config.Env("VAULT_PKI_ENABLED", false),
			},

			// Transit Secret Engine
			"transit": map[string]any{
				"mount":   config.Env("VAULT_TRANSIT_MOUNT", "transit"),
				"enabled": config.Env("VAULT_TRANSIT_ENABLED", false),
			},

			// TOTP Secret Engine
			"totp": map[string]any{
				"mount":   config.Env("VAULT_TOTP_MOUNT", "totp"),
				"enabled": config.Env("VAULT_TOTP_ENABLED", false),
			},
		},

		// Secret Paths Configuration
		"paths": map[string]any{
			// Application secrets
			"app": map[string]any{
				"master_key": config.Env("VAULT_PATH_APP_MASTER_KEY", "secret/app/master-key"),
				"app_key":    config.Env("VAULT_PATH_APP_KEY", "secret/app/app-key"),
				"jwt_secret": config.Env("VAULT_PATH_JWT_SECRET", "secret/app/jwt-secret"),
			},

			// Database credentials
			"database": map[string]any{
				"postgres": config.Env("VAULT_PATH_DB_POSTGRES", "secret/database/postgres"),
				"redis":    config.Env("VAULT_PATH_DB_REDIS", "secret/database/redis"),
			},

			// External service credentials
			"services": map[string]any{
				"minio":        config.Env("VAULT_PATH_MINIO", "secret/services/minio"),
				"livekit":      config.Env("VAULT_PATH_LIVEKIT", "secret/services/livekit"),
				"mail":         config.Env("VAULT_PATH_MAIL", "secret/services/mail"),
				"oauth_google": config.Env("VAULT_PATH_OAUTH_GOOGLE", "secret/services/oauth/google"),
				"notification": config.Env("VAULT_PATH_NOTIFICATION", "secret/services/notification"),
				"webauthn":     config.Env("VAULT_PATH_WEBAUTHN", "secret/services/webauthn"),
			},

			// API keys and tokens
			"api": map[string]any{
				"webhook_tokens": config.Env("VAULT_PATH_WEBHOOK_TOKENS", "secret/api/webhook-tokens"),
				"api_keys":       config.Env("VAULT_PATH_API_KEYS", "secret/api/keys"),
			},
		},

		// Caching Configuration
		"cache": map[string]any{
			"enabled":     config.Env("VAULT_CACHE_ENABLED", true),
			"ttl":         config.Env("VAULT_CACHE_TTL", 3600), // Cache TTL in seconds
			"max_entries": config.Env("VAULT_CACHE_MAX_ENTRIES", 1000),
		},

		// Retry Configuration
		"retry": map[string]any{
			"max_retries": config.Env("VAULT_MAX_RETRIES", 3),
			"retry_wait":  config.Env("VAULT_RETRY_WAIT", 1000), // Milliseconds
		},

		// Lease Management
		"lease": map[string]any{
			"renew_buffer":  config.Env("VAULT_LEASE_RENEW_BUFFER", 300), // Renew 5 minutes before expiry
			"increment":     config.Env("VAULT_LEASE_INCREMENT", 3600),   // Request 1 hour lease
			"max_lease_ttl": config.Env("VAULT_MAX_LEASE_TTL", 86400),    // Maximum lease TTL (24 hours)
		},

		// Logging Configuration
		"logging": map[string]any{
			"enabled":       config.Env("VAULT_LOGGING_ENABLED", true),
			"level":         config.Env("VAULT_LOG_LEVEL", "info"), // debug, info, warn, error
			"audit_enabled": config.Env("VAULT_AUDIT_LOGGING", true),
		},

		// Development/Testing Settings
		"dev": map[string]any{
			"enabled":         config.Env("VAULT_DEV_MODE", config.Env("APP_ENV", "local") == "local"),
			"fallback_to_env": config.Env("VAULT_FALLBACK_TO_ENV", config.Env("APP_ENV", "local") == "local"),
			"mock_mode":       config.Env("VAULT_MOCK_MODE", false),
		},

		// Health Check Configuration
		"health": map[string]any{
			"check_interval": config.Env("VAULT_HEALTH_CHECK_INTERVAL", 300), // Seconds
			"timeout":        config.Env("VAULT_HEALTH_TIMEOUT", 30),         // Seconds
		},

		// Agent Configuration (for Vault Agent integration)
		"agent": map[string]any{
			"enabled":     config.Env("VAULT_AGENT_ENABLED", false),
			"socket_path": config.Env("VAULT_AGENT_SOCKET", "/tmp/vault-agent.sock"),
		},
	})
}
