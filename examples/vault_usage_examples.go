package examples

import (
	"fmt"
	"log"
	"time"

	"goravel/app/services"
	"goravel/bootstrap"

	"github.com/goravel/framework/facades"
)

func VaultUsageExamples() {
	// Bootstrap the application
	bootstrap.Boot()

	fmt.Println("=== HashiCorp Vault Integration Examples ===")

	// Example 1: Basic Vault Service Usage
	fmt.Println("\n1. Basic Vault Service Usage:")

	// Get Vault service from container
	app := facades.App()
	vaultService, err := app.MakeWith("vault", nil)
	if err != nil || vaultService == nil {
		fmt.Printf("Vault service not available: %v\n", err)
		fmt.Println("This is expected in local development without Vault configured")
		return
	}

	vs, ok := vaultService.(*services.VaultService)
	if !ok {
		log.Fatal("Invalid Vault service type")
	}

	// Example 2: Store and retrieve application secrets
	fmt.Println("\n2. Application Secrets Management:")

	// Store application master key
	masterKeyData := map[string]interface{}{
		"master_key": "YourBase64EncodedMasterKeyHere==",
		"created_at": time.Now().Format(time.RFC3339),
		"algorithm":  "AES-256-GCM",
		"version":    "1.0",
	}

	err = vs.PutSecret("secret/app/master-key", masterKeyData)
	if err != nil {
		fmt.Printf("Failed to store master key: %v\n", err)
	} else {
		fmt.Println("✓ Master key stored in Vault!")
	}

	// Retrieve master key
	masterKey, err := vs.GetSecretValue("secret/app/master-key", "master_key")
	if err != nil {
		fmt.Printf("Failed to retrieve master key: %v\n", err)
	} else {
		fmt.Printf("✓ Retrieved master key: %s...\n", masterKey[:20])
	}

	// Example 3: Database credentials management
	fmt.Println("\n3. Database Credentials Management:")

	dbCredentials := map[string]interface{}{
		"host":            "localhost",
		"port":            "5432",
		"database":        "myapp",
		"username":        "dbuser",
		"password":        "dbpassword123",
		"ssl_mode":        "require",
		"max_connections": 100,
		"created_at":      time.Now().Format(time.RFC3339),
	}

	err = vs.PutSecret("secret/database/postgres", dbCredentials)
	if err != nil {
		fmt.Printf("Failed to store DB credentials: %v\n", err)
	} else {
		fmt.Println("✓ Database credentials stored in Vault!")
	}

	// Retrieve database configuration
	dbSecret, err := vs.GetSecret("secret/database/postgres")
	if err != nil {
		fmt.Printf("Failed to retrieve DB credentials: %v\n", err)
	} else {
		fmt.Printf("✓ Retrieved DB config for database: %s\n", dbSecret.Data["database"])
	}

	// Example 4: External service API keys
	fmt.Println("\n4. External Service API Keys:")

	serviceKeys := map[string]interface{}{
		"stripe_secret_key": "sk_test_...",
		"stripe_public_key": "pk_test_...",
		"sendgrid_api_key":  "SG.xxx...",
		"aws_access_key":    "AKIA...",
		"aws_secret_key":    "xxx...",
		"created_at":        time.Now().Format(time.RFC3339),
		"environment":       "production",
	}

	err = vs.PutSecret("secret/services/external-apis", serviceKeys)
	if err != nil {
		fmt.Printf("Failed to store service keys: %v\n", err)
	} else {
		fmt.Println("✓ External service API keys stored!")
	}

	// Example 5: OAuth provider secrets
	fmt.Println("\n5. OAuth Provider Configuration:")

	googleOAuth := map[string]interface{}{
		"client_id":     "xxx.apps.googleusercontent.com",
		"client_secret": "GOCSPX-xxx",
		"redirect_uri":  "https://myapp.com/auth/google/callback",
		"scopes":        []string{"openid", "email", "profile"},
		"created_at":    time.Now().Format(time.RFC3339),
	}

	err = vs.PutSecret("secret/services/oauth/google", googleOAuth)
	if err != nil {
		fmt.Printf("Failed to store Google OAuth config: %v\n", err)
	} else {
		fmt.Println("✓ Google OAuth configuration stored!")
	}

	// Example 6: JWT signing keys
	fmt.Println("\n6. JWT Signing Keys:")

	jwtConfig := map[string]interface{}{
		"jwt_secret":        "your-super-secret-jwt-key",
		"access_token_ttl":  3600,    // 1 hour
		"refresh_token_ttl": 2592000, // 30 days
		"algorithm":         "HS256",
		"issuer":            "goravel-app",
		"audience":          "goravel-users",
		"created_at":        time.Now().Format(time.RFC3339),
	}

	err = vs.PutSecret("secret/app/jwt-secret", jwtConfig)
	if err != nil {
		fmt.Printf("Failed to store JWT config: %v\n", err)
	} else {
		fmt.Println("✓ JWT configuration stored!")
	}

	// Example 7: Redis configuration
	fmt.Println("\n7. Redis Configuration:")

	redisConfig := map[string]interface{}{
		"host":        "localhost",
		"port":        "6379",
		"password":    "redis-password",
		"database":    0,
		"max_retries": 3,
		"pool_size":   10,
		"created_at":  time.Now().Format(time.RFC3339),
	}

	err = vs.PutSecret("secret/database/redis", redisConfig)
	if err != nil {
		fmt.Printf("Failed to store Redis config: %v\n", err)
	} else {
		fmt.Println("✓ Redis configuration stored!")
	}

	// Example 8: MinIO/S3 credentials
	fmt.Println("\n8. Object Storage Credentials:")

	minioConfig := map[string]interface{}{
		"endpoint":   "localhost:9000",
		"access_key": "miniouserroot",
		"secret_key": "miniouserrootpassword",
		"bucket":     "goravelstorage",
		"region":     "ap-southeast-1",
		"use_ssl":    false,
		"created_at": time.Now().Format(time.RFC3339),
	}

	err = vs.PutSecret("secret/services/minio", minioConfig)
	if err != nil {
		fmt.Printf("Failed to store MinIO config: %v\n", err)
	} else {
		fmt.Println("✓ MinIO configuration stored!")
	}

	// Example 9: Email service configuration
	fmt.Println("\n9. Email Service Configuration:")

	emailConfig := map[string]interface{}{
		"smtp_host":     "smtp.gmail.com",
		"smtp_port":     587,
		"smtp_username": "your-email@gmail.com",
		"smtp_password": "your-app-password",
		"from_name":     "Goravel App",
		"from_email":    "noreply@yourapp.com",
		"use_tls":       true,
		"created_at":    time.Now().Format(time.RFC3339),
	}

	err = vs.PutSecret("secret/services/mail", emailConfig)
	if err != nil {
		fmt.Printf("Failed to store email config: %v\n", err)
	} else {
		fmt.Println("✓ Email service configuration stored!")
	}

	// Example 10: WebAuthn configuration
	fmt.Println("\n10. WebAuthn Configuration:")

	webauthnConfig := map[string]interface{}{
		"rp_display_name": "Goravel App",
		"rp_id":           "localhost",
		"rp_origin":       "http://localhost:3000",
		"timeout":         60000,
		"created_at":      time.Now().Format(time.RFC3339),
	}

	err = vs.PutSecret("secret/services/webauthn", webauthnConfig)
	if err != nil {
		fmt.Printf("Failed to store WebAuthn config: %v\n", err)
	} else {
		fmt.Println("✓ WebAuthn configuration stored!")
	}

	// Example 11: Notification service configuration
	fmt.Println("\n11. Notification Service Configuration:")

	notificationConfig := map[string]interface{}{
		"fcm_server_key":     "your-fcm-server-key",
		"apns_key_id":        "your-apns-key-id",
		"apns_team_id":       "your-apns-team-id",
		"apns_bundle_id":     "com.yourapp.bundle",
		"webhook_secret":     "webhook-secret-key",
		"rate_limit_per_min": 1000,
		"created_at":         time.Now().Format(time.RFC3339),
	}

	err = vs.PutSecret("secret/services/notification", notificationConfig)
	if err != nil {
		fmt.Printf("Failed to store notification config: %v\n", err)
	} else {
		fmt.Println("✓ Notification service configuration stored!")
	}

	// Example 12: LiveKit configuration for meetings
	fmt.Println("\n12. LiveKit Meeting Configuration:")

	livekitConfig := map[string]interface{}{
		"api_key":       "your-livekit-api-key",
		"api_secret":    "your-livekit-api-secret",
		"ws_url":        "wss://your-livekit-server.com",
		"turn_server":   "turn:your-turn-server.com:3478",
		"turn_username": "turn-username",
		"turn_password": "turn-password",
		"created_at":    time.Now().Format(time.RFC3339),
	}

	err = vs.PutSecret("secret/services/livekit", livekitConfig)
	if err != nil {
		fmt.Printf("Failed to store LiveKit config: %v\n", err)
	} else {
		fmt.Println("✓ LiveKit configuration stored!")
	}

	// Example 13: API webhook tokens
	fmt.Println("\n13. API Webhook Tokens:")

	webhookTokens := map[string]interface{}{
		"stripe_webhook_secret": "whsec_...",
		"github_webhook_secret": "github-webhook-secret",
		"slack_webhook_url":     "https://hooks.slack.com/services/...",
		"discord_webhook_url":   "https://discord.com/api/webhooks/...",
		"teams_webhook_url":     "https://outlook.office.com/webhook/...",
		"created_at":            time.Now().Format(time.RFC3339),
	}

	err = vs.PutSecret("secret/api/webhook-tokens", webhookTokens)
	if err != nil {
		fmt.Printf("Failed to store webhook tokens: %v\n", err)
	} else {
		fmt.Println("✓ Webhook tokens stored!")
	}

	// Example 14: Batch secret operations
	fmt.Println("\n14. Batch Secret Operations:")

	// Store multiple related secrets
	secrets := map[string]map[string]interface{}{
		"secret/app/feature-flags": {
			"enable_new_ui":        true,
			"enable_beta_features": false,
			"maintenance_mode":     false,
			"max_file_size_mb":     100,
		},
		"secret/app/rate-limits": {
			"api_requests_per_minute": 1000,
			"login_attempts_per_hour": 5,
			"password_reset_per_hour": 3,
			"file_uploads_per_day":    50,
		},
		"secret/monitoring/alerts": {
			"slack_webhook":    "https://hooks.slack.com/...",
			"pagerduty_key":    "your-pagerduty-integration-key",
			"email_recipients": []string{"admin@yourapp.com", "ops@yourapp.com"},
		},
	}

	for path, data := range secrets {
		data["created_at"] = time.Now().Format(time.RFC3339)
		err = vs.PutSecret(path, data)
		if err != nil {
			fmt.Printf("Failed to store %s: %v\n", path, err)
		} else {
			fmt.Printf("✓ Stored %s\n", path)
		}
	}

	// Example 15: Secret validation and health check
	fmt.Println("\n15. Secret Validation:")

	// Validate that all critical secrets exist
	criticalPaths := []string{
		"secret/app/master-key",
		"secret/database/postgres",
		"secret/app/jwt-secret",
		"secret/services/minio",
	}

	fmt.Println("Validating critical secrets:")
	for _, path := range criticalPaths {
		_, err := vs.GetSecret(path)
		if err != nil {
			fmt.Printf("❌ Missing or inaccessible: %s\n", path)
		} else {
			fmt.Printf("✓ Available: %s\n", path)
		}
	}

	// Example 16: Clean up example secrets (optional)
	fmt.Println("\n16. Cleanup Example Secrets (optional):")

	examplePaths := []string{
		"secret/example/credentials",
		"secret/app/feature-flags",
		"secret/app/rate-limits",
		"secret/monitoring/alerts",
	}

	for _, path := range examplePaths {
		err := vs.DeleteSecret(path)
		if err != nil {
			fmt.Printf("Failed to delete %s: %v\n", path, err)
		} else {
			fmt.Printf("✓ Deleted example secret: %s\n", path)
		}
	}

	fmt.Println("\n=== Vault Integration Examples Complete ===")

	// Print configuration recommendations
	fmt.Println("\n📋 Production Recommendations:")
	fmt.Println("1. Use AppRole or Kubernetes auth instead of tokens in production")
	fmt.Println("2. Enable audit logging for compliance")
	fmt.Println("3. Set up proper Vault policies for least privilege access")
	fmt.Println("4. Use Vault Agent for automatic token renewal")
	fmt.Println("5. Enable TLS for all Vault communications")
	fmt.Println("6. Regularly rotate secrets and tokens")
	fmt.Println("7. Monitor Vault health and performance")
	fmt.Println("8. Backup Vault data regularly")

	fmt.Println("\n🐳 Docker Setup:")
	fmt.Println("Run 'docker-compose up vault' to start Vault in development mode")
	fmt.Println("Access Vault UI at: http://localhost:8200")
	fmt.Println("Default dev token: 'myroot'")
}

// VaultProductionPatterns demonstrates production-ready patterns
func VaultProductionPatterns() {
	fmt.Println("=== Vault Production Patterns ===")

	app := facades.App()
	vaultService, err := app.MakeWith("vault", nil)
	if err != nil {
		fmt.Printf("Vault service not available: %v\n", err)
		return
	}

	vs, ok := vaultService.(*services.VaultService)
	if !ok {
		log.Fatal("Invalid Vault service type")
	}

	// Pattern 1: Environment-specific secrets
	fmt.Println("\n1. Environment-specific Secret Management:")

	environments := []string{"development", "staging", "production"}
	for _, env := range environments {
		envSecrets := map[string]interface{}{
			"database_url":  fmt.Sprintf("postgres://user:pass@%s-db:5432/myapp", env),
			"redis_url":     fmt.Sprintf("redis://%s-redis:6379", env),
			"api_base_url":  fmt.Sprintf("https://api-%s.myapp.com", env),
			"debug_enabled": env != "production",
			"log_level":     map[string]string{"development": "debug", "staging": "info", "production": "warn"}[env],
			"environment":   env,
			"created_at":    time.Now().Format(time.RFC3339),
		}

		path := fmt.Sprintf("secret/environments/%s", env)
		err = vs.PutSecret(path, envSecrets)
		if err != nil {
			fmt.Printf("Failed to store %s secrets: %v\n", env, err)
		} else {
			fmt.Printf("✓ Stored %s environment secrets\n", env)
		}
	}

	// Pattern 2: Service discovery secrets
	fmt.Println("\n2. Service Discovery Configuration:")

	serviceConfig := map[string]interface{}{
		"consul_address":  "consul.service.consul:8500",
		"consul_token":    "consul-acl-token",
		"etcd_endpoints":  []string{"etcd1:2379", "etcd2:2379", "etcd3:2379"},
		"etcd_username":   "etcd-user",
		"etcd_password":   "etcd-password",
		"service_mesh_ca": "-----BEGIN CERTIFICATE-----\n...",
		"created_at":      time.Now().Format(time.RFC3339),
	}

	err = vs.PutSecret("secret/infrastructure/service-discovery", serviceConfig)
	if err != nil {
		fmt.Printf("Failed to store service discovery config: %v\n", err)
	} else {
		fmt.Println("✓ Service discovery configuration stored")
	}

	// Pattern 3: Certificate management
	fmt.Println("\n3. Certificate Management:")

	certConfig := map[string]interface{}{
		"tls_cert":    "-----BEGIN CERTIFICATE-----\n...",
		"tls_key":     "-----BEGIN PRIVATE KEY-----\n...",
		"ca_cert":     "-----BEGIN CERTIFICATE-----\n...",
		"cert_expiry": time.Now().AddDate(1, 0, 0).Format(time.RFC3339),
		"auto_renew":  true,
		"domains":     []string{"*.myapp.com", "myapp.com"},
		"created_at":  time.Now().Format(time.RFC3339),
	}

	err = vs.PutSecret("secret/certificates/wildcard", certConfig)
	if err != nil {
		fmt.Printf("Failed to store certificate config: %v\n", err)
	} else {
		fmt.Println("✓ Certificate configuration stored")
	}

	// Pattern 4: Monitoring and alerting
	fmt.Println("\n4. Monitoring and Alerting Configuration:")

	monitoringConfig := map[string]interface{}{
		"prometheus_url":         "http://prometheus:9090",
		"grafana_admin_password": "secure-grafana-password",
		"alertmanager_webhook":   "https://hooks.slack.com/services/...",
		"pagerduty_integration":  "your-pagerduty-key",
		"datadog_api_key":        "your-datadog-api-key",
		"newrelic_license_key":   "your-newrelic-license",
		"created_at":             time.Now().Format(time.RFC3339),
	}

	err = vs.PutSecret("secret/monitoring/config", monitoringConfig)
	if err != nil {
		fmt.Printf("Failed to store monitoring config: %v\n", err)
	} else {
		fmt.Println("✓ Monitoring configuration stored")
	}

	fmt.Println("\n✅ Production patterns configured successfully!")
}

// VaultSecurityBestPractices demonstrates security best practices
func VaultSecurityBestPractices() {
	fmt.Println("=== Vault Security Best Practices ===")

	fmt.Println("\n🔐 Authentication Best Practices:")
	fmt.Println("1. Use AppRole for applications (not root tokens)")
	fmt.Println("2. Implement short-lived, renewable tokens")
	fmt.Println("3. Use Kubernetes auth for pod-based applications")
	fmt.Println("4. Enable MFA for human users")
	fmt.Println("5. Regularly rotate authentication credentials")

	fmt.Println("\n🛡️ Authorization Best Practices:")
	fmt.Println("1. Follow principle of least privilege")
	fmt.Println("2. Use path-based policies")
	fmt.Println("3. Implement time-based access controls")
	fmt.Println("4. Regular policy audits and reviews")
	fmt.Println("5. Use namespaces for multi-tenancy (Enterprise)")

	fmt.Println("\n🔍 Audit and Monitoring:")
	fmt.Println("1. Enable audit logging on all Vault instances")
	fmt.Println("2. Monitor for unusual access patterns")
	fmt.Println("3. Set up alerts for policy violations")
	fmt.Println("4. Regular access reviews and cleanup")
	fmt.Println("5. Log analysis and SIEM integration")

	fmt.Println("\n🔄 Operational Security:")
	fmt.Println("1. Regular Vault updates and patches")
	fmt.Println("2. Backup and disaster recovery testing")
	fmt.Println("3. Network segmentation and firewall rules")
	fmt.Println("4. TLS encryption for all communications")
	fmt.Println("5. Secure key management for unseal keys")

	fmt.Println("\n📊 Compliance and Governance:")
	fmt.Println("1. Document all secret access patterns")
	fmt.Println("2. Implement secret lifecycle management")
	fmt.Println("3. Regular compliance audits")
	fmt.Println("4. Data classification and handling")
	fmt.Println("5. Incident response procedures")
}
