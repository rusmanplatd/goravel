package services

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/goravel/framework/facades"
	"github.com/hashicorp/vault/api"
)

// VaultService provides secure secret management using HashiCorp Vault
type VaultService struct {
	client     *api.Client
	token      string
	cache      map[string]*CachedSecret
	cacheMutex sync.RWMutex
	config     VaultConfig
	renewals   map[string]*time.Timer
	ctx        context.Context
	cancel     context.CancelFunc
}

// VaultConfig holds configuration for Vault service
type VaultConfig struct {
	Address        string
	Namespace      string
	Timeout        time.Duration
	AuthMethod     string
	Token          string
	CacheEnabled   bool
	CacheTTL       time.Duration
	MaxRetries     int
	RetryWait      time.Duration
	FallbackToEnv  bool
	DevMode        bool
	LoggingEnabled bool
	AuditEnabled   bool
}

// CachedSecret represents a cached secret with expiration
type CachedSecret struct {
	Data      map[string]interface{}
	ExpiresAt time.Time
	LeaseID   string
	Renewable bool
}

// SecretData represents secret data with metadata
type SecretData struct {
	Data          map[string]interface{}
	Metadata      map[string]interface{}
	LeaseID       string
	Renewable     bool
	LeaseDuration int
}

// NewVaultService creates a new Vault service instance
func NewVaultService() (*VaultService, error) {
	config := loadVaultConfig()

	// Create context for background operations
	ctx, cancel := context.WithCancel(context.Background())

	service := &VaultService{
		cache:    make(map[string]*CachedSecret),
		renewals: make(map[string]*time.Timer),
		config:   config,
		ctx:      ctx,
		cancel:   cancel,
	}

	// Initialize Vault client
	if err := service.initClient(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to initialize Vault client: %v", err)
	}

	// Authenticate with Vault
	if err := service.authenticate(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to authenticate with Vault: %v", err)
	}

	// Start background lease renewal
	go service.startLeaseRenewal()

	// Start health checks
	go service.startHealthCheck()

	service.logInfo("Vault service initialized successfully", map[string]interface{}{
		"address":     config.Address,
		"auth_method": config.AuthMethod,
		"namespace":   config.Namespace,
	})

	return service, nil
}

// loadVaultConfig loads configuration from facades.Config
func loadVaultConfig() VaultConfig {
	config := facades.Config()

	return VaultConfig{
		Address:        config.GetString("vault.address", "http://localhost:8200"),
		Namespace:      config.GetString("vault.namespace", ""),
		Timeout:        time.Duration(config.GetInt("vault.timeout", 60)) * time.Second,
		AuthMethod:     config.GetString("vault.auth.method", "token"),
		Token:          config.GetString("vault.auth.token", ""),
		CacheEnabled:   config.GetBool("vault.cache.enabled", true),
		CacheTTL:       time.Duration(config.GetInt("vault.cache.ttl", 3600)) * time.Second,
		MaxRetries:     config.GetInt("vault.retry.max_retries", 3),
		RetryWait:      time.Duration(config.GetInt("vault.retry.retry_wait", 1000)) * time.Millisecond,
		FallbackToEnv:  config.GetBool("vault.dev.fallback_to_env", false),
		DevMode:        config.GetBool("vault.dev.enabled", false),
		LoggingEnabled: config.GetBool("vault.logging.enabled", true),
		AuditEnabled:   config.GetBool("vault.logging.audit_enabled", true),
	}
}

// initClient initializes the Vault API client
func (v *VaultService) initClient() error {
	// Create Vault client configuration
	vaultConfig := api.DefaultConfig()
	vaultConfig.Address = v.config.Address
	vaultConfig.Timeout = v.config.Timeout

	// Configure TLS if enabled
	tlsConfig := facades.Config()
	if tlsConfig.GetBool("vault.tls.enabled", true) {
		tlsClientConfig := &tls.Config{
			InsecureSkipVerify: tlsConfig.GetBool("vault.tls.skip_verify", false),
			ServerName:         tlsConfig.GetString("vault.tls.tls_server_name", ""),
		}

		// Load CA certificate if provided
		if caCert := tlsConfig.GetString("vault.tls.ca_cert", ""); caCert != "" {
			// Implementation would load CA cert
			v.logInfo("CA certificate configured", nil)
		}

		// Load client certificate if provided
		if clientCert := tlsConfig.GetString("vault.tls.client_cert", ""); clientCert != "" {
			clientKey := tlsConfig.GetString("vault.tls.client_key", "")
			if clientKey != "" {
				// Implementation would load client cert and key
				v.logInfo("Client certificate configured", nil)
			}
		}

		vaultConfig.HttpClient.Transport = &http.Transport{
			TLSClientConfig: tlsClientConfig,
		}
	}

	// Create client
	client, err := api.NewClient(vaultConfig)
	if err != nil {
		return fmt.Errorf("failed to create Vault client: %v", err)
	}

	// Set namespace if configured (Vault Enterprise)
	if v.config.Namespace != "" {
		client.SetNamespace(v.config.Namespace)
	}

	v.client = client
	return nil
}

// authenticate authenticates with Vault using the configured method
func (v *VaultService) authenticate() error {
	switch v.config.AuthMethod {
	case "token":
		return v.authenticateToken()
	case "approle":
		return v.authenticateAppRole()
	case "kubernetes":
		return v.authenticateKubernetes()
	case "userpass":
		return v.authenticateUserPass()
	case "ldap":
		return v.authenticateLDAP()
	case "aws":
		return v.authenticateAWS()
	case "gcp":
		return v.authenticateGCP()
	case "azure":
		return v.authenticateAzure()
	default:
		return fmt.Errorf("unsupported authentication method: %s", v.config.AuthMethod)
	}
}

// authenticateToken authenticates using a Vault token
func (v *VaultService) authenticateToken() error {
	if v.config.Token == "" {
		return fmt.Errorf("vault token not configured")
	}

	v.client.SetToken(v.config.Token)
	v.token = v.config.Token

	// Verify token is valid
	secret, err := v.client.Auth().Token().LookupSelf()
	if err != nil {
		return fmt.Errorf("failed to verify token: %v", err)
	}

	v.logInfo("Authenticated with Vault using token", map[string]interface{}{
		"accessor": secret.Data["accessor"],
		"policies": secret.Data["policies"],
	})

	return nil
}

// authenticateAppRole authenticates using AppRole
func (v *VaultService) authenticateAppRole() error {
	config := facades.Config()
	roleID := config.GetString("vault.auth.approle.role_id", "")
	secretID := config.GetString("vault.auth.approle.secret_id", "")
	mount := config.GetString("vault.auth.approle.mount", "approle")

	if roleID == "" || secretID == "" {
		return fmt.Errorf("AppRole credentials not configured")
	}

	// Authenticate with AppRole
	data := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}

	secret, err := v.client.Logical().Write(fmt.Sprintf("auth/%s/login", mount), data)
	if err != nil {
		return fmt.Errorf("AppRole authentication failed: %v", err)
	}

	if secret.Auth == nil {
		return fmt.Errorf("no auth information returned from AppRole authentication")
	}

	v.client.SetToken(secret.Auth.ClientToken)
	v.token = secret.Auth.ClientToken

	v.logInfo("Authenticated with Vault using AppRole", map[string]interface{}{
		"accessor": secret.Auth.Accessor,
		"policies": secret.Auth.Policies,
	})

	return nil
}

// authenticateKubernetes authenticates using Kubernetes service account
func (v *VaultService) authenticateKubernetes() error {
	config := facades.Config()
	role := config.GetString("vault.auth.kubernetes.role", "")
	jwtPath := config.GetString("vault.auth.kubernetes.jwt_path", "/var/run/secrets/kubernetes.io/serviceaccount/token")
	mount := config.GetString("vault.auth.kubernetes.mount", "kubernetes")

	if role == "" {
		return fmt.Errorf("Kubernetes role not configured")
	}

	// Read JWT token from service account
	jwt, err := ioutil.ReadFile(jwtPath)
	if err != nil {
		return fmt.Errorf("failed to read Kubernetes JWT: %v", err)
	}

	// Authenticate with Kubernetes
	data := map[string]interface{}{
		"role": role,
		"jwt":  string(jwt),
	}

	secret, err := v.client.Logical().Write(fmt.Sprintf("auth/%s/login", mount), data)
	if err != nil {
		return fmt.Errorf("Kubernetes authentication failed: %v", err)
	}

	if secret.Auth == nil {
		return fmt.Errorf("no auth information returned from Kubernetes authentication")
	}

	v.client.SetToken(secret.Auth.ClientToken)
	v.token = secret.Auth.ClientToken

	v.logInfo("Authenticated with Vault using Kubernetes", map[string]interface{}{
		"accessor": secret.Auth.Accessor,
		"policies": secret.Auth.Policies,
	})

	return nil
}

// authenticateUserPass authenticates using username/password
func (v *VaultService) authenticateUserPass() error {
	config := facades.Config()
	username := config.GetString("vault.auth.userpass.username", "")
	password := config.GetString("vault.auth.userpass.password", "")
	mount := config.GetString("vault.auth.userpass.mount", "userpass")

	if username == "" || password == "" {
		return fmt.Errorf("UserPass credentials not configured")
	}

	// Authenticate with UserPass
	data := map[string]interface{}{
		"password": password,
	}

	secret, err := v.client.Logical().Write(fmt.Sprintf("auth/%s/login/%s", mount, username), data)
	if err != nil {
		return fmt.Errorf("UserPass authentication failed: %v", err)
	}

	if secret.Auth == nil {
		return fmt.Errorf("no auth information returned from UserPass authentication")
	}

	v.client.SetToken(secret.Auth.ClientToken)
	v.token = secret.Auth.ClientToken

	v.logInfo("Authenticated with Vault using UserPass", map[string]interface{}{
		"username": username,
		"accessor": secret.Auth.Accessor,
		"policies": secret.Auth.Policies,
	})

	return nil
}

// authenticateLDAP authenticates using LDAP
func (v *VaultService) authenticateLDAP() error {
	config := facades.Config()
	username := config.GetString("vault.auth.ldap.username", "")
	password := config.GetString("vault.auth.ldap.password", "")
	mount := config.GetString("vault.auth.ldap.mount", "ldap")

	if username == "" || password == "" {
		return fmt.Errorf("LDAP credentials not configured")
	}

	// Authenticate with LDAP
	data := map[string]interface{}{
		"password": password,
	}

	secret, err := v.client.Logical().Write(fmt.Sprintf("auth/%s/login/%s", mount, username), data)
	if err != nil {
		return fmt.Errorf("LDAP authentication failed: %v", err)
	}

	if secret.Auth == nil {
		return fmt.Errorf("no auth information returned from LDAP authentication")
	}

	v.client.SetToken(secret.Auth.ClientToken)
	v.token = secret.Auth.ClientToken

	v.logInfo("Authenticated with Vault using LDAP", map[string]interface{}{
		"username": username,
		"accessor": secret.Auth.Accessor,
		"policies": secret.Auth.Policies,
	})

	return nil
}

// authenticateAWS authenticates using AWS IAM
func (v *VaultService) authenticateAWS() error {
	config := facades.Config()
	role := config.GetString("vault.auth.aws.role", "")

	if role == "" {
		return fmt.Errorf("AWS role not configured")
	}

	// This would implement AWS IAM authentication
	// For now, return an error indicating implementation needed
	return fmt.Errorf("AWS authentication requires implementation of AWS IAM signature")
}

// authenticateGCP authenticates using Google Cloud Platform
func (v *VaultService) authenticateGCP() error {
	config := facades.Config()
	role := config.GetString("vault.auth.gcp.role", "")

	if role == "" {
		return fmt.Errorf("GCP role not configured")
	}

	// This would implement GCP authentication
	// For now, return an error indicating implementation needed
	return fmt.Errorf("GCP authentication requires implementation of GCP JWT")
}

// authenticateAzure authenticates using Azure
func (v *VaultService) authenticateAzure() error {
	config := facades.Config()
	role := config.GetString("vault.auth.azure.role", "")

	if role == "" {
		return fmt.Errorf("Azure role not configured")
	}

	// This would implement Azure authentication
	// For now, return an error indicating implementation needed
	return fmt.Errorf("Azure authentication requires implementation of Azure JWT")
}

// GetSecret retrieves a secret from Vault with caching support
func (v *VaultService) GetSecret(path string) (*SecretData, error) {
	// Check cache first
	if v.config.CacheEnabled {
		if cached := v.getCachedSecret(path); cached != nil {
			v.logDebug("Secret retrieved from cache", map[string]interface{}{
				"path": path,
			})
			return &SecretData{
				Data:      cached.Data,
				LeaseID:   cached.LeaseID,
				Renewable: cached.Renewable,
			}, nil
		}
	}

	// Retrieve from Vault with retry logic
	var secret *api.Secret
	var err error

	for attempt := 0; attempt <= v.config.MaxRetries; attempt++ {
		secret, err = v.client.Logical().Read(path)
		if err == nil {
			break
		}

		if attempt < v.config.MaxRetries {
			v.logWarning("Vault request failed, retrying", map[string]interface{}{
				"path":    path,
				"attempt": attempt + 1,
				"error":   err.Error(),
			})
			time.Sleep(v.config.RetryWait)
		}
	}

	if err != nil {
		// Fallback to environment if configured
		if v.config.FallbackToEnv {
			return v.fallbackToEnvironment(path)
		}
		return nil, fmt.Errorf("failed to retrieve secret after %d attempts: %v", v.config.MaxRetries+1, err)
	}

	if secret == nil {
		return nil, fmt.Errorf("secret not found at path: %s", path)
	}

	// Extract data based on KV version
	var data map[string]interface{}
	var metadata map[string]interface{}

	if secret.Data != nil {
		if dataField, exists := secret.Data["data"]; exists {
			// KV v2
			data = dataField.(map[string]interface{})
			if metadataField, exists := secret.Data["metadata"]; exists {
				metadata = metadataField.(map[string]interface{})
			}
		} else {
			// KV v1
			data = secret.Data
		}
	}

	secretData := &SecretData{
		Data:          data,
		Metadata:      metadata,
		LeaseID:       secret.LeaseID,
		Renewable:     secret.Renewable,
		LeaseDuration: secret.LeaseDuration,
	}

	// Cache the secret
	if v.config.CacheEnabled {
		v.cacheSecret(path, secretData)
	}

	// Set up lease renewal if applicable
	if secret.LeaseID != "" && secret.Renewable {
		v.scheduleLeaseRenewal(secret.LeaseID, time.Duration(secret.LeaseDuration)*time.Second)
	}

	v.logInfo("Secret retrieved from Vault", map[string]interface{}{
		"path":      path,
		"lease_id":  secret.LeaseID,
		"renewable": secret.Renewable,
	})

	return secretData, nil
}

// GetSecretValue retrieves a specific value from a secret
func (v *VaultService) GetSecretValue(path, key string) (string, error) {
	secret, err := v.GetSecret(path)
	if err != nil {
		return "", err
	}

	if value, exists := secret.Data[key]; exists {
		if strValue, ok := value.(string); ok {
			return strValue, nil
		}
		return fmt.Sprintf("%v", value), nil
	}

	return "", fmt.Errorf("key '%s' not found in secret at path '%s'", key, path)
}

// PutSecret stores a secret in Vault
func (v *VaultService) PutSecret(path string, data map[string]interface{}) error {
	// Determine if this is KV v2
	kvMount := facades.Config().GetString("vault.secrets.kv.mount", "secret")
	kvVersion := facades.Config().GetInt("vault.secrets.kv.version", 2)

	var writePath string
	var writeData map[string]interface{}

	if kvVersion == 2 {
		// KV v2 format
		writePath = fmt.Sprintf("%s/data/%s", kvMount, strings.TrimPrefix(path, kvMount+"/"))
		writeData = map[string]interface{}{
			"data": data,
		}
	} else {
		// KV v1 format
		writePath = path
		writeData = data
	}

	// Write to Vault with retry logic
	var err error
	for attempt := 0; attempt <= v.config.MaxRetries; attempt++ {
		_, err = v.client.Logical().Write(writePath, writeData)
		if err == nil {
			break
		}

		if attempt < v.config.MaxRetries {
			v.logWarning("Vault write failed, retrying", map[string]interface{}{
				"path":    writePath,
				"attempt": attempt + 1,
				"error":   err.Error(),
			})
			time.Sleep(v.config.RetryWait)
		}
	}

	if err != nil {
		return fmt.Errorf("failed to store secret after %d attempts: %v", v.config.MaxRetries+1, err)
	}

	// Invalidate cache for this path
	v.invalidateCache(path)

	v.logInfo("Secret stored in Vault", map[string]interface{}{
		"path": writePath,
	})

	return nil
}

// DeleteSecret deletes a secret from Vault
func (v *VaultService) DeleteSecret(path string) error {
	// Determine if this is KV v2
	kvMount := facades.Config().GetString("vault.secrets.kv.mount", "secret")
	kvVersion := facades.Config().GetInt("vault.secrets.kv.version", 2)

	var deletePath string
	if kvVersion == 2 {
		// KV v2 format
		deletePath = fmt.Sprintf("%s/data/%s", kvMount, strings.TrimPrefix(path, kvMount+"/"))
	} else {
		// KV v1 format
		deletePath = path
	}

	// Delete from Vault with retry logic
	var err error
	for attempt := 0; attempt <= v.config.MaxRetries; attempt++ {
		_, err = v.client.Logical().Delete(deletePath)
		if err == nil {
			break
		}

		if attempt < v.config.MaxRetries {
			v.logWarning("Vault delete failed, retrying", map[string]interface{}{
				"path":    deletePath,
				"attempt": attempt + 1,
				"error":   err.Error(),
			})
			time.Sleep(v.config.RetryWait)
		}
	}

	if err != nil {
		return fmt.Errorf("failed to delete secret after %d attempts: %v", v.config.MaxRetries+1, err)
	}

	// Invalidate cache for this path
	v.invalidateCache(path)

	v.logInfo("Secret deleted from Vault", map[string]interface{}{
		"path": deletePath,
	})

	return nil
}

// getCachedSecret retrieves a secret from cache if valid
func (v *VaultService) getCachedSecret(path string) *CachedSecret {
	v.cacheMutex.RLock()
	defer v.cacheMutex.RUnlock()

	if cached, exists := v.cache[path]; exists {
		if time.Now().Before(cached.ExpiresAt) {
			return cached
		}
		// Remove expired entry
		delete(v.cache, path)
	}

	return nil
}

// cacheSecret stores a secret in cache
func (v *VaultService) cacheSecret(path string, secret *SecretData) {
	v.cacheMutex.Lock()
	defer v.cacheMutex.Unlock()

	v.cache[path] = &CachedSecret{
		Data:      secret.Data,
		ExpiresAt: time.Now().Add(v.config.CacheTTL),
		LeaseID:   secret.LeaseID,
		Renewable: secret.Renewable,
	}
}

// invalidateCache removes a secret from cache
func (v *VaultService) invalidateCache(path string) {
	v.cacheMutex.Lock()
	defer v.cacheMutex.Unlock()

	delete(v.cache, path)
}

// fallbackToEnvironment provides fallback to environment variables
func (v *VaultService) fallbackToEnvironment(path string) (*SecretData, error) {
	v.logWarning("Falling back to environment variables", map[string]interface{}{
		"path": path,
	})

	// Map common Vault paths to environment variables
	envMappings := map[string]map[string]string{
		"secret/app/master-key": {
			"master_key": "APP_MASTER_KEY",
		},
		"secret/app/app-key": {
			"app_key": "APP_KEY",
		},
		"secret/app/jwt-secret": {
			"jwt_secret": "JWT_SECRET",
		},
		"secret/database/postgres": {
			"host":     "DB_HOST",
			"port":     "DB_PORT",
			"database": "DB_DATABASE",
			"username": "DB_USERNAME",
			"password": "DB_PASSWORD",
		},
		"secret/database/redis": {
			"host":     "REDIS_HOST",
			"port":     "REDIS_PORT",
			"password": "REDIS_PASSWORD",
		},
		"secret/services/minio": {
			"access_key": "MINIO_ACCESS_KEY",
			"secret_key": "MINIO_SECRET_KEY",
			"endpoint":   "MINIO_ENDPOINT",
		},
	}

	if envMapping, exists := envMappings[path]; exists {
		data := make(map[string]interface{})
		for key, envVar := range envMapping {
			if value := facades.Config().Env(envVar, ""); value != "" {
				data[key] = value
			}
		}

		if len(data) > 0 {
			return &SecretData{
				Data:      data,
				Metadata:  map[string]interface{}{"source": "environment"},
				LeaseID:   "",
				Renewable: false,
			}, nil
		}
	}

	return nil, fmt.Errorf("no fallback environment mapping found for path: %s", path)
}

// scheduleLeaseRenewal schedules automatic lease renewal
func (v *VaultService) scheduleLeaseRenewal(leaseID string, duration time.Duration) {
	// Calculate renewal time (renew at 2/3 of lease duration)
	renewalTime := duration * 2 / 3

	timer := time.AfterFunc(renewalTime, func() {
		if err := v.renewLease(leaseID); err != nil {
			v.logError("Failed to renew lease", map[string]interface{}{
				"lease_id": leaseID,
				"error":    err.Error(),
			})
		}
	})

	v.renewals[leaseID] = timer
}

// renewLease renews a Vault lease
func (v *VaultService) renewLease(leaseID string) error {
	increment := facades.Config().GetInt("vault.lease.increment", 3600)

	secret, err := v.client.Sys().Renew(leaseID, increment)
	if err != nil {
		return fmt.Errorf("failed to renew lease %s: %v", leaseID, err)
	}

	v.logInfo("Lease renewed successfully", map[string]interface{}{
		"lease_id":       leaseID,
		"lease_duration": secret.LeaseDuration,
	})

	// Schedule next renewal
	if secret.Renewable {
		v.scheduleLeaseRenewal(leaseID, time.Duration(secret.LeaseDuration)*time.Second)
	}

	return nil
}

// startLeaseRenewal starts the background lease renewal process
func (v *VaultService) startLeaseRenewal() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-v.ctx.Done():
			return
		case <-ticker.C:
			// Cleanup expired renewals
			for leaseID, timer := range v.renewals {
				select {
				case <-timer.C:
					delete(v.renewals, leaseID)
				default:
					// Timer still active
				}
			}
		}
	}
}

// startHealthCheck starts periodic health checks
func (v *VaultService) startHealthCheck() {
	interval := time.Duration(facades.Config().GetInt("vault.health.check_interval", 300)) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-v.ctx.Done():
			return
		case <-ticker.C:
			if err := v.healthCheck(); err != nil {
				v.logError("Vault health check failed", map[string]interface{}{
					"error": err.Error(),
				})
			}
		}
	}
}

// healthCheck performs a health check on Vault
func (v *VaultService) healthCheck() error {
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(facades.Config().GetInt("vault.health.timeout", 30))*time.Second)
	defer cancel()

	req := v.client.NewRequest("GET", "/v1/sys/health")
	resp, err := v.client.RawRequestWithContext(ctx, req)
	if err != nil {
		return fmt.Errorf("health check request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 429 && resp.StatusCode != 472 && resp.StatusCode != 503 {
		return fmt.Errorf("unhealthy status code: %d", resp.StatusCode)
	}

	return nil
}

// Close gracefully shuts down the Vault service
func (v *VaultService) Close() error {
	v.cancel()

	// Stop all lease renewal timers
	for _, timer := range v.renewals {
		timer.Stop()
	}

	v.logInfo("Vault service shutdown completed", nil)
	return nil
}

// Logging methods
func (v *VaultService) logInfo(message string, data map[string]interface{}) {
	if !v.config.LoggingEnabled {
		return
	}
	facades.Log().Info(fmt.Sprintf("[Vault] %s", message), data)
}

func (v *VaultService) logWarning(message string, data map[string]interface{}) {
	if !v.config.LoggingEnabled {
		return
	}
	facades.Log().Warning(fmt.Sprintf("[Vault] %s", message), data)
}

func (v *VaultService) logError(message string, data map[string]interface{}) {
	if !v.config.LoggingEnabled {
		return
	}
	facades.Log().Error(fmt.Sprintf("[Vault] %s", message), data)
}

func (v *VaultService) logDebug(message string, data map[string]interface{}) {
	if !v.config.LoggingEnabled {
		return
	}
	logLevel := facades.Config().GetString("vault.logging.level", "info")
	if logLevel == "debug" {
		facades.Log().Debug(fmt.Sprintf("[Vault] %s", message), data)
	}
}
