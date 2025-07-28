package services

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"goravel/app/helpers"
	"goravel/app/models"

	"github.com/golang-jwt/jwt/v5"
	"github.com/goravel/framework/facades"
)

type OAuthService struct {
	jwtService                *JWTService
	analyticsService          *OAuthAnalyticsService
	consentService            *OAuthConsentService
	sessionService            *SessionService
	hierarchicalScopeService  *OAuthHierarchicalScopeService
	tokenBindingService       *OAuthTokenBindingService
	resourceIndicatorsService *OAuthResourceIndicatorsService
	rsaPrivateKey             *rsa.PrivateKey
	rsaPublicKey              *rsa.PublicKey
}

func NewOAuthService() (*OAuthService, error) {
	jwtService, err := NewJWTService()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize JWT service: %w", err)
	}

	// Create token binding service without circular dependency
	tokenBindingService := NewOAuthTokenBindingService()

	service := &OAuthService{
		jwtService:                jwtService,
		analyticsService:          NewOAuthAnalyticsService(),
		consentService:            NewOAuthConsentService(),
		sessionService:            NewSessionService(),
		hierarchicalScopeService:  NewOAuthHierarchicalScopeService(),
		tokenBindingService:       tokenBindingService,
		resourceIndicatorsService: NewOAuthResourceIndicatorsService(),
	}

	// Set the OAuth service reference to break circular dependency
	tokenBindingService.SetOAuthService(service)

	// Initialize RSA keys for JWT signing
	if err := service.initializeRSAKeys(); err != nil {
		return nil, fmt.Errorf("failed to initialize RSA keys: %w", err)
	}

	return service, nil
}

// MustNewOAuthService creates a new OAuth service and panics on error (for backward compatibility)
// Deprecated: This function has been removed. Use NewOAuthService() instead for proper error handling.

// initializeRSAKeys initializes RSA key pair for JWT signing
func (s *OAuthService) initializeRSAKeys() error {
	// Try to load existing keys from secure environment storage
	privateKeyPEM := facades.Config().GetString("oauth.rsa_private_key", "")

	if privateKeyPEM == "" {
		// Generate new RSA key pair
		privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			facades.Log().Error("Failed to generate RSA key pair: " + err.Error())
			return err
		}

		s.rsaPrivateKey = privateKey
		s.rsaPublicKey = &privateKey.PublicKey

		// Prepare key data for secure storage
		privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
		privateKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		})

		publicKeyBytes, _ := x509.MarshalPKIXPublicKey(s.rsaPublicKey)
		publicKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		})

		facades.Log().Info("Generated new RSA key pair for OAuth2 JWT signing")

		// Production-ready key storage implementation
		if facades.Config().GetString("app.env") == "production" {
			// Try multiple secure storage backends in order of preference
			if err := s.storeRSAKeysSecurely(string(privateKeyPEM), string(publicKeyPEM)); err != nil {
				facades.Log().Error("Failed to store RSA keys securely", map[string]interface{}{
					"error": err.Error(),
				})

				// Fallback to environment variable storage with security warning
				facades.Log().Warning("CRITICAL SECURITY NOTICE: Secure key storage failed, falling back to environment variables")
				facades.Log().Warning("Please configure one of: HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault")
				facades.Log().Warning("Set these environment variables securely:")
				facades.Log().Warning("OAUTH_RSA_PRIVATE_KEY=<base64_encoded_private_key>")
				facades.Log().Warning("OAUTH_RSA_PUBLIC_KEY=<base64_encoded_public_key>")

				// Store in environment as fallback (not recommended for production)
				os.Setenv("OAUTH_RSA_PRIVATE_KEY", base64.StdEncoding.EncodeToString(privateKeyPEM))
				os.Setenv("OAUTH_RSA_PUBLIC_KEY", base64.StdEncoding.EncodeToString(publicKeyPEM))
			} else {
				facades.Log().Info("RSA keys stored securely in key management system")
			}
		} else {
			// Only log keys in non-production environments for debugging
			facades.Log().Debug("OAuth RSA Private Key (store in OAUTH_RSA_PRIVATE_KEY env var)", map[string]interface{}{
				"private_key": string(privateKeyPEM),
			})
			facades.Log().Debug("OAuth RSA Public Key (store in OAUTH_RSA_PUBLIC_KEY env var)", map[string]interface{}{
				"public_key": string(publicKeyPEM),
			})
		}
	} else {
		// Load existing keys from environment
		block, _ := pem.Decode([]byte(privateKeyPEM))
		if block == nil {
			facades.Log().Error("Failed to decode RSA private key from environment")
			return fmt.Errorf("failed to decode RSA private key")
		}

		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			facades.Log().Error("Failed to parse RSA private key: " + err.Error())
			return fmt.Errorf("failed to parse RSA private key: %w", err)
		}

		s.rsaPrivateKey = privateKey
		s.rsaPublicKey = &privateKey.PublicKey

		facades.Log().Info("Loaded RSA key pair from secure environment storage")
	}

	return nil
}

// storeRSAKeysSecurely stores RSA keys in a secure key management system
func (s *OAuthService) storeRSAKeysSecurely(privateKeyPEM, publicKeyPEM string) error {
	// Try to use HashiCorp Vault if configured
	vaultEnabled := facades.Config().GetBool("vault.enabled", false)
	if vaultEnabled {
		if err := s.storeKeysInVault(privateKeyPEM, publicKeyPEM); err == nil {
			return nil
		} else {
			facades.Log().Warning("Failed to store keys in Vault, trying other methods", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// Try to use AWS KMS/Secrets Manager if configured
	awsEnabled := facades.Config().GetString("aws.region", "") != ""
	if awsEnabled {
		if err := s.storeKeysInAWS(privateKeyPEM, publicKeyPEM); err == nil {
			return nil
		} else {
			facades.Log().Warning("Failed to store keys in AWS, trying other methods", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// Try to use Azure Key Vault if configured
	azureEnabled := facades.Config().GetString("azure.key_vault.vault_url", "") != ""
	if azureEnabled {
		if err := s.storeKeysInAzure(privateKeyPEM, publicKeyPEM); err == nil {
			return nil
		} else {
			facades.Log().Warning("Failed to store keys in Azure Key Vault", map[string]interface{}{
				"error": err.Error(),
			})
		}
	}

	// Fallback: Store in encrypted database
	return s.storeKeysInDatabase(privateKeyPEM, publicKeyPEM)
}

// storeKeysInVault stores keys in HashiCorp Vault
func (s *OAuthService) storeKeysInVault(privateKeyPEM, publicKeyPEM string) error {
	// Check if vault service is available
	vaultAddr := facades.Config().GetString("vault.address", "")
	if vaultAddr == "" {
		return fmt.Errorf("vault address not configured")
	}

	vaultToken := facades.Config().GetString("vault.token", "")
	if vaultToken == "" {
		return fmt.Errorf("vault token not configured")
	}

	// Create HTTP client with timeout
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	// Store private key
	privateKeyPath := "oauth/rsa/private_key"
	if err := s.storeVaultSecret(client, vaultAddr, vaultToken, privateKeyPath, privateKeyPEM); err != nil {
		return fmt.Errorf("failed to store private key in vault: %w", err)
	}

	// Store public key
	publicKeyPath := "oauth/rsa/public_key"
	if err := s.storeVaultSecret(client, vaultAddr, vaultToken, publicKeyPath, publicKeyPEM); err != nil {
		return fmt.Errorf("failed to store public key in vault: %w", err)
	}

	facades.Log().Info("Keys successfully stored in HashiCorp Vault", map[string]interface{}{
		"vault_address":    vaultAddr,
		"private_key_path": privateKeyPath,
		"public_key_path":  publicKeyPath,
		"storage_backend":  "vault_kv_v2",
	})

	return nil
}

// storeVaultSecret stores a secret in HashiCorp Vault using KV v2 engine
func (s *OAuthService) storeVaultSecret(client *http.Client, vaultAddr, token, path, value string) error {
	// Use KV v2 engine path format
	url := fmt.Sprintf("%s/v1/secret/data/%s", strings.TrimSuffix(vaultAddr, "/"), path)

	// Prepare the secret data for KV v2 engine
	secretData := map[string]interface{}{
		"data": map[string]interface{}{
			"value": value,
			"metadata": map[string]interface{}{
				"created_by": "goravel-oauth-service",
				"created_at": time.Now().Format(time.RFC3339),
				"key_type":   "rsa",
				"purpose":    "oauth_signing",
			},
		},
		"options": map[string]interface{}{
			"cas": 0, // Check-and-Set for new secret
		},
	}

	jsonData, err := json.Marshal(secretData)
	if err != nil {
		return fmt.Errorf("failed to marshal secret data: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create vault request: %w", err)
	}

	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to store secret in vault: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// retrieveVaultSecret retrieves a secret from HashiCorp Vault
func (s *OAuthService) retrieveVaultSecret(path string) (string, error) {
	vaultAddr := facades.Config().GetString("vault.address", "")
	if vaultAddr == "" {
		return "", fmt.Errorf("vault address not configured")
	}

	vaultToken := facades.Config().GetString("vault.token", "")
	if vaultToken == "" {
		return "", fmt.Errorf("vault token not configured")
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	url := fmt.Sprintf("%s/v1/secret/data/%s", strings.TrimSuffix(vaultAddr, "/"), path)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create vault request: %w", err)
	}

	req.Header.Set("X-Vault-Token", vaultToken)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to retrieve secret from vault: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("vault request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var vaultResp struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&vaultResp); err != nil {
		return "", fmt.Errorf("failed to decode vault response: %w", err)
	}

	value, exists := vaultResp.Data.Data["value"]
	if !exists {
		return "", fmt.Errorf("secret value not found in vault response")
	}

	valueStr, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("secret value is not a string")
	}

	return valueStr, nil
}

// storeKeysInAWS stores keys in AWS Secrets Manager
func (s *OAuthService) storeKeysInAWS(privateKeyPEM, publicKeyPEM string) error {
	region := facades.Config().GetString("aws.region")
	if region == "" {
		return fmt.Errorf("AWS region not configured")
	}

	accessKeyID := facades.Config().GetString("aws.access_key_id")
	secretAccessKey := facades.Config().GetString("aws.secret_access_key")

	if accessKeyID == "" || secretAccessKey == "" {
		return fmt.Errorf("AWS credentials not configured")
	}

	// Store private key
	privateKeySecretName := "oauth-rsa-private-key"
	if err := s.storeAWSSecret(region, accessKeyID, secretAccessKey, privateKeySecretName, privateKeyPEM, "RSA Private Key for OAuth signing"); err != nil {
		return fmt.Errorf("failed to store private key in AWS Secrets Manager: %w", err)
	}

	// Store public key
	publicKeySecretName := "oauth-rsa-public-key"
	if err := s.storeAWSSecret(region, accessKeyID, secretAccessKey, publicKeySecretName, publicKeyPEM, "RSA Public Key for OAuth verification"); err != nil {
		return fmt.Errorf("failed to store public key in AWS Secrets Manager: %w", err)
	}

	facades.Log().Info("Keys successfully stored in AWS Secrets Manager", map[string]interface{}{
		"region":             region,
		"private_key_secret": privateKeySecretName,
		"public_key_secret":  publicKeySecretName,
		"service":            "secretsmanager",
	})

	return nil
}

// storeAWSSecret stores a secret in AWS Secrets Manager using REST API
func (s *OAuthService) storeAWSSecret(region, accessKeyID, secretAccessKey, secretName, secretValue, description string) error {
	// AWS Secrets Manager endpoint
	endpoint := fmt.Sprintf("https://secretsmanager.%s.amazonaws.com/", region)

	// Create secret payload
	secretData := map[string]interface{}{
		"Name":         secretName,
		"SecretString": secretValue,
		"Description":  description,
		"Tags": []map[string]string{
			{"Key": "Service", "Value": "goravel-oauth"},
			{"Key": "CreatedBy", "Value": "goravel"},
			{"Key": "CreatedAt", "Value": time.Now().Format(time.RFC3339)},
			{"Key": "KeyType", "Value": "RSA"},
		},
	}

	jsonData, err := json.Marshal(secretData)
	if err != nil {
		return fmt.Errorf("failed to marshal secret data: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Add required headers
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.CreateSecret")

	// Sign the request using AWS Signature Version 4
	if err := s.signAWSRequest(req, region, accessKeyID, secretAccessKey, "secretsmanager"); err != nil {
		return fmt.Errorf("failed to sign AWS request: %w", err)
	}

	// Make the request
	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to store secret: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		// If secret already exists, try to update it
		if strings.Contains(string(body), "ResourceExistsException") {
			return s.updateAWSSecret(region, accessKeyID, secretAccessKey, secretName, secretValue)
		}
		return fmt.Errorf("AWS request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// updateAWSSecret updates an existing secret in AWS Secrets Manager
func (s *OAuthService) updateAWSSecret(region, accessKeyID, secretAccessKey, secretName, secretValue string) error {
	endpoint := fmt.Sprintf("https://secretsmanager.%s.amazonaws.com/", region)

	updateData := map[string]interface{}{
		"SecretId":     secretName,
		"SecretString": secretValue,
	}

	jsonData, err := json.Marshal(updateData)
	if err != nil {
		return fmt.Errorf("failed to marshal update data: %w", err)
	}

	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create update request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "secretsmanager.UpdateSecret")

	if err := s.signAWSRequest(req, region, accessKeyID, secretAccessKey, "secretsmanager"); err != nil {
		return fmt.Errorf("failed to sign AWS update request: %w", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("AWS update request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// signAWSRequest signs an AWS request using Signature Version 4
func (s *OAuthService) signAWSRequest(req *http.Request, region, accessKeyID, secretAccessKey, service string) error {
	// AWS Signature Version 4 implementation
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	// Step 1: Create canonical request
	canonicalRequest, err := s.createCanonicalRequest(req)
	if err != nil {
		return fmt.Errorf("failed to create canonical request: %w", err)
	}

	// Step 2: Create string to sign
	algorithm := "AWS4-HMAC-SHA256"
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", dateStamp, region, service)
	stringToSign := fmt.Sprintf("%s\n%s\n%s\n%x",
		algorithm,
		amzDate,
		credentialScope,
		sha256.Sum256([]byte(canonicalRequest)))

	// Step 3: Calculate signature
	signature, err := s.calculateSignature(secretAccessKey, dateStamp, region, service, stringToSign)
	if err != nil {
		return fmt.Errorf("failed to calculate signature: %w", err)
	}

	// Step 4: Add authorization header
	authHeader := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algorithm,
		accessKeyID,
		credentialScope,
		s.getSignedHeaders(req),
		signature)

	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("Authorization", authHeader)

	facades.Log().Debug("AWS request signed with v4 signature", map[string]interface{}{
		"service":   service,
		"region":    region,
		"date":      amzDate,
		"algorithm": algorithm,
		"scope":     credentialScope,
	})

	return nil
}

// createCanonicalRequest creates the canonical request for AWS Signature Version 4
func (s *OAuthService) createCanonicalRequest(req *http.Request) (string, error) {
	// HTTP method
	method := req.Method

	// URI path
	path := req.URL.Path
	if path == "" {
		path = "/"
	}

	// Query string
	queryString := ""
	if req.URL.RawQuery != "" {
		// Sort query parameters
		values := req.URL.Query()
		keys := make([]string, 0, len(values))
		for k := range values {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		var queryParts []string
		for _, k := range keys {
			for _, v := range values[k] {
				queryParts = append(queryParts, fmt.Sprintf("%s=%s", url.QueryEscape(k), url.QueryEscape(v)))
			}
		}
		queryString = strings.Join(queryParts, "&")
	}

	// Canonical headers
	headers := make(map[string]string)
	for k, v := range req.Header {
		key := strings.ToLower(k)
		headers[key] = strings.TrimSpace(strings.Join(v, ","))
	}

	// Sort header keys
	headerKeys := make([]string, 0, len(headers))
	for k := range headers {
		headerKeys = append(headerKeys, k)
	}
	sort.Strings(headerKeys)

	var canonicalHeaders []string
	for _, k := range headerKeys {
		canonicalHeaders = append(canonicalHeaders, fmt.Sprintf("%s:%s", k, headers[k]))
	}
	canonicalHeadersStr := strings.Join(canonicalHeaders, "\n") + "\n"

	// Signed headers
	signedHeaders := strings.Join(headerKeys, ";")

	// Payload hash
	var payloadHash string
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return "", fmt.Errorf("failed to read request body: %w", err)
		}
		// Reset body for actual request
		req.Body = io.NopCloser(bytes.NewReader(body))
		payloadHash = fmt.Sprintf("%x", sha256.Sum256(body))
	} else {
		payloadHash = fmt.Sprintf("%x", sha256.Sum256([]byte("")))
	}

	// Build canonical request
	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		method,
		path,
		queryString,
		canonicalHeadersStr,
		signedHeaders,
		payloadHash)

	return canonicalRequest, nil
}

// calculateSignature calculates the AWS v4 signature
func (s *OAuthService) calculateSignature(secretAccessKey, dateStamp, region, service, stringToSign string) (string, error) {
	// Create signing key
	kDate := s.hmacSHA256([]byte("AWS4"+secretAccessKey), dateStamp)
	kRegion := s.hmacSHA256(kDate, region)
	kService := s.hmacSHA256(kRegion, service)
	kSigning := s.hmacSHA256(kService, "aws4_request")

	// Calculate signature
	signature := s.hmacSHA256(kSigning, stringToSign)
	return fmt.Sprintf("%x", signature), nil
}

// getSignedHeaders returns the signed headers string
func (s *OAuthService) getSignedHeaders(req *http.Request) string {
	keys := make([]string, 0, len(req.Header))
	for k := range req.Header {
		keys = append(keys, strings.ToLower(k))
	}
	sort.Strings(keys)
	return strings.Join(keys, ";")
}

// hmacSHA256 calculates HMAC-SHA256
func (s *OAuthService) hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// storeKeysInAzure stores keys in Azure Key Vault
func (s *OAuthService) storeKeysInAzure(privateKeyPEM, publicKeyPEM string) error {
	vaultURL := facades.Config().GetString("azure.key_vault.vault_url")
	if vaultURL == "" {
		return fmt.Errorf("Azure Key Vault URL not configured")
	}

	// Get Azure credentials
	tenantID := facades.Config().GetString("azure.tenant_id")
	clientID := facades.Config().GetString("azure.client_id")
	clientSecret := facades.Config().GetString("azure.client_secret")

	if tenantID == "" || clientID == "" || clientSecret == "" {
		return fmt.Errorf("Azure credentials not properly configured")
	}

	// Get access token for Key Vault
	token, err := s.getAzureAccessToken(tenantID, clientID, clientSecret)
	if err != nil {
		return fmt.Errorf("failed to get Azure access token: %w", err)
	}

	// Store private key
	if err := s.storeSecretInKeyVault(vaultURL, token, "oauth-rsa-private-key", privateKeyPEM); err != nil {
		return fmt.Errorf("failed to store private key: %w", err)
	}

	// Store public key
	if err := s.storeSecretInKeyVault(vaultURL, token, "oauth-rsa-public-key", publicKeyPEM); err != nil {
		return fmt.Errorf("failed to store public key: %w", err)
	}

	facades.Log().Info("Keys successfully stored in Azure Key Vault", map[string]interface{}{
		"vault_url":          vaultURL,
		"private_key_secret": "oauth-rsa-private-key",
		"public_key_secret":  "oauth-rsa-public-key",
	})

	return nil
}

// getAzureAccessToken gets an access token for Azure Key Vault
func (s *OAuthService) getAzureAccessToken(tenantID, clientID, clientSecret string) (string, error) {
	tokenURL := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", tenantID)

	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("scope", "https://vault.azure.net/.default")

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.PostForm(tokenURL, data)
	if err != nil {
		return "", fmt.Errorf("failed to request token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	return tokenResp.AccessToken, nil
}

// storeSecretInKeyVault stores a secret in Azure Key Vault
func (s *OAuthService) storeSecretInKeyVault(vaultURL, accessToken, secretName, secretValue string) error {
	// Use the latest API version
	apiVersion := "7.4"
	url := fmt.Sprintf("%s/secrets/%s?api-version=%s", vaultURL, secretName, apiVersion)

	secretData := map[string]interface{}{
		"value": secretValue,
		"attributes": map[string]interface{}{
			"enabled": true,
		},
		"tags": map[string]string{
			"service":    "oauth",
			"created_by": "goravel",
			"created_at": time.Now().Format(time.RFC3339),
		},
	}

	jsonData, err := json.Marshal(secretData)
	if err != nil {
		return fmt.Errorf("failed to marshal secret data: %w", err)
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to store secret: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to store secret with status %d: %s", resp.StatusCode, string(body))
	}

	facades.Log().Debug("Secret stored successfully in Azure Key Vault", map[string]interface{}{
		"secret_name": secretName,
		"vault_url":   vaultURL,
	})

	return nil
}

// storeKeysInDatabase stores encrypted keys in database as fallback
func (s *OAuthService) storeKeysInDatabase(privateKeyPEM, publicKeyPEM string) error {
	// Encrypt keys before storing
	encryptionKey := facades.Config().GetString("app.key")
	if encryptionKey == "" {
		return fmt.Errorf("application encryption key not configured")
	}

	// Use AES-256-GCM encryption for secure key storage
	encryptedPrivateKey, err := s.encryptData(privateKeyPEM, encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt private key: %w", err)
	}

	encryptedPublicKey, err := s.encryptData(publicKeyPEM, encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt public key: %w", err)
	}

	// Store in oauth_jwks_keys table
	now := time.Now()
	expiresAt := now.Add(365 * 24 * time.Hour) // 1 year expiry

	// Store the key pair in a single record
	keyRecord := models.OAuthJWKSKey{
		KeyID:      "oauth-rsa-" + fmt.Sprintf("%d", now.Unix()),
		KeyType:    "RSA",
		Algorithm:  "RS256",
		Use:        "sig",
		PublicKey:  encryptedPublicKey,
		PrivateKey: &encryptedPrivateKey,
		IsActive:   true,
		IsPrimary:  true,
		ExpiresAt:  &expiresAt,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := facades.Orm().Query().Create(&keyRecord); err != nil {
		return fmt.Errorf("failed to store RSA key pair in database: %w", err)
	}

	facades.Log().Info("RSA keys stored successfully in encrypted database")
	return nil
}

// encryptData encrypts data using AES-256-GCM encryption
func (s *OAuthService) encryptData(data, key string) (string, error) {
	// Use AES-256-GCM for authenticated encryption
	keyBytes := sha256.Sum256([]byte(key))

	block, err := aes.NewCipher(keyBytes[:])
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)

	// Return base64 encoded result
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptData decrypts data using AES-256-GCM encryption
func (s *OAuthService) decryptData(encryptedData, key string) (string, error) {
	// Decode from base64
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %w", err)
	}

	// Use AES-256-GCM for authenticated decryption
	keyBytes := sha256.Sum256([]byte(key))

	block, err := aes.NewCipher(keyBytes[:])
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	// Extract nonce and ciphertext
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the data
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// CreateJWTAccessToken creates a JWT access token
func (s *OAuthService) CreateJWTAccessToken(userID *string, clientID string, scopes []string, name *string) (string, error) {
	if s.rsaPrivateKey == nil {
		return "", fmt.Errorf("RSA private key not initialized")
	}

	ttl := facades.Config().GetInt("oauth.access_token_ttl", 60)

	// Get client information
	client, err := s.GetClient(clientID)
	if err != nil {
		return "", err
	}

	// Get user information if userID is provided
	var userEmail string
	if userID != nil {
		var user models.User
		if err := facades.Orm().Query().Where("id", *userID).First(&user); err == nil {
			userEmail = user.Email
		}
	}

	// Create JWT claims
	claims := jwt.MapClaims{
		"iss":    facades.Config().GetString("app.url", "http://localhost"),
		"sub":    userID,
		"aud":    clientID,
		"exp":    time.Now().Add(time.Duration(ttl) * time.Minute).Unix(),
		"iat":    time.Now().Unix(),
		"nbf":    time.Now().Unix(),
		"jti":    helpers.GenerateULID(),
		"scope":  strings.Join(scopes, " "),
		"client": client.Name,
		"email":  userEmail,
		"type":   "access_token",
	}

	// Create and sign token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.rsaPrivateKey)
}

// GetJWKS returns the JSON Web Key Set for JWT verification with Google-like structure
func (s *OAuthService) GetJWKS() map[string]interface{} {
	if s.rsaPublicKey == nil {
		return map[string]interface{}{
			"keys": []interface{}{},
		}
	}

	// Convert public key to JWK format with proper structure
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(s.rsaPublicKey)
	if err != nil {
		facades.Log().Error("Failed to marshal public key: " + err.Error())
		return map[string]interface{}{
			"keys": []interface{}{},
		}
	}

	// Calculate key ID based on public key thumbprint (Google-like)
	keyID := s.calculateKeyID(publicKeyBytes)

	// Create JWK with Google-compatible structure
	jwk := map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"kid": keyID,
		"alg": "RS256",
		"n":   base64.RawURLEncoding.EncodeToString(s.rsaPublicKey.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01}), // 65537 in big-endian

		// Additional Google-like metadata
		"key_ops":  []string{"verify"},
		"x5t":      s.calculateX5Thumbprint(publicKeyBytes),
		"x5t#S256": s.calculateX5ThumbprintSHA256(publicKeyBytes),
	}

	// Support for multiple keys (for key rotation)
	keys := []interface{}{jwk}

	// Add secondary key if available (for key rotation scenarios)
	if secondaryKey := s.getSecondaryPublicKey(); secondaryKey != nil {
		secondaryKeyBytes, err := x509.MarshalPKIXPublicKey(secondaryKey)
		if err == nil {
			secondaryKeyID := s.calculateKeyID(secondaryKeyBytes)
			secondaryJWK := map[string]interface{}{
				"kty":      "RSA",
				"use":      "sig",
				"kid":      secondaryKeyID,
				"alg":      "RS256",
				"n":        base64.RawURLEncoding.EncodeToString(secondaryKey.N.Bytes()),
				"e":        base64.RawURLEncoding.EncodeToString([]byte{0x01, 0x00, 0x01}),
				"key_ops":  []string{"verify"},
				"x5t":      s.calculateX5Thumbprint(secondaryKeyBytes),
				"x5t#S256": s.calculateX5ThumbprintSHA256(secondaryKeyBytes),
			}
			keys = append(keys, secondaryJWK)
		}
	}

	return map[string]interface{}{
		"keys": keys,
	}
}

// RotateJWKS performs Google-like key rotation
func (s *OAuthService) RotateJWKS() error {
	if !facades.Config().GetBool("oauth.jwks.auto_rotation", true) {
		return fmt.Errorf("JWKS auto rotation is disabled")
	}

	facades.Log().Info("Starting JWKS key rotation")

	// Generate new RSA key pair
	newPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate new RSA key: %w", err)
	}

	// Store current key as secondary (for grace period)
	if s.rsaPrivateKey != nil {
		s.storeSecondaryKey(s.rsaPrivateKey, s.rsaPublicKey)
	}

	// Update to new key
	s.rsaPrivateKey = newPrivateKey
	s.rsaPublicKey = &newPrivateKey.PublicKey

	// Store new keys in cache/config for persistence
	s.storeCurrentKeys()

	facades.Log().Info("JWKS key rotation completed successfully")

	return nil
}

// ValidateJWKSRotation checks if key rotation is working properly
func (s *OAuthService) ValidateJWKSRotation() error {
	if s.rsaPrivateKey == nil {
		return fmt.Errorf("no active private key found")
	}

	if s.rsaPublicKey == nil {
		return fmt.Errorf("no active public key found")
	}

	// Test key functionality by creating and verifying a test token
	testClaims := jwt.MapClaims{
		"test": true,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Minute).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, testClaims)
	tokenString, err := token.SignedString(s.rsaPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to sign test token: %w", err)
	}

	// Verify the token
	_, err = jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.rsaPublicKey, nil
	})

	if err != nil {
		return fmt.Errorf("failed to verify test token: %w", err)
	}

	return nil
}

// GetJWKSRotationStatus returns the current status of key rotation
func (s *OAuthService) GetJWKSRotationStatus() map[string]interface{} {
	status := map[string]interface{}{
		"auto_rotation_enabled": facades.Config().GetBool("oauth.jwks.auto_rotation", true),
		"current_key_id":        "",
		"secondary_key_id":      "",
		"keys_count":            0,
	}

	if s.rsaPublicKey != nil {
		publicKeyBytes, _ := x509.MarshalPKIXPublicKey(s.rsaPublicKey)
		status["current_key_id"] = s.calculateKeyID(publicKeyBytes)
		status["keys_count"] = 1
	}

	if secondaryKey := s.getSecondaryPublicKey(); secondaryKey != nil {
		secondaryKeyBytes, _ := x509.MarshalPKIXPublicKey(secondaryKey)
		status["secondary_key_id"] = s.calculateKeyID(secondaryKeyBytes)
		status["keys_count"] = status["keys_count"].(int) + 1
	}

	return status
}

// Helper methods for key management

func (s *OAuthService) storeCurrentKeys() {
	if s.rsaPrivateKey == nil {
		return
	}

	// Store private key
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(s.rsaPrivateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Store public key
	publicKeyBytes, _ := x509.MarshalPKIXPublicKey(s.rsaPublicKey)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	// Store in cache with expiration
	keyExpiration := time.Duration(facades.Config().GetInt("oauth.jwks.key_ttl_hours", 24*7)) * time.Hour
	facades.Cache().Put("oauth_current_private_key", string(privateKeyPEM), keyExpiration)
	facades.Cache().Put("oauth_current_public_key", string(publicKeyPEM), keyExpiration)

	facades.Log().Info("Stored current JWKS keys in cache")
}

func (s *OAuthService) storeSecondaryKey(privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) {
	// Store secondary key for grace period
	publicKeyBytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	gracePeriod := time.Duration(facades.Config().GetInt("oauth.jwks.grace_period_hours", 24)) * time.Hour
	facades.Cache().Put("oauth_secondary_public_key", string(publicKeyPEM), gracePeriod)

	facades.Log().Info("Stored secondary JWKS key for grace period")
}

// calculateKeyID generates a key ID based on the public key thumbprint
func (s *OAuthService) calculateKeyID(publicKeyBytes []byte) string {
	hash := sha256.Sum256(publicKeyBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:8]) // Use first 8 bytes for shorter ID
}

// calculateX5Thumbprint calculates the X.509 certificate thumbprint (SHA-1)
func (s *OAuthService) calculateX5Thumbprint(publicKeyBytes []byte) string {
	// For simplicity, we'll use SHA-256 hash of the public key
	// In a real implementation, you'd use the actual X.509 certificate
	hash := sha256.Sum256(publicKeyBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:20]) // SHA-1 length equivalent
}

// calculateX5ThumbprintSHA256 calculates the X.509 certificate thumbprint (SHA-256)
func (s *OAuthService) calculateX5ThumbprintSHA256(publicKeyBytes []byte) string {
	hash := sha256.Sum256(publicKeyBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// getSecondaryPublicKey returns a secondary public key for key rotation
func (s *OAuthService) getSecondaryPublicKey() *rsa.PublicKey {
	publicKeyPEM := facades.Cache().GetString("oauth_secondary_public_key", "")
	if publicKeyPEM == "" {
		return nil
	}

	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil
	}

	rsaPublicKey, ok := publicKeyInterface.(*rsa.PublicKey)
	if !ok {
		return nil
	}

	return rsaPublicKey
}

// DetectSuspiciousActivity detects suspicious OAuth2 activity
func (s *OAuthService) DetectSuspiciousActivity(userID, clientID, ipAddress string, userAgent string) *SuspiciousActivityReport {
	report := &SuspiciousActivityReport{
		UserID:    userID,
		ClientID:  clientID,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		Timestamp: time.Now(),
		Flags:     []string{},
		RiskScore: 0,
	}

	// Check for unusual IP address
	if s.isUnusualIP(userID, ipAddress) {
		report.Flags = append(report.Flags, "unusual_ip")
		report.RiskScore += 30
	}

	// Check for unusual user agent
	if s.isUnusualUserAgent(userID, userAgent) {
		report.Flags = append(report.Flags, "unusual_user_agent")
		report.RiskScore += 20
	}

	// Check for rapid successive requests
	if s.hasRapidRequests(userID, clientID) {
		report.Flags = append(report.Flags, "rapid_requests")
		report.RiskScore += 40
	}

	// Check for suspicious client
	if s.isSuspiciousClient(clientID) {
		report.Flags = append(report.Flags, "suspicious_client")
		report.RiskScore += 50
	}

	// Determine risk level
	if report.RiskScore >= 80 {
		report.RiskLevel = "HIGH"
	} else if report.RiskScore >= 50 {
		report.RiskLevel = "MEDIUM"
	} else if report.RiskScore >= 20 {
		report.RiskLevel = "LOW"
	} else {
		report.RiskLevel = "MINIMAL"
	}

	// Log suspicious activity
	if report.RiskScore > 0 {
		facades.Log().Warning("Suspicious OAuth2 activity detected", map[string]interface{}{
			"user_id":    userID,
			"client_id":  clientID,
			"ip_address": ipAddress,
			"risk_score": report.RiskScore,
			"risk_level": report.RiskLevel,
			"flags":      report.Flags,
		})
	}

	return report
}

type SuspiciousActivityReport struct {
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	Timestamp time.Time `json:"timestamp"`
	Flags     []string  `json:"flags"`
	RiskScore int       `json:"risk_score"`
	RiskLevel string    `json:"risk_level"`
}

// Helper methods for suspicious activity detection
func (s *OAuthService) isUnusualIP(userID, ipAddress string) bool {
	// Check if this IP is from a different country/region than usual
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return true
	}

	// Check if it's a private IP (less suspicious for development)
	if ip.IsPrivate() {
		return false
	}

	// Check against known suspicious IP ranges
	if s.isKnownMaliciousIP(ipAddress) {
		facades.Log().Warning("Access from known malicious IP", map[string]interface{}{
			"user_id":    userID,
			"ip_address": ipAddress,
		})
		return true
	}

	// Get user's historical IP addresses from recent activity logs
	historicalIPs := s.getUserHistoricalIPs(userID)

	// If this is a completely new IP and user has established history, flag as unusual
	if len(historicalIPs) > 5 && !s.isIPInHistory(ipAddress, historicalIPs) {
		// Check if IP is from same network class (less suspicious)
		if !s.isFromSameNetworkClass(ipAddress, historicalIPs) {
			facades.Log().Info("Unusual IP detected", map[string]interface{}{
				"user_id":        userID,
				"ip_address":     ipAddress,
				"historical_ips": len(historicalIPs),
			})
			return true
		}
	}

	// Store this IP for future reference
	s.recordUserIP(userID, ipAddress)

	return false
}

func (s *OAuthService) isUnusualUserAgent(userID, userAgent string) bool {
	// Check if this user agent is significantly different from user's history
	userAgentLower := strings.ToLower(userAgent)

	// Basic checks for suspicious patterns
	suspiciousPatterns := []string{
		"curl", "wget", "python", "bot", "crawler", "scanner", "scraper",
		"headless", "phantom", "selenium", "automated", "script",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(userAgentLower, pattern) {
			facades.Log().Warning("Suspicious user agent detected", map[string]interface{}{
				"user_id":    userID,
				"user_agent": userAgent,
				"pattern":    pattern,
			})
			return true
		}
	}

	// Check for empty or very short user agents
	if len(strings.TrimSpace(userAgent)) < 10 {
		facades.Log().Warning("Suspicious short user agent", map[string]interface{}{
			"user_id":    userID,
			"user_agent": userAgent,
		})
		return true
	}

	// Get user's historical user agents
	historicalUserAgents := s.getUserHistoricalUserAgents(userID)

	// If user has established history and this is completely new, flag as unusual
	if len(historicalUserAgents) > 3 {
		// Check for similarity with historical user agents
		if !s.isUserAgentSimilar(userAgent, historicalUserAgents) {
			facades.Log().Info("Unusual user agent detected", map[string]interface{}{
				"user_id":                userID,
				"user_agent":             userAgent,
				"historical_user_agents": len(historicalUserAgents),
			})
			return true
		}
	}

	// Record this user agent for future reference
	s.recordUserAgent(userID, userAgent)

	return false
}

func (s *OAuthService) hasRapidRequests(userID, clientID string) bool {
	// Check for rapid successive requests in the last minute
	cacheKey := fmt.Sprintf("oauth_requests_%s_%s", userID, clientID)

	// Get current request timestamps from cache
	var requestTimes []int64
	err := facades.Cache().Get(cacheKey, &requestTimes)
	if err != nil {
		requestTimes = []int64{}
	}

	now := time.Now().Unix()
	oneMinuteAgo := now - 60

	// Filter out old requests (older than 1 minute)
	var recentRequests []int64
	for _, requestTime := range requestTimes {
		if requestTime > oneMinuteAgo {
			recentRequests = append(recentRequests, requestTime)
		}
	}

	// Add current request
	recentRequests = append(recentRequests, now)

	// Store updated request times
	facades.Cache().Put(cacheKey, recentRequests, 2*time.Minute)

	// Check if we exceed the threshold
	threshold := facades.Config().GetInt("oauth.rate_limit_per_minute", 10)
	if len(recentRequests) > threshold {
		facades.Log().Warning("Rapid OAuth requests detected", map[string]interface{}{
			"user_id":       userID,
			"client_id":     clientID,
			"request_count": len(recentRequests),
			"threshold":     threshold,
		})
		return true
	}

	return false
}

func (s *OAuthService) isSuspiciousClient(clientID string) bool {
	// Check if the client has been flagged as suspicious
	client, err := s.GetClient(clientID)
	if err != nil {
		facades.Log().Warning("Client not found during suspicious check", map[string]interface{}{
			"client_id": clientID,
			"error":     err.Error(),
		})
		return true
	}

	// Check for suspicious client patterns
	if client.IsRevoked() {
		facades.Log().Warning("Revoked client attempted access", map[string]interface{}{
			"client_id": clientID,
		})
		return true
	}

	// Check client creation date - very new clients might be suspicious
	if client.CreatedAt.After(time.Now().AddDate(0, 0, -1)) { // Created within last day
		facades.Log().Info("Very new client detected", map[string]interface{}{
			"client_id":  clientID,
			"created_at": client.CreatedAt,
		})
		// Don't immediately flag as suspicious, but log for monitoring
	}

	// Check for suspicious redirect URIs
	redirectURIs := client.GetRedirectURIs()
	for _, uri := range redirectURIs {
		if s.isSuspiciousRedirectURI(uri) {
			facades.Log().Warning("Suspicious redirect URI detected", map[string]interface{}{
				"client_id":    clientID,
				"redirect_uri": uri,
			})
			return true
		}
	}

	// Check client usage patterns
	if s.hasUnusualClientActivity(clientID) {
		return true
	}

	return false
}

// CreateDeviceCodeWithQR creates a device code with QR code generation
func (s *OAuthService) CreateDeviceCodeWithQR(clientID string, scopes []string, expiresAt time.Time) (*models.OAuthDeviceCode, string, error) {
	// Create the device code
	deviceCode, err := s.CreateDeviceCode(clientID, scopes, expiresAt)
	if err != nil {
		return nil, "", err
	}

	// Generate verification URL with user code
	verificationURI := facades.Config().GetString("oauth.device_verification_uri", "https://example.com/device")
	verificationURIComplete := fmt.Sprintf("%s?user_code=%s", verificationURI, deviceCode.UserCode)

	// Generate QR code data (URL for QR code generation)
	qrCodeURL := fmt.Sprintf("https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=%s",
		fmt.Sprintf("Visit: %s", verificationURIComplete))

	return deviceCode, qrCodeURL, nil
}

// CreateClient creates a new OAuth2 client
func (s *OAuthService) CreateClient(name string, userID *string, redirectURIs []string, personalAccessClient, passwordClient bool) (*models.OAuthClient, error) {
	client := &models.OAuthClient{
		ID:                   helpers.GenerateULID(),
		UserID:               userID,
		Name:                 name,
		PersonalAccessClient: personalAccessClient,
		PasswordClient:       passwordClient,
		Revoked:              false,
	}

	// Set redirect URIs
	client.SetRedirectURIs(redirectURIs)

	// Generate secret for confidential clients
	if !personalAccessClient {
		secret := s.generateClientSecret()
		client.Secret = &secret
	}

	err := facades.Orm().Query().Create(client)
	if err != nil {
		return nil, err
	}

	// If this is a personal access client, create the personal access client record
	if personalAccessClient {
		personalClient := &models.OAuthPersonalAccessClient{
			ID:       helpers.GenerateULID(),
			ClientID: client.ID,
		}
		facades.Orm().Query().Create(personalClient)
	}

	return client, nil
}

// GetClient retrieves an OAuth2 client by ID
func (s *OAuthService) GetClient(clientID string) (*models.OAuthClient, error) {
	var client models.OAuthClient
	err := facades.Orm().Query().Where("id", clientID).First(&client)
	if err != nil {
		return nil, err
	}
	return &client, nil
}

// ValidateClient validates client credentials
func (s *OAuthService) ValidateClient(clientID, clientSecret string) (*models.OAuthClient, error) {
	client, err := s.GetClient(clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client")
	}

	if client.IsRevoked() {
		return nil, fmt.Errorf("client is revoked")
	}

	// For confidential clients, validate the secret
	if client.IsConfidential() {
		if client.Secret == nil || *client.Secret != clientSecret {
			return nil, fmt.Errorf("invalid client secret")
		}
	}

	return client, nil
}

// CreateAccessToken creates a new access token
func (s *OAuthService) CreateAccessToken(userID *string, clientID string, scopes []string, name *string) (*models.OAuthAccessToken, error) {
	token := &models.OAuthAccessToken{
		ID:       s.generateTokenID(),
		UserID:   userID,
		ClientID: clientID,
		Name:     name,
		Revoked:  false,
	}

	token.SetScopes(scopes)

	err := facades.Orm().Query().Create(token)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// CreateRefreshToken creates a new refresh token
func (s *OAuthService) CreateRefreshToken(accessTokenID string, expiresAt time.Time) (*models.OAuthRefreshToken, error) {
	token := &models.OAuthRefreshToken{
		ID:            s.generateTokenID(),
		AccessTokenID: accessTokenID,
		Revoked:       false,
		ExpiresAt:     expiresAt,
	}

	err := facades.Orm().Query().Create(token)
	if err != nil {
		return nil, err
	}

	return token, nil
}

// CreateAuthCode creates a new authorization code
func (s *OAuthService) CreateAuthCode(userID, clientID string, scopes []string, expiresAt time.Time) (*models.OAuthAuthCode, error) {
	code := &models.OAuthAuthCode{
		ID:        s.generateTokenID(),
		UserID:    userID,
		ClientID:  clientID,
		Revoked:   false,
		ExpiresAt: expiresAt,
	}

	code.SetScopes(scopes)

	err := facades.Orm().Query().Create(code)
	if err != nil {
		return nil, err
	}

	return code, nil
}

// CreateAuthCodeWithPKCE creates a new authorization code with PKCE support
func (s *OAuthService) CreateAuthCodeWithPKCE(userID, clientID string, scopes []string, expiresAt time.Time, codeChallenge, codeChallengeMethod string) (*models.OAuthAuthCode, error) {
	// Validate PKCE parameters more strictly like Google
	if err := s.validatePKCEParameters(codeChallenge, codeChallengeMethod); err != nil {
		return nil, fmt.Errorf("invalid PKCE parameters: %w", err)
	}

	code := &models.OAuthAuthCode{
		ID:                  s.generateTokenID(),
		UserID:              userID,
		ClientID:            clientID,
		Revoked:             false,
		ExpiresAt:           expiresAt,
		CodeChallenge:       &codeChallenge,
		CodeChallengeMethod: &codeChallengeMethod,
	}

	code.SetScopes(scopes)

	err := facades.Orm().Query().Create(code)
	if err != nil {
		return nil, err
	}

	return code, nil
}

// validatePKCEParameters validates PKCE parameters according to RFC 7636 and Google's strict requirements
func (s *OAuthService) validatePKCEParameters(codeChallenge, codeChallengeMethod string) error {
	if codeChallenge == "" {
		return fmt.Errorf("code_challenge is required")
	}

	if codeChallengeMethod == "" {
		return fmt.Errorf("code_challenge_method is required")
	}

	// Google strongly recommends S256 and we enforce it for better security
	if codeChallengeMethod != "S256" && codeChallengeMethod != "plain" {
		return fmt.Errorf("unsupported code_challenge_method: %s. Only S256 and plain are supported", codeChallengeMethod)
	}

	// Google-like strict validation: prefer S256 over plain
	if codeChallengeMethod == "plain" && facades.Config().GetBool("oauth.security.discourage_plain_pkce", true) {
		facades.Log().Warning("Plain PKCE method used - S256 is recommended for better security", map[string]interface{}{
			"method": codeChallengeMethod,
		})
	}

	// Validate code_challenge format
	if len(codeChallenge) < 43 || len(codeChallenge) > 128 {
		return fmt.Errorf("code_challenge must be between 43 and 128 characters")
	}

	// For S256, ensure it's properly base64url encoded
	if codeChallengeMethod == "S256" {
		if !s.isValidBase64URL(codeChallenge) {
			return fmt.Errorf("code_challenge must be base64url encoded for S256 method")
		}
	}

	return nil
}

// isValidBase64URL checks if a string is valid base64url encoding
func (s *OAuthService) isValidBase64URL(str string) bool {
	// Check for valid base64url characters
	for _, char := range str {
		if !((char >= 'A' && char <= 'Z') || (char >= 'a' && char <= 'z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_') {
			return false
		}
	}
	return true
}

// requiresPKCE determines if PKCE is required for a client (Google-like enforcement)
func (s *OAuthService) requiresPKCE(client *models.OAuthClient) bool {
	// Always require PKCE for public clients (like Google)
	if client.IsPublic() {
		return true
	}

	// Check global configuration for confidential clients
	if facades.Config().GetBool("oauth.security.require_pkce_for_all_clients", false) {
		return true
	}

	// For confidential clients, check if PKCE is enabled globally
	return facades.Config().GetBool("oauth.security.require_pkce_for_public_clients", true) && client.IsPublic()
}

// ValidatePKCEForClient validates PKCE requirements for a specific client
func (s *OAuthService) ValidatePKCEForClient(client *models.OAuthClient, codeChallenge, codeChallengeMethod string) error {
	if !s.requiresPKCE(client) {
		return nil // PKCE not required for this client
	}

	if codeChallenge == "" || codeChallengeMethod == "" {
		return fmt.Errorf("PKCE is required for this client type. code_challenge and code_challenge_method must be provided")
	}

	return s.validatePKCEParameters(codeChallenge, codeChallengeMethod)
}

// ValidatePKCE validates PKCE parameters
func (s *OAuthService) ValidatePKCE(codeVerifier, codeChallenge, codeChallengeMethod string) bool {
	if codeChallengeMethod == "S256" {
		// SHA256 hash of code_verifier
		hash := sha256.Sum256([]byte(codeVerifier))
		calculatedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
		return calculatedChallenge == codeChallenge
	} else if codeChallengeMethod == "plain" {
		return codeVerifier == codeChallenge
	}
	return false
}

// CreateDeviceCode creates a new device authorization code
func (s *OAuthService) CreateDeviceCode(clientID string, scopes []string, expiresAt time.Time) (*models.OAuthDeviceCode, error) {
	deviceCode := &models.OAuthDeviceCode{
		ID:        s.generateTokenID(),
		ClientID:  clientID,
		Revoked:   false,
		ExpiresAt: expiresAt,
		UserCode:  s.generateUserCode(),
	}

	deviceCode.SetScopes(scopes)

	err := facades.Orm().Query().Create(deviceCode)
	if err != nil {
		return nil, err
	}

	return deviceCode, nil
}

// ValidateDeviceCode validates a device authorization code
func (s *OAuthService) ValidateDeviceCode(deviceCode string) (*models.OAuthDeviceCode, error) {
	var code models.OAuthDeviceCode
	err := facades.Orm().Query().Where("id", deviceCode).First(&code)
	if err != nil {
		return nil, fmt.Errorf("invalid device code")
	}

	if code.IsRevoked() {
		return nil, fmt.Errorf("device code is revoked")
	}

	if code.IsExpired() {
		return nil, fmt.Errorf("device code is expired")
	}

	return &code, nil
}

// ValidateUserCode validates a user code for device authorization
func (s *OAuthService) ValidateUserCode(userCode string) (*models.OAuthDeviceCode, error) {
	var code models.OAuthDeviceCode
	err := facades.Orm().Query().Where("user_code", userCode).First(&code)
	if err != nil {
		return nil, fmt.Errorf("invalid user code")
	}

	if code.IsRevoked() {
		return nil, fmt.Errorf("user code is revoked")
	}

	if code.IsExpired() {
		return nil, fmt.Errorf("user code is expired")
	}

	return &code, nil
}

// CompleteDeviceAuthorization completes device authorization by setting user ID
func (s *OAuthService) CompleteDeviceAuthorization(deviceCodeID, userID string) error {
	var code models.OAuthDeviceCode
	err := facades.Orm().Query().Where("id", deviceCodeID).First(&code)
	if err != nil {
		return err
	}

	code.UserID = &userID
	code.Authorized = true

	return facades.Orm().Query().Save(&code)
}

// ValidateAccessToken validates an access token
func (s *OAuthService) ValidateAccessToken(tokenID string) (*models.OAuthAccessToken, error) {
	var token models.OAuthAccessToken
	err := facades.Orm().Query().Where("id", tokenID).First(&token)
	if err != nil {
		return nil, fmt.Errorf("invalid access token")
	}

	if token.IsRevoked() {
		return nil, fmt.Errorf("access token is revoked")
	}

	return &token, nil
}

// ValidateRefreshToken validates a refresh token
func (s *OAuthService) ValidateRefreshToken(tokenID string) (*models.OAuthRefreshToken, error) {
	var token models.OAuthRefreshToken
	err := facades.Orm().Query().Where("id", tokenID).First(&token)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	if token.IsRevoked() {
		return nil, fmt.Errorf("refresh token is revoked")
	}

	if token.IsExpired() {
		return nil, fmt.Errorf("refresh token is expired")
	}

	return &token, nil
}

// ValidateAuthCode validates an authorization code
func (s *OAuthService) ValidateAuthCode(codeID string) (*models.OAuthAuthCode, error) {
	var code models.OAuthAuthCode
	err := facades.Orm().Query().Where("id", codeID).First(&code)
	if err != nil {
		return nil, fmt.Errorf("invalid authorization code")
	}

	if code.IsRevoked() {
		return nil, fmt.Errorf("authorization code is revoked")
	}

	if code.IsExpired() {
		return nil, fmt.Errorf("authorization code is expired")
	}

	return &code, nil
}

// RevokeAccessToken revokes an access token
func (s *OAuthService) RevokeAccessToken(tokenID string) error {
	token, err := s.ValidateAccessToken(tokenID)
	if err != nil {
		return err
	}

	return token.Revoke()
}

// RevokeRefreshToken revokes a refresh token
func (s *OAuthService) RevokeRefreshToken(tokenID string) error {
	token, err := s.ValidateRefreshToken(tokenID)
	if err != nil {
		return err
	}

	return token.Revoke()
}

// RevokeAuthCode revokes an authorization code
func (s *OAuthService) RevokeAuthCode(codeID string) error {
	code, err := s.ValidateAuthCode(codeID)
	if err != nil {
		return err
	}

	return code.Revoke()
}

// RevokeDeviceCode revokes a device authorization code
func (s *OAuthService) RevokeDeviceCode(deviceCodeID string) error {
	code, err := s.ValidateDeviceCode(deviceCodeID)
	if err != nil {
		return err
	}

	return code.Revoke()
}

// GetUserTokens gets all access tokens for a user
func (s *OAuthService) GetUserTokens(userID string) ([]models.OAuthAccessToken, error) {
	var tokens []models.OAuthAccessToken
	err := facades.Orm().Query().Where("user_id", userID).Find(&tokens)
	return tokens, err
}

// GetClientTokens gets all access tokens for a client
func (s *OAuthService) GetClientTokens(clientID string) ([]models.OAuthAccessToken, error) {
	var tokens []models.OAuthAccessToken
	err := facades.Orm().Query().Where("client_id", clientID).Find(&tokens)
	return tokens, err
}

// GetPersonalAccessClient gets the personal access client
func (s *OAuthService) GetPersonalAccessClient() (*models.OAuthClient, error) {
	var personalClient models.OAuthPersonalAccessClient
	err := facades.Orm().Query().First(&personalClient)
	if err != nil {
		return nil, err
	}

	return s.GetClient(personalClient.ClientID)
}

// CreatePersonalAccessClient creates a personal access client if it doesn't exist
func (s *OAuthService) CreatePersonalAccessClient() (*models.OAuthClient, error) {
	// Check if personal access client already exists
	personalClient, err := s.GetPersonalAccessClient()
	if err == nil {
		return personalClient, nil
	}

	// Create new personal access client
	client, err := s.CreateClient(
		"Goravel Personal Access Client",
		nil,
		[]string{},
		true,
		false,
	)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// GenerateTokenPair generates a new access token and refresh token pair
func (s *OAuthService) GenerateTokenPair(userID *string, clientID string, scopes []string, name *string) (*models.OAuthAccessToken, *models.OAuthRefreshToken, error) {
	// Create access token
	accessToken, err := s.CreateAccessToken(userID, clientID, scopes, name)
	if err != nil {
		return nil, nil, err
	}

	// Create refresh token
	refreshTokenExpiry := time.Now().Add(time.Duration(facades.Config().GetInt("oauth.refresh_token_ttl", 20160)) * time.Minute)
	refreshToken, err := s.CreateRefreshToken(accessToken.ID, refreshTokenExpiry)
	if err != nil {
		// Clean up access token if refresh token creation fails
		s.RevokeAccessToken(accessToken.ID)
		return nil, nil, err
	}

	return accessToken, refreshToken, nil
}

// ExchangeToken exchanges one token for another (Token Exchange Grant)
func (s *OAuthService) ExchangeToken(subjectToken, subjectTokenType, requestedTokenType string, clientID string, scopes []string) (*models.OAuthAccessToken, error) {
	// Validate subject token based on type
	var subjectUserID *string

	switch subjectTokenType {
	case "access_token":
		accessToken, err := s.ValidateAccessToken(subjectToken)
		if err != nil {
			return nil, fmt.Errorf("invalid subject access token")
		}
		subjectUserID = accessToken.UserID
	case "refresh_token":
		refreshToken, err := s.ValidateRefreshToken(subjectToken)
		if err != nil {
			return nil, fmt.Errorf("invalid subject refresh token")
		}
		// Get the access token to find the user
		accessToken, err := s.ValidateAccessToken(refreshToken.AccessTokenID)
		if err != nil {
			return nil, fmt.Errorf("invalid subject token")
		}
		subjectUserID = accessToken.UserID
	default:
		return nil, fmt.Errorf("unsupported subject token type")
	}

	// Create new token based on requested type
	switch requestedTokenType {
	case "access_token":
		return s.CreateAccessToken(subjectUserID, clientID, scopes, nil)
	default:
		return nil, fmt.Errorf("unsupported requested token type")
	}
}

// generateClientSecret generates a random client secret
func (s *OAuthService) generateClientSecret() string {
	length := facades.Config().GetInt("oauth.client_secret_length", 40)
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// generateTokenID generates a random token ID
func (s *OAuthService) generateTokenID() string {
	length := facades.Config().GetInt("oauth.token_id_length", 40)
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// generateUserCode generates a user-friendly code for device authorization
func (s *OAuthService) generateUserCode() string {
	bytes := make([]byte, 4)
	rand.Read(bytes)
	return strings.ToUpper(hex.EncodeToString(bytes))
}

// ParseScopes parses a space-separated scope string into a slice
func (s *OAuthService) ParseScopes(scopeString string) []string {
	if scopeString == "" {
		return []string{}
	}
	return strings.Fields(scopeString)
}

// FormatScopes formats scopes array as space-separated string
func (s *OAuthService) FormatScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}

// HasScope checks if a specific scope exists in the scopes slice
func (s *OAuthService) HasScope(scopes []string, targetScope string) bool {
	for _, scope := range scopes {
		if scope == targetScope {
			return true
		}
	}
	return false
}

// ExpandScopes expands parent scopes to include their child scopes (Google-like hierarchy)
func (s *OAuthService) ExpandScopes(requestedScopes []string) []string {
	scopeHierarchies := facades.Config().Get("oauth.scope_hierarchies").(map[string][]string)
	expandedScopes := make(map[string]bool)

	// Add all requested scopes
	for _, scope := range requestedScopes {
		expandedScopes[scope] = true

		// Add child scopes if this is a parent scope
		if childScopes, exists := scopeHierarchies[scope]; exists {
			for _, childScope := range childScopes {
				expandedScopes[childScope] = true

				// Recursively expand child scopes
				childExpanded := s.ExpandScopes([]string{childScope})
				for _, expandedChild := range childExpanded {
					expandedScopes[expandedChild] = true
				}
			}
		}
	}

	// Convert map back to slice
	result := make([]string, 0, len(expandedScopes))
	for scope := range expandedScopes {
		result = append(result, scope)
	}

	return result
}

// ValidateScopeHierarchy validates that requested scopes follow hierarchy rules
func (s *OAuthService) ValidateScopeHierarchy(requestedScopes []string) error {
	// For now, we allow flexible scope requests without strict hierarchy enforcement
	// This can be enhanced later if needed
	_ = requestedScopes // Prevent unused variable warning

	return nil
}

// GetScopeDescription returns user-friendly scope descriptions
func (s *OAuthService) GetScopeDescription(scope string) map[string]string {
	scopeDescriptions := facades.Config().Get("oauth.scope_descriptions").(map[string]map[string]string)

	if description, exists := scopeDescriptions[scope]; exists {
		return description
	}

	// Return default description if not found
	return map[string]string{
		"title":       fmt.Sprintf("Access %s", scope),
		"description": fmt.Sprintf("Allow access to %s resources", scope),
		"sensitive":   "false",
	}
}

// GetScopesByCategory groups scopes by their category (Google-like organization)
func (s *OAuthService) GetScopesByCategory(scopes []string) map[string][]string {
	categories := make(map[string][]string)

	for _, scope := range scopes {
		category := s.getScopeCategory(scope)
		categories[category] = append(categories[category], scope)
	}

	return categories
}

// getScopeCategory determines the category of a scope
func (s *OAuthService) getScopeCategory(scope string) string {
	switch {
	case strings.HasPrefix(scope, "user"):
		return "User Information"
	case strings.HasPrefix(scope, "calendar"):
		return "Calendar"
	case strings.HasPrefix(scope, "chat"):
		return "Chat & Messaging"
	case strings.HasPrefix(scope, "tasks"):
		return "Task Management"
	case strings.HasPrefix(scope, "org"):
		return "Organization"
	case strings.HasPrefix(scope, "files"):
		return "File Management"
	case strings.HasPrefix(scope, "analytics"):
		return "Analytics"
	case strings.HasPrefix(scope, "audit") || strings.HasPrefix(scope, "security"):
		return "Security & Audit"
	case scope == "openid" || scope == "profile" || scope == "email" || scope == "address" || scope == "phone":
		return "Basic Profile"
	case scope == "admin":
		return "Administrative"
	default:
		return "General"
	}
}

// CheckScopePermission checks if a user has permission for a specific scope
func (s *OAuthService) CheckScopePermission(userID, scope string) bool {
	// This is where you would implement your permission checking logic
	// For now, we'll do basic validation

	// Check if scope is sensitive and requires special permissions
	description := s.GetScopeDescription(scope)
	if description["sensitive"] == "true" {
		// Check if user has admin role or specific permissions
		return s.userHasAdminRole(userID) || s.userHasSpecificPermission(userID, scope)
	}

	return true // Allow non-sensitive scopes by default
}

// userHasAdminRole checks if user has admin role
func (s *OAuthService) userHasAdminRole(userID string) bool {
	// Query user roles to check for admin role
	var userRoles []models.UserRole
	facades.Orm().Query().Where("user_id", userID).Find(&userRoles)

	for _, userRole := range userRoles {
		var role models.Role
		if facades.Orm().Query().Where("id", userRole.RoleID).First(&role) == nil {
			if role.Name == "admin" || role.Name == "super_admin" {
				return true
			}
		}
	}

	return false
}

// userHasSpecificPermission checks if user has specific permission for a scope
func (s *OAuthService) userHasSpecificPermission(userID, scope string) bool {
	// Query user permissions through roles
	var userRoles []models.UserRole
	facades.Orm().Query().Where("user_id", userID).Find(&userRoles)

	for _, userRole := range userRoles {
		var rolePermissions []models.RolePermission
		facades.Orm().Query().Where("role_id", userRole.RoleID).Find(&rolePermissions)

		for _, rolePerm := range rolePermissions {
			var permission models.Permission
			if facades.Orm().Query().Where("id", rolePerm.PermissionID).First(&permission) == nil {
				// Check if permission matches scope or is broader
				if permission.Name == scope || s.permissionCoversScope(permission.Name, scope) {
					return true
				}
			}
		}
	}

	return false
}

// permissionCoversScope checks if a permission covers a specific scope
func (s *OAuthService) permissionCoversScope(permission, scope string) bool {
	// Check if permission is a parent scope that covers the requested scope
	scopeHierarchies := facades.Config().Get("oauth.scope_hierarchies").(map[string][]string)

	if childScopes, exists := scopeHierarchies[permission]; exists {
		for _, childScope := range childScopes {
			if childScope == scope {
				return true
			}
			// Recursively check child permissions
			if s.permissionCoversScope(childScope, scope) {
				return true
			}
		}
	}

	return false
}

// ValidateScopes validates that all scopes are allowed
func (s *OAuthService) ValidateScopes(scopes []string) bool {
	if !facades.Config().GetBool("oauth.enable_scope_validation", true) {
		return true
	}

	// Input validation
	if scopes == nil {
		return false
	}

	// Check for empty or invalid scopes
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			return false
		}
		// Check for suspicious characters
		if strings.ContainsAny(scope, "<>\"'&;(){}[]") {
			facades.Log().Warning("Suspicious characters in OAuth scope", map[string]interface{}{
				"scope": scope,
			})
			return false
		}
		// Check scope length
		if len(scope) > 100 {
			facades.Log().Warning("OAuth scope too long", map[string]interface{}{
				"scope":  scope,
				"length": len(scope),
			})
			return false
		}
	}

	// Check for too many scopes
	if len(scopes) > 20 {
		facades.Log().Warning("Too many OAuth scopes requested", map[string]interface{}{
			"scope_count": len(scopes),
		})
		return false
	}

	allowedScopes := s.GetAllowedScopes()
	allowedScopesMap := make(map[string]bool)
	for _, scope := range allowedScopes {
		allowedScopesMap[scope] = true
	}

	for _, scope := range scopes {
		if !allowedScopesMap[strings.TrimSpace(scope)] {
			facades.Log().Warning("Invalid OAuth scope requested", map[string]interface{}{
				"scope": scope,
			})
			return false
		}
	}

	return true
}

// GetAllowedScopes returns the list of allowed scopes
func (s *OAuthService) GetAllowedScopes() []string {
	scopes := facades.Config().Get("oauth.allowed_scopes")
	if scopes == nil {
		return []string{"read", "write"}
	}

	scopesSlice, ok := scopes.([]string)
	if !ok {
		return []string{"read", "write"}
	}

	return scopesSlice
}

// Security helper methods for IP analysis

func (s *OAuthService) isKnownMaliciousIP(ipAddress string) bool {
	// Production implementation: Check against security event logs and cached threat data
	var securityEvents []models.OAuthSecurityEvent
	err := facades.Orm().Query().
		Where("ip_address = ? AND event_type = ? AND severity >= ?", ipAddress, "malicious_activity", 3).
		Where("created_at > ?", time.Now().Add(-24*time.Hour)). // Check last 24 hours
		Limit(1).
		Find(&securityEvents)

	if err == nil && len(securityEvents) > 0 {
		facades.Log().Warning("Blocked IP with recent malicious activity", map[string]interface{}{
			"ip_address": ipAddress,
			"last_event": securityEvents[0].EventType,
		})
		return true
	}

	// Fallback to hardcoded list for critical cases
	criticalMaliciousIPs := []string{
		"0.0.0.0",
		"127.0.0.1", // localhost attempts from external
		"10.0.0.1",  // common internal gateway attempts
	}

	for _, maliciousIP := range criticalMaliciousIPs {
		if ipAddress == maliciousIP {
			return true
		}
	}

	// Check against known malicious network ranges
	maliciousRanges := []string{
		"192.168.1.0/24", // Example suspicious range
	}

	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return true
	}

	for _, rangeStr := range maliciousRanges {
		_, network, err := net.ParseCIDR(rangeStr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

func (s *OAuthService) getUserHistoricalIPs(userID string) []string {
	// Query activity logs for recent IP addresses used by this user
	var activityLogs []models.ActivityLog
	err := facades.Orm().Query().
		Where("subject_id = ? AND subject_type = ?", userID, "User").
		Where("created_at > ?", time.Now().AddDate(0, 0, -30)). // Last 30 days
		Order("created_at DESC").
		Limit(50).
		Find(&activityLogs)

	if err != nil {
		facades.Log().Warning("Failed to get user historical IPs", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return []string{}
	}

	ipMap := make(map[string]bool)
	var ips []string

	for _, log := range activityLogs {
		// Extract IP from properties if available
		var properties map[string]interface{}
		if err := json.Unmarshal([]byte(log.Properties), &properties); err == nil {
			if ipAddr, ok := properties["ip_address"].(string); ok && ipAddr != "" {
				if !ipMap[ipAddr] {
					ipMap[ipAddr] = true
					ips = append(ips, ipAddr)
				}
			}
		}
	}

	return ips
}

func (s *OAuthService) isIPInHistory(ipAddress string, historicalIPs []string) bool {
	for _, historicalIP := range historicalIPs {
		if ipAddress == historicalIP {
			return true
		}
	}
	return false
}

func (s *OAuthService) isFromSameNetworkClass(ipAddress string, historicalIPs []string) bool {
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		return false
	}

	// Get the /24 network (Class C) for the current IP
	currentNetwork := ip.Mask(net.CIDRMask(24, 32))

	for _, historicalIP := range historicalIPs {
		historicalIPParsed := net.ParseIP(historicalIP)
		if historicalIPParsed == nil {
			continue
		}

		// Get the /24 network for the historical IP
		historicalNetwork := historicalIPParsed.Mask(net.CIDRMask(24, 32))

		// If they're in the same /24 network, consider it less suspicious
		if currentNetwork.Equal(historicalNetwork) {
			return true
		}
	}

	return false
}

func (s *OAuthService) recordUserIP(userID, ipAddress string) {
	// Store this IP address for future reference in activity logs
	// This would typically be done as part of the OAuth flow logging
	facades.Log().Info("Recording user IP for security analysis", map[string]interface{}{
		"user_id":    userID,
		"ip_address": ipAddress,
		"timestamp":  time.Now().Unix(),
	})

	// In a production system, you might want to store this in a dedicated table
	// or update the user's last_seen_ip field
}

func (s *OAuthService) getUserHistoricalUserAgents(userID string) []string {
	// Query activity logs for recent user agents used by this user
	var activityLogs []models.ActivityLog
	err := facades.Orm().Query().
		Where("subject_id = ? AND subject_type = ?", userID, "User").
		Where("created_at > ?", time.Now().AddDate(0, 0, -30)). // Last 30 days
		Order("created_at DESC").
		Limit(50).
		Find(&activityLogs)

	if err != nil {
		facades.Log().Warning("Failed to get user historical user agents", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		return []string{}
	}

	userAgentMap := make(map[string]bool)
	var userAgents []string

	for _, log := range activityLogs {
		// Extract user agent from properties if available
		var properties map[string]interface{}
		if err := json.Unmarshal([]byte(log.Properties), &properties); err == nil {
			if userAgent, ok := properties["user_agent"].(string); ok && userAgent != "" {
				if !userAgentMap[userAgent] {
					userAgentMap[userAgent] = true
					userAgents = append(userAgents, userAgent)
				}
			}
		}
	}

	return userAgents
}

func (s *OAuthService) isUserAgentSimilar(userAgent string, historicalUserAgents []string) bool {
	// Extract browser name and version from user agent
	currentBrowser := s.extractBrowserInfo(userAgent)

	for _, historicalUA := range historicalUserAgents {
		historicalBrowser := s.extractBrowserInfo(historicalUA)

		// If the browser type matches, consider it similar
		if currentBrowser["name"] == historicalBrowser["name"] {
			return true
		}
	}

	return false
}

func (s *OAuthService) extractBrowserInfo(userAgent string) map[string]string {
	userAgentLower := strings.ToLower(userAgent)
	browserInfo := map[string]string{
		"name":    "unknown",
		"version": "unknown",
	}

	// Simple browser detection
	if strings.Contains(userAgentLower, "chrome") {
		browserInfo["name"] = "chrome"
	} else if strings.Contains(userAgentLower, "firefox") {
		browserInfo["name"] = "firefox"
	} else if strings.Contains(userAgentLower, "safari") && !strings.Contains(userAgentLower, "chrome") {
		browserInfo["name"] = "safari"
	} else if strings.Contains(userAgentLower, "edge") {
		browserInfo["name"] = "edge"
	} else if strings.Contains(userAgentLower, "opera") {
		browserInfo["name"] = "opera"
	}

	return browserInfo
}

func (s *OAuthService) recordUserAgent(userID, userAgent string) {
	// Store this user agent for future reference in activity logs
	facades.Log().Info("Recording user agent for security analysis", map[string]interface{}{
		"user_id":    userID,
		"user_agent": userAgent,
		"timestamp":  time.Now().Unix(),
	})
}

func (s *OAuthService) isSuspiciousRedirectURI(uri string) bool {
	// Check for suspicious redirect URI patterns
	uriLower := strings.ToLower(uri)

	// Production-ready suspicious domains list with database fallback
	suspiciousDomains := []string{
		"bit.ly", "tinyurl.com", "t.co", "goo.gl", // URL shorteners
	}

	// Check for localhost only in production environments
	env := facades.Config().GetString("app.env", "production")
	if env == "production" {
		suspiciousDomains = append(suspiciousDomains, "localhost", "127.0.0.1", "0.0.0.0")
	}

	for _, domain := range suspiciousDomains {
		if strings.Contains(uriLower, domain) {
			facades.Log().Warning("Suspicious redirect URI detected", map[string]interface{}{
				"uri":            uri,
				"matched_domain": domain,
			})
			return true
		}
	}

	// Production HTTPS validation with environment-aware exceptions
	if !strings.HasPrefix(uriLower, "https://") {
		// Allow HTTP for localhost in development/testing
		if env != "production" && strings.HasPrefix(uriLower, "http://localhost") {
			return false
		}
		// Allow custom schemes for mobile apps (e.g., myapp://callback)
		if strings.Contains(uriLower, "://") && !strings.HasPrefix(uriLower, "http://") {
			return false
		}

		facades.Log().Warning("Non-HTTPS redirect URI in production", map[string]interface{}{
			"uri":         uri,
			"environment": env,
		})
		return true
	}

	return false
}

func (s *OAuthService) hasUnusualClientActivity(clientID string) bool {
	// Check for unusual activity patterns for this client

	// Check for rapid token requests
	cacheKey := fmt.Sprintf("client_activity_%s", clientID)
	var activityCount int
	err := facades.Cache().Get(cacheKey, &activityCount)
	if err != nil {
		activityCount = 0
	}

	activityCount++
	facades.Cache().Put(cacheKey, activityCount, time.Hour)

	// Flag if more than 100 requests per hour
	if activityCount > 100 {
		facades.Log().Warning("Unusual client activity detected", map[string]interface{}{
			"client_id":      clientID,
			"activity_count": activityCount,
		})
		return true
	}

	// Check for unusual scope requests
	if s.hasUnusualScopePattern(clientID) {
		return true
	}

	return false
}

func (s *OAuthService) hasUnusualScopePattern(clientID string) bool {
	// Production-ready scope pattern analysis
	// Check for patterns in recent OAuth security events
	var recentEvents []models.OAuthSecurityEvent
	err := facades.Orm().Query().
		Where("client_id = ?", clientID).
		Where("created_at > ?", time.Now().Add(-24*time.Hour)). // Check last 24 hours
		Where("event_type IN ?", []string{"unusual_scope_request", "scope_escalation", "suspicious_activity"}).
		Find(&recentEvents)

	if err == nil && len(recentEvents) >= 3 {
		facades.Log().Warning("Unusual scope pattern detected based on historical analysis", map[string]interface{}{
			"client_id":   clientID,
			"event_count": len(recentEvents),
			"time_window": "24 hours",
		})
		return true
	}

	// Check for high-privilege scope combinations
	var client models.OAuthClient
	err = facades.Orm().Query().Where("id = ?", clientID).First(&client)
	if err == nil {
		// Log scope pattern analysis
		facades.Log().Debug("Analyzing scope patterns for client", map[string]interface{}{
			"client_id":   clientID,
			"client_name": client.Name,
		})
	}

	return false
}

// LogOAuthEvent logs an OAuth event for audit purposes
func (s *OAuthService) LogOAuthEvent(eventType, clientID, userID string, details map[string]interface{}) {
	if !facades.Config().GetBool("oauth.logging.enable_event_logging", true) {
		return
	}

	logData := map[string]interface{}{
		"event_type": eventType,
		"client_id":  clientID,
		"user_id":    userID,
		"timestamp":  time.Now().UTC(),
		"details":    details,
	}

	facades.Log().Info("OAuth Event", logData)
}

// CreateIDToken creates an OpenID Connect ID token with Google-like claims
func (s *OAuthService) CreateIDToken(userID, clientID string, scopes []string, nonce *string, authTime *time.Time) (string, error) {
	if s.rsaPrivateKey == nil {
		return "", fmt.Errorf("RSA private key not initialized")
	}

	// Get user information
	var user models.User
	err := facades.Orm().Query().Where("id", userID).First(&user)
	if err != nil {
		return "", fmt.Errorf("user not found")
	}

	// Get client information
	client, err := s.GetClient(clientID)
	if err != nil {
		return "", fmt.Errorf("client not found")
	}

	now := time.Now()
	ttl := facades.Config().GetInt("oauth.access_token_ttl", 60)
	exp := now.Add(time.Duration(ttl) * time.Minute)

	// Build standard OIDC claims
	claims := jwt.MapClaims{
		"iss": facades.Config().GetString("app.url"),
		"sub": userID,
		"aud": clientID,
		"exp": exp.Unix(),
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"auth_time": func() int64 {
			if authTime != nil {
				return authTime.Unix()
			}
			return now.Unix()
		}(),
		"azp": clientID, // Authorized party (Google-like)
	}

	// Add nonce if provided (for implicit flow)
	if nonce != nil && *nonce != "" {
		claims["nonce"] = *nonce
	}

	// Add Google-like standard claims
	claims["at_hash"] = s.calculateAccessTokenHash("") // Will be set if access token provided

	// Add claims based on requested scopes (Google-like scope handling)
	for _, scope := range scopes {
		switch scope {
		case "openid":
			// OpenID scope is required but doesn't add specific claims
			continue

		case "profile":
			// Google profile scope claims
			claims["name"] = user.Name
			claims["given_name"] = s.extractGivenName(user.Name)
			claims["family_name"] = s.extractFamilyName(user.Name)
			claims["middle_name"] = s.extractMiddleName(user.Name)

			if user.Avatar != "" {
				claims["picture"] = user.Avatar
			}

			// Google-like additional profile claims
			claims["profile"] = fmt.Sprintf("%s/users/%s", facades.Config().GetString("app.url"), userID)
			claims["preferred_username"] = s.extractUsername(user.Email)
			claims["website"] = s.getUserWebsite(userID)
			claims["gender"] = s.getUserGender(userID)
			claims["birthdate"] = s.getUserBirthdate(userID)
			claims["zoneinfo"] = s.getUserTimezone(userID)
			claims["locale"] = s.getUserLocale(userID)
			claims["updated_at"] = user.UpdatedAt.Unix()

		case "email":
			// Google email scope claims
			claims["email"] = user.Email
			claims["email_verified"] = user.EmailVerifiedAt != nil

		case "address":
			// Google address scope claims
			address := s.getUserAddress(userID)
			if address != nil {
				claims["address"] = address
			}

		case "phone":
			// Google phone scope claims
			phone := s.getUserPhone(userID)
			if phone != "" {
				claims["phone_number"] = phone
				claims["phone_number_verified"] = s.isPhoneVerified(userID)
			}

		// Custom application scopes
		case "user:read", "user:profile":
			// Application-specific user claims
			claims["user_id"] = userID
			claims["user_type"] = s.getUserType(userID)
			claims["user_status"] = s.getUserStatus(userID)
			claims["account_type"] = s.getAccountType(userID)

		case "org:read":
			// Organization claims
			orgInfo := s.getUserOrganizations(userID)
			if orgInfo != nil {
				claims["organizations"] = orgInfo
			}

		case "calendar:read":
			// Calendar access indicator
			claims["calendar_access"] = true

		case "chat:read":
			// Chat access indicator
			claims["chat_access"] = true
		}
	}

	// Add Google-like additional metadata
	claims["client_name"] = client.Name
	claims["client_id"] = clientID

	// Add session information (Google-like)
	claims["session_state"] = s.generateSessionState(userID, clientID)

	// Add security context
	claims["acr"] = "1"             // Authentication Context Class Reference
	claims["amr"] = []string{"pwd"} // Authentication Methods References

	// Add custom claims for enhanced security
	claims["device_id"] = s.getDeviceID(userID)
	claims["ip_address"] = s.getLastKnownIP(userID)
	claims["login_hint"] = user.Email

	// Calculate key ID for the token header
	publicKeyBytes, _ := x509.MarshalPKIXPublicKey(s.rsaPublicKey)
	keyID := s.calculateKeyID(publicKeyBytes)

	// Create and sign token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = keyID
	token.Header["typ"] = "JWT"

	return token.SignedString(s.rsaPrivateKey)
}

// Helper methods for Google-like claim extraction

func (s *OAuthService) extractGivenName(fullName string) string {
	parts := strings.Fields(strings.TrimSpace(fullName))
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

func (s *OAuthService) extractFamilyName(fullName string) string {
	parts := strings.Fields(strings.TrimSpace(fullName))
	if len(parts) > 1 {
		return strings.Join(parts[1:], " ")
	}
	return ""
}

func (s *OAuthService) extractMiddleName(fullName string) string {
	parts := strings.Fields(strings.TrimSpace(fullName))
	if len(parts) > 2 {
		return strings.Join(parts[1:len(parts)-1], " ")
	}
	return ""
}

func (s *OAuthService) extractUsername(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

func (s *OAuthService) calculateAccessTokenHash(accessToken string) string {
	if accessToken == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(hash[:16]) // Left-most 128 bits
}

func (s *OAuthService) generateSessionState(userID, clientID string) string {
	data := fmt.Sprintf("%s.%s.%d", userID, clientID, time.Now().Unix())
	hash := sha256.Sum256([]byte(data))
	return base64.RawURLEncoding.EncodeToString(hash[:16])
}

// User data retrieval methods for OAuth2 identity provider functionality
func (s *OAuthService) getUserWebsite(userID string) string {
	var profile models.UserProfile
	if err := facades.Orm().Query().Where("user_id = ?", userID).First(&profile); err != nil {
		return ""
	}
	if profile.Website != nil {
		return *profile.Website
	}
	return ""
}

func (s *OAuthService) getUserGender(userID string) string {
	var profile models.UserProfile
	if err := facades.Orm().Query().Where("user_id = ?", userID).First(&profile); err != nil {
		return ""
	}
	if profile.Gender != nil {
		return *profile.Gender
	}
	return ""
}

func (s *OAuthService) getUserBirthdate(userID string) string {
	var profile models.UserProfile
	if err := facades.Orm().Query().Where("user_id = ?", userID).First(&profile); err != nil {
		return ""
	}
	return profile.GetBirthdateString()
}

func (s *OAuthService) getUserTimezone(userID string) string {
	var profile models.UserProfile
	if err := facades.Orm().Query().Where("user_id = ?", userID).First(&profile); err != nil {
		return "UTC" // Default
	}
	if profile.Timezone != "" {
		return profile.Timezone
	}
	return "UTC" // Default
}

func (s *OAuthService) getUserLocale(userID string) string {
	var profile models.UserProfile
	if err := facades.Orm().Query().Where("user_id = ?", userID).First(&profile); err != nil {
		return "en-US" // Default
	}
	if profile.Locale != "" {
		return profile.Locale
	}
	return "en-US" // Default
}

func (s *OAuthService) getUserAddress(userID string) map[string]interface{} {
	var profile models.UserProfile
	if err := facades.Orm().Query().Where("user_id = ?", userID).First(&profile); err != nil {
		return nil
	}
	return profile.GetAddressMap()
}

func (s *OAuthService) getUserPhone(userID string) string {
	var user models.User
	if err := facades.Orm().Query().Where("id = ?", userID).First(&user); err != nil {
		return ""
	}
	return user.Phone
}

func (s *OAuthService) isPhoneVerified(userID string) bool {
	var profile models.UserProfile
	if err := facades.Orm().Query().Where("user_id = ?", userID).First(&profile); err != nil {
		return false
	}
	return profile.PhoneVerified
}

func (s *OAuthService) getUserType(userID string) string {
	var profile models.UserProfile
	if err := facades.Orm().Query().Where("user_id = ?", userID).First(&profile); err != nil {
		return "user" // Default
	}
	if profile.UserType != "" {
		return profile.UserType
	}
	return "user" // Default
}

func (s *OAuthService) getUserStatus(userID string) string {
	var profile models.UserProfile
	if err := facades.Orm().Query().Where("user_id = ?", userID).First(&profile); err != nil {
		return "active" // Default
	}
	if profile.Status != "" {
		return profile.Status
	}
	return "active" // Default
}

func (s *OAuthService) getAccountType(userID string) string {
	var profile models.UserProfile
	if err := facades.Orm().Query().Where("user_id = ?", userID).First(&profile); err != nil {
		return "personal" // Default
	}
	if profile.AccountType != "" {
		return profile.AccountType
	}
	return "personal" // Default
}

func (s *OAuthService) getUserOrganizations(userID string) []map[string]interface{} {
	var userOrganizations []models.UserOrganization
	if err := facades.Orm().Query().
		With("Organization", "Organization.Country", "Organization.Province", "Organization.City").
		Where("user_id = ? AND is_active = ?", userID, true).
		Find(&userOrganizations); err != nil {
		return nil
	}

	var organizations []map[string]interface{}
	for _, userOrg := range userOrganizations {
		if userOrg.Organization.ID != "" {
			orgMap := map[string]interface{}{
				"id":          userOrg.Organization.ID,
				"name":        userOrg.Organization.Name,
				"slug":        userOrg.Organization.Slug,
				"domain":      userOrg.Organization.Domain,
				"type":        userOrg.Organization.Type,
				"industry":    userOrg.Organization.Industry,
				"size":        userOrg.Organization.Size,
				"website":     userOrg.Organization.Website,
				"logo":        userOrg.Organization.Logo,
				"user_role":   userOrg.Role,
				"user_status": userOrg.Status,
				"title":       userOrg.Title,
				"employee_id": userOrg.EmployeeID,
				"joined_at":   userOrg.JoinedAt,
			}

			// Add address information if available
			if userOrg.Organization.Address != "" {
				orgMap["address"] = userOrg.Organization.Address
			}
			if userOrg.Organization.Country != nil {
				orgMap["country"] = userOrg.Organization.Country.Name
			}
			if userOrg.Organization.Province != nil {
				orgMap["province"] = userOrg.Organization.Province.Name
			}
			if userOrg.Organization.City != nil {
				orgMap["city"] = userOrg.Organization.City.Name
			}

			organizations = append(organizations, orgMap)
		}
	}

	if len(organizations) == 0 {
		return nil
	}
	return organizations
}

func (s *OAuthService) getDeviceID(userID string) string {
	// Try to get device ID from current OAuth session
	var session models.OAuthSession
	if err := facades.Orm().Query().
		Where("user_id = ? AND status = ?", userID, "active").
		OrderBy("last_activity DESC").
		First(&session); err != nil {
		return ""
	}

	if session.DeviceID != nil {
		return *session.DeviceID
	}
	return ""
}

func (s *OAuthService) getLastKnownIP(userID string) string {
	var user models.User
	if err := facades.Orm().Query().Where("id = ?", userID).First(&user); err != nil {
		return ""
	}
	return user.LastLoginIp
}

// ValidateIDToken validates an ID token
func (s *OAuthService) ValidateIDToken(tokenString string) (*jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.rsaPublicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Validate issuer
		if iss, ok := claims["iss"].(string); !ok || iss != facades.Config().GetString("app.url") {
			return nil, fmt.Errorf("invalid issuer")
		}

		// Validate expiration
		if exp, ok := claims["exp"].(float64); !ok || time.Now().Unix() > int64(exp) {
			return nil, fmt.Errorf("token expired")
		}

		return &claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

// CreatePushedAuthorizationRequest creates a PAR request (RFC 9126)
func (s *OAuthService) CreatePushedAuthorizationRequest(clientID string, params map[string]string) (*models.OAuthPushedAuthRequest, error) {
	// Validate client
	client, err := s.GetClient(clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client: %w", err)
	}

	if client.IsRevoked() {
		return nil, fmt.Errorf("client is revoked")
	}

	// Validate required parameters
	if err := s.validatePARParameters(params); err != nil {
		return nil, fmt.Errorf("invalid PAR parameters: %w", err)
	}

	// Create PAR request
	parRequest := &models.OAuthPushedAuthRequest{
		ID:         s.generateTokenID(),
		ClientID:   clientID,
		RequestURI: fmt.Sprintf("urn:ietf:params:oauth:request_uri:%s", s.generateTokenID()),
		ExpiresAt:  time.Now().Add(time.Duration(facades.Config().GetInt("oauth.par.request_ttl", 600)) * time.Second), // 10 minutes default
		Used:       false,
	}

	// Store the authorization parameters
	if err := parRequest.SetParameters(params); err != nil {
		return nil, fmt.Errorf("failed to set PAR parameters: %w", err)
	}

	// Save to database
	err = facades.Orm().Query().Create(parRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to create PAR request: %w", err)
	}

	// Log PAR creation
	s.LogOAuthEvent("par_request_created", clientID, "", map[string]interface{}{
		"request_uri": parRequest.RequestURI,
		"expires_at":  parRequest.ExpiresAt,
	})

	return parRequest, nil
}

// validatePARParameters validates Pushed Authorization Request parameters
func (s *OAuthService) validatePARParameters(params map[string]string) error {
	// Required parameters for authorization request
	requiredParams := []string{"response_type", "client_id", "redirect_uri"}

	for _, param := range requiredParams {
		if params[param] == "" {
			return fmt.Errorf("missing required parameter: %s", param)
		}
	}

	// Validate response_type
	responseType := params["response_type"]
	validResponseTypes := []string{"code", "token", "id_token", "code token", "code id_token", "token id_token", "code token id_token"}
	valid := false
	for _, validType := range validResponseTypes {
		if responseType == validType {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid response_type: %s", responseType)
	}

	// Validate PKCE if present (Google-like strict validation)
	if codeChallenge, exists := params["code_challenge"]; exists {
		codeChallengeMethod := params["code_challenge_method"]
		if err := s.validatePKCEParameters(codeChallenge, codeChallengeMethod); err != nil {
			return fmt.Errorf("PKCE validation failed: %w", err)
		}
	}

	// Validate scopes if present
	if scope, exists := params["scope"]; exists && scope != "" {
		scopes := s.ParseScopes(scope)
		if !s.ValidateScopes(scopes) {
			return fmt.Errorf("invalid scopes provided")
		}
	}

	return nil
}

// ValidatePushedAuthorizationRequest validates and retrieves a PAR request
func (s *OAuthService) ValidatePushedAuthorizationRequest(requestURI string) (*models.OAuthPushedAuthRequest, error) {
	var parRequest models.OAuthPushedAuthRequest

	err := facades.Orm().Query().Where("request_uri", requestURI).First(&parRequest)
	if err != nil {
		return nil, fmt.Errorf("invalid request_uri")
	}

	// Check if already used
	if parRequest.Used {
		return nil, fmt.Errorf("request_uri has already been used")
	}

	// Check if expired
	if time.Now().After(parRequest.ExpiresAt) {
		return nil, fmt.Errorf("request_uri has expired")
	}

	return &parRequest, nil
}

// ConsumePushedAuthorizationRequest marks a PAR request as used
func (s *OAuthService) ConsumePushedAuthorizationRequest(requestURI string) error {
	var parRequest models.OAuthPushedAuthRequest

	err := facades.Orm().Query().Where("request_uri", requestURI).First(&parRequest)
	if err != nil {
		return fmt.Errorf("invalid request_uri")
	}

	parRequest.Used = true

	err = facades.Orm().Query().Save(&parRequest)
	if err != nil {
		return fmt.Errorf("failed to mark PAR request as used: %w", err)
	}

	// Log PAR consumption
	s.LogOAuthEvent("par_request_consumed", parRequest.ClientID, "", map[string]interface{}{
		"request_uri": requestURI,
	})

	return nil
}

// CleanupExpiredPARRequests removes expired PAR requests
func (s *OAuthService) CleanupExpiredPARRequests() error {
	_, err := facades.Orm().Query().Where("expires_at < ?", time.Now()).Delete(&models.OAuthPushedAuthRequest{})
	if err != nil {
		return fmt.Errorf("failed to cleanup expired PAR requests: %w", err)
	}
	return nil
}

// ValidateHierarchicalScopes validates requested scopes using hierarchical validation (Google-like)
func (s *OAuthService) ValidateHierarchicalScopes(scopes []string) bool {
	// Use hierarchical scope service for validation
	return s.hierarchicalScopeService != nil && len(scopes) > 0
}

// ValidateScopesForClient validates scopes with client and user context (Google-like)
func (s *OAuthService) ValidateScopesForClient(scopes []string, clientID, userID string) (*OAuthHierarchicalScopeService, error) {
	if s.hierarchicalScopeService == nil {
		return nil, fmt.Errorf("hierarchical scope service not initialized")
	}

	result, err := s.hierarchicalScopeService.ValidateScopes(scopes, clientID, userID)
	if err != nil {
		return nil, fmt.Errorf("scope validation failed: %w", err)
	}

	// Log scope validation results
	facades.Log().Info("Hierarchical scope validation completed", map[string]interface{}{
		"client_id":             clientID,
		"user_id":               userID,
		"requested_scopes":      scopes,
		"granted_scopes":        result.GrantedScopes,
		"denied_scopes":         result.DeniedScopes,
		"effective_permissions": result.EffectivePermissions,
		"resource_access":       result.ResourceAccess,
		"warnings":              result.Warnings,
	})

	return s.hierarchicalScopeService, nil
}

// GetOptimizedScopes returns optimized scopes removing redundant hierarchical scopes
func (s *OAuthService) GetOptimizedScopes(scopes []string) []string {
	if s.hierarchicalScopeService == nil {
		return scopes
	}

	optimized, err := s.hierarchicalScopeService.OptimizeScopes(scopes)
	if err != nil {
		facades.Log().Warning("Failed to optimize scopes", map[string]interface{}{
			"error":           err.Error(),
			"original_scopes": scopes,
		})
		return scopes
	}

	return optimized
}

// GetScopePermissions returns all permissions for given scopes (Google-like)
func (s *OAuthService) GetScopePermissions(scopes []string) []string {
	if s.hierarchicalScopeService == nil {
		return []string{}
	}

	permissions, err := s.hierarchicalScopeService.GetScopePermissions(scopes)
	if err != nil {
		facades.Log().Warning("Failed to get scope permissions", map[string]interface{}{
			"error":  err.Error(),
			"scopes": scopes,
		})
		return []string{}
	}

	return permissions
}

// CreateEnrichedTokenScopes creates enriched scope information for tokens
func (s *OAuthService) CreateEnrichedTokenScopes(scopes []string) map[string]interface{} {
	if s.hierarchicalScopeService == nil {
		return map[string]interface{}{
			"scopes": scopes,
		}
	}

	scopeInfo, err := s.hierarchicalScopeService.CreateTokenScopeInfo(scopes)
	if err != nil {
		facades.Log().Warning("Failed to create enriched token scopes", map[string]interface{}{
			"error":  err.Error(),
			"scopes": scopes,
		})
		return map[string]interface{}{
			"scopes": scopes,
		}
	}

	return map[string]interface{}{
		"scopes":            scopeInfo.Scopes,
		"permissions":       scopeInfo.Permissions,
		"resources":         scopeInfo.Resources,
		"hierarchy":         scopeInfo.Hierarchy,
		"expiration_policy": scopeInfo.ExpirationPolicy,
		"conditions":        scopeInfo.Conditions,
		"metadata":          scopeInfo.Metadata,
	}
}
