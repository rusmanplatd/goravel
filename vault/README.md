# HashiCorp Vault Integration

This directory contains configuration files and documentation for HashiCorp Vault integration with the Goravel application.

## 🏗️ Architecture

```
vault/
├── config/
│   └── vault.hcl           # Production Vault configuration
├── policies/
│   ├── admin.hcl           # Admin policy (full access)
│   ├── goravel-app.hcl     # Application policy (limited access)
│   └── readonly.hcl        # Read-only policy (monitoring)
├── init-vault.sh           # Vault initialization script
└── README.md               # This file
```

## 🚀 Quick Start

### Development Mode (Docker Compose)

1. **Start Vault in development mode:**
   ```bash
   docker-compose up vault -d
   ```

2. **Initialize Vault with policies and secrets:**
   ```bash
   docker-compose exec vault /vault/init-vault.sh
   ```

3. **Access Vault UI:**
   - URL: http://localhost:8200
   - Token: `myroot` (development only)

### Production Mode

1. **Set environment variables:**
   ```bash
   export VAULT_DEV_MODE=false
   export VAULT_ADDR=https://your-vault-server.com:8200
   ```

2. **Start Vault:**
   ```bash
   docker-compose up vault -d
   ```

3. **Initialize and unseal Vault:**
   ```bash
   ./vault/init-vault.sh
   ```

## 🔧 Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_ADDR` | `http://localhost:8200` | Vault server address |
| `VAULT_TOKEN` | `myroot` | Vault authentication token |
| `VAULT_DEV_MODE` | `true` | Enable development mode |
| `VAULT_FALLBACK_TO_ENV` | `true` | Fallback to environment variables |
| `VAULT_CACHE_ENABLED` | `true` | Enable secret caching |
| `VAULT_LOGGING_ENABLED` | `true` | Enable Vault service logging |

### Application Configuration

Update your `.env` file:

```env
# Vault Configuration
VAULT_ADDR=http://localhost:8200
VAULT_TOKEN=myroot
VAULT_AUTH_METHOD=token
VAULT_DEV_MODE=true
VAULT_FALLBACK_TO_ENV=true
VAULT_CACHE_ENABLED=true
VAULT_LOGGING_ENABLED=true

# For AppRole authentication (recommended for production)
# VAULT_AUTH_METHOD=approle
# VAULT_ROLE_ID=your-role-id
# VAULT_SECRET_ID=your-secret-id
```

## 🔑 Secret Organization

### Secret Paths

```
secret/
├── app/
│   ├── master-key          # Application master encryption key
│   ├── jwt-secret          # JWT signing configuration
│   ├── feature-flags       # Application feature toggles
│   └── rate-limits         # Rate limiting configuration
├── database/
│   ├── postgres            # PostgreSQL connection details
│   └── redis               # Redis connection details
├── services/
│   ├── minio               # Object storage credentials
│   ├── livekit             # Meeting service configuration
│   ├── mail                # Email service configuration
│   ├── oauth/
│   │   └── google          # OAuth provider settings
│   ├── notification        # Push notification settings
│   └── webauthn            # WebAuthn configuration
└── api/
    ├── webhook-tokens      # Webhook verification tokens
    └── keys                # API keys and tokens
```

### Secret Engines

| Engine | Mount Path | Purpose |
|--------|------------|---------|
| KV v2 | `secret/` | Static secrets storage |
| Transit | `transit/` | Encryption as a service |
| PKI | `pki/` | Certificate management |
| Database | `database/` | Dynamic database credentials |
| TOTP | `totp/` | Time-based OTP for 2FA |

## 🔐 Authentication Methods

### Token Authentication (Development)

```go
// Simple token authentication
vaultService, err := services.NewVaultService()
```

### AppRole Authentication (Production)

```go
// Set environment variables
os.Setenv("VAULT_AUTH_METHOD", "approle")
os.Setenv("VAULT_ROLE_ID", "your-role-id")
os.Setenv("VAULT_SECRET_ID", "your-secret-id")

vaultService, err := services.NewVaultService()
```

### Kubernetes Authentication

```go
// For pod-based applications
os.Setenv("VAULT_AUTH_METHOD", "kubernetes")
os.Setenv("VAULT_K8S_ROLE", "goravel-app")

vaultService, err := services.NewVaultService()
```

## 📋 Policies

### Admin Policy
- Full access to all Vault operations
- System administration capabilities
- Policy management

### Goravel App Policy
- Read/write access to `secret/app/*`
- Read-only access to `secret/database/*` and `secret/services/*`
- Transit encryption operations
- Token self-management

### Read-Only Policy
- Read access to all secrets
- Health and metrics endpoints
- Suitable for monitoring and backup services

## 🛠️ Usage Examples

### Basic Secret Operations

```go
// Get Vault service
vs, err := app.MakeWith("vault", nil).(*services.VaultService)

// Store a secret
err = vs.PutSecret("secret/app/config", map[string]interface{}{
    "api_key": "your-api-key",
    "debug":   true,
})

// Retrieve a secret
secret, err := vs.GetSecret("secret/app/config")

// Get specific value
apiKey, err := vs.GetSecretValue("secret/app/config", "api_key")
```

### Database Credentials

```go
// Get database configuration from Vault
dbConfig, err := vs.GetSecret("secret/database/postgres")
if err != nil {
    // Fallback to environment variables
    dbConfig = fallbackDBConfig()
}

// Use in database connection
dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s",
    dbConfig.Data["username"],
    dbConfig.Data["password"],
    dbConfig.Data["host"],
    dbConfig.Data["port"],
    dbConfig.Data["database"])
```

### Dynamic Database Credentials

```go
// Get dynamic database credentials
creds, err := vs.GetSecret("database/creds/goravel-readwrite")
if err != nil {
    return err
}

// Credentials are automatically rotated
username := creds.Data["username"].(string)
password := creds.Data["password"].(string)
```

### Transit Encryption

```go
// Encrypt data
plaintext := "sensitive data"
encrypted, err := vs.TransitEncrypt("goravel-master-key", plaintext)

// Decrypt data
decrypted, err := vs.TransitDecrypt("goravel-master-key", encrypted)
```

## 🔍 Monitoring and Logging

### Audit Logging

Vault audit logs are stored in `/vault/logs/audit.log` and contain:
- All API requests and responses
- Authentication events
- Policy violations
- Secret access patterns

### Health Checks

```bash
# Check Vault status
curl http://localhost:8200/v1/sys/health

# Check seal status
curl http://localhost:8200/v1/sys/seal-status

# Get metrics
curl http://localhost:8200/v1/sys/metrics
```

### Application Monitoring

The Vault service includes built-in monitoring:
- Health checks every 5 minutes
- Automatic lease renewal
- Connection retry logic
- Performance metrics

## 🚨 Security Best Practices

### Development
- ✅ Use development mode for local testing
- ✅ Enable fallback to environment variables
- ✅ Use simple token authentication
- ⚠️ Never commit tokens to version control

### Production
- ✅ Use AppRole or Kubernetes authentication
- ✅ Enable TLS encryption
- ✅ Use proper Vault policies
- ✅ Enable audit logging
- ✅ Regular secret rotation
- ✅ Monitor access patterns
- ✅ Backup Vault data
- ❌ Never use development mode
- ❌ Never use root tokens in applications

### Network Security
- Use firewall rules to restrict Vault access
- Implement network segmentation
- Use VPN or private networks
- Enable mTLS for client authentication

## 🔄 Backup and Recovery

### Backup

```bash
# Backup Vault data (file storage)
docker-compose exec vault tar -czf /vault/backup.tar.gz /vault/data

# Copy backup to host
docker cp $(docker-compose ps -q vault):/vault/backup.tar.gz ./vault-backup.tar.gz
```

### Recovery

```bash
# Restore Vault data
docker cp ./vault-backup.tar.gz $(docker-compose ps -q vault):/vault/backup.tar.gz
docker-compose exec vault tar -xzf /vault/backup.tar.gz -C /
docker-compose restart vault
```

### Disaster Recovery

1. **Unseal Keys**: Store unseal keys securely (separate locations)
2. **Root Token**: Keep root token in secure, offline storage
3. **Policies**: Version control all policy files
4. **Configuration**: Backup Vault configuration files
5. **Secrets**: Regular encrypted backups of secret data

## 🐳 Docker Operations

### Start Services

```bash
# Start only Vault
docker-compose up vault -d

# Start all services including Vault
docker-compose up -d
```

### Initialize Vault

```bash
# Run initialization script
docker-compose exec vault /vault/init-vault.sh

# Or run from host
./vault/init-vault.sh
```

### View Logs

```bash
# Vault service logs
docker-compose logs vault -f

# Audit logs
docker-compose exec vault tail -f /vault/logs/audit.log
```

### Access Vault CLI

```bash
# Interactive shell
docker-compose exec vault sh

# Run Vault commands
docker-compose exec vault vault status
docker-compose exec vault vault secrets list
```

## 🔧 Troubleshooting

### Common Issues

**Vault sealed:**
```bash
# Check status
docker-compose exec vault vault status

# Unseal (development)
docker-compose exec vault vault operator unseal myroot
```

**Connection refused:**
```bash
# Check if Vault is running
docker-compose ps vault

# Check logs
docker-compose logs vault
```

**Authentication failed:**
```bash
# Verify token
export VAULT_TOKEN=myroot
docker-compose exec vault vault auth -method=token

# Check policies
docker-compose exec vault vault token lookup
```

**Secret not found:**
```bash
# List secrets
docker-compose exec vault vault kv list secret/

# Check path
docker-compose exec vault vault kv get secret/app/master-key
```

### Debug Mode

Enable debug logging in your application:

```env
VAULT_LOG_LEVEL=debug
VAULT_LOGGING_ENABLED=true
```

## 📚 Additional Resources

- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)
- [Vault API Reference](https://www.vaultproject.io/api-docs)
- [Vault Best Practices](https://learn.hashicorp.com/vault)
- [Production Hardening](https://learn.hashicorp.com/tutorials/vault/production-hardening)

## 🤝 Contributing

When adding new secrets or policies:

1. Update the appropriate policy file
2. Add examples to the usage documentation
3. Update the initialization script if needed
4. Test in development mode first
5. Document any new environment variables 