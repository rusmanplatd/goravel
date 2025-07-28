# HashiCorp Vault E2EE Integration

This document describes how to configure and use the HashiCorp Vault-based End-to-End Encryption (E2EE) service in Goravel.

## Overview

The E2EE service has been completely migrated to use HashiCorp Vault for secure key management. This provides enterprise-grade security for encryption keys with features like:

- Centralized key management
- Audit logging
- Access policies and authentication
- Key rotation capabilities
- High availability and disaster recovery

## Configuration

### Required Environment Variables

Add the following configuration to your `.env` file or environment:

```bash
# Vault Server Configuration
E2EE_VAULT_ADDR=https://vault.example.com:8200

# Authentication Method 1: Token Authentication (recommended for development)
E2EE_VAULT_TOKEN=hvs.your-vault-token-here

# Authentication Method 2: AppRole Authentication (recommended for production)
E2EE_VAULT_ROLE_ID=your-role-id
E2EE_VAULT_SECRET_ID=your-secret-id

# Optional Configuration
E2EE_VAULT_NAMESPACE=your-namespace  # For Vault Enterprise
E2EE_VAULT_SECRET_PATH=secret/data/e2ee  # Custom secret path
```

### Vault Setup

#### 1. Enable KV Secrets Engine

```bash
vault secrets enable -path=secret kv-v2
```

#### 2. Create Policies

Create a policy file `e2ee-policy.hcl`:

```hcl
# E2EE Service Policy
path "secret/data/e2ee/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/metadata/e2ee/*" {
  capabilities = ["list", "read", "delete"]
}

# Allow token renewal
path "auth/token/renew-self" {
  capabilities = ["update"]
}
```

Apply the policy:

```bash
vault policy write e2ee-policy e2ee-policy.hcl
```

#### 3. Authentication Setup

##### Option A: Token Authentication (Development)

```bash
# Create a token with the e2ee policy
vault token create -policy=e2ee-policy -ttl=24h
```

##### Option B: AppRole Authentication (Production)

```bash
# Enable AppRole auth method
vault auth enable approle

# Create AppRole
vault write auth/approle/role/e2ee-service \
    token_policies="e2ee-policy" \
    token_ttl=1h \
    token_max_ttl=4h \
    bind_secret_id=true

# Get Role ID
vault read auth/approle/role/e2ee-service/role-id

# Generate Secret ID
vault write -f auth/approle/role/e2ee-service/secret-id
```

## Usage

### Service Initialization

The E2EE service will automatically connect to Vault during initialization:

```go
// Service automatically initializes with Vault
e2eeService := services.NewE2EEService()

// Generate key pairs
keyPair, err := e2eeService.GenerateKeyPair()
if err != nil {
    log.Fatal("Failed to generate key pair:", err)
}

// Encrypt messages
encryptedMsg, err := e2eeService.EncryptMessage(
    "Hello, World!",
    []string{keyPair.PublicKey},
)
if err != nil {
    log.Fatal("Failed to encrypt message:", err)
}

// Decrypt messages
decryptedMsg, err := e2eeService.DecryptMessage(encryptedMsg, keyPair.PrivateKey)
if err != nil {
    log.Fatal("Failed to decrypt message:", err)
}
```

### Key Storage Structure

The service stores data in Vault with the following structure:

```
secret/data/e2ee/
├── master-keys/          # User master keys
│   ├── user_123         # Base64 encoded master key for user 123
│   └── user_456         # Base64 encoded master key for user 456
└── encrypted-data/       # Additional encrypted data storage
    ├── session_abc      # Session-specific encrypted data
    └── room_xyz         # Room-specific encrypted data
```

## Security Features

### Master Key Management

- Each user gets a unique 256-bit AES master key
- Keys are automatically generated on first use
- Keys are stored encrypted in Vault
- Support for key rotation

### Authentication & Authorization

- Multiple authentication methods supported
- Fine-grained access control via Vault policies
- Audit logging of all key operations
- Token renewal and rotation

### High Availability

- Vault clustering support
- Automatic failover
- Backup and disaster recovery through Vault

## Monitoring & Troubleshooting

### Health Checks

The service performs health checks during initialization:

```bash
# Check Vault connectivity
curl -H "X-Vault-Token: $VAULT_TOKEN" $VAULT_ADDR/v1/sys/health
```

### Common Issues

#### 1. Connection Issues

```
Error: failed to create Vault client
```

**Solution**: Check `E2EE_VAULT_ADDR` and network connectivity.

#### 2. Authentication Issues

```
Error: HashiCorp Vault authentication not configured
```

**Solution**: Ensure either `E2EE_VAULT_TOKEN` or both `E2EE_VAULT_ROLE_ID` and `E2EE_VAULT_SECRET_ID` are set.

#### 3. Permission Issues

```
Error: failed to read from Vault: permission denied
```

**Solution**: Verify the Vault policy allows the required operations.

### Logging

The service logs all key operations for audit purposes:

```
[INFO] Successfully connected to HashiCorp Vault
[INFO] Retrieved master key from Vault user_id=123 key_size=32
[INFO] Generated and stored new master key in Vault user_id=456 key_size=32
```

## Development & Testing

### Test Environment

For testing, the service automatically uses a mock implementation when Vault is not configured:

```go
// In tests, this will use mock storage
e2eeService := services.NewE2EEService()
```

### Local Development with Vault

1. Start Vault dev server:
```bash
vault server -dev -dev-root-token-id=myroot
```

2. Set environment variables:
```bash
export E2EE_VAULT_ADDR=http://127.0.0.1:8200
export E2EE_VAULT_TOKEN=myroot
```

3. Run your application

## Migration Notes

### Breaking Changes

- **No backward compatibility**: The service requires Vault configuration
- **Removed features**: File-based and database key storage removed
- **Configuration changes**: New environment variables required

### Data Migration

If migrating from the old system:

1. Export existing master keys from your current storage
2. Import them into Vault using the CLI or API
3. Update your application configuration
4. Test thoroughly before production deployment

## Production Deployment

### Checklist

- [ ] Vault cluster properly configured and secured
- [ ] SSL/TLS enabled for Vault communication
- [ ] AppRole authentication configured
- [ ] Proper Vault policies in place
- [ ] Backup and disaster recovery tested
- [ ] Monitoring and alerting configured
- [ ] Security audit completed

### Performance Considerations

- Vault operations add network latency
- Consider caching strategies for frequently accessed keys
- Monitor Vault performance and scale accordingly
- Use Vault Agent for token management in production

## Support

For issues related to:
- **Vault configuration**: Check HashiCorp Vault documentation
- **E2EE service**: Check application logs and Vault audit logs
- **Performance**: Monitor Vault metrics and application performance 