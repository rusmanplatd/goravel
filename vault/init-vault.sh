#!/bin/bash

# Vault Initialization Script
# This script sets up Vault with necessary policies and secret engines

set -e

# Configuration
VAULT_ADDR="${VAULT_ADDR:-http://localhost:8200}"
VAULT_TOKEN="${VAULT_TOKEN:-myroot}"
VAULT_DEV_MODE="${VAULT_DEV_MODE:-true}"

echo "🔐 Initializing HashiCorp Vault..."
echo "Vault Address: $VAULT_ADDR"
echo "Development Mode: $VAULT_DEV_MODE"

# Wait for Vault to be ready
echo "⏳ Waiting for Vault to be ready..."
until curl -s "$VAULT_ADDR/v1/sys/health" > /dev/null 2>&1; do
  echo "Waiting for Vault..."
  sleep 2
done

# Set Vault address and token
export VAULT_ADDR="$VAULT_ADDR"
export VAULT_TOKEN="$VAULT_TOKEN"

echo "✅ Vault is ready!"

# Only initialize if not in dev mode (dev mode auto-initializes)
if [ "$VAULT_DEV_MODE" != "true" ]; then
  echo "🔧 Initializing Vault..."
  
  # Check if Vault is already initialized
  if ! vault status | grep -q "Initialized.*true"; then
    echo "Initializing Vault with 5 key shares and 3 key threshold..."
    vault operator init -key-shares=5 -key-threshold=3 > vault-init.txt
    echo "⚠️  IMPORTANT: Save the vault-init.txt file securely!"
    
    # Extract unseal keys and root token
    UNSEAL_KEY_1=$(grep 'Unseal Key 1:' vault-init.txt | awk '{print $NF}')
    UNSEAL_KEY_2=$(grep 'Unseal Key 2:' vault-init.txt | awk '{print $NF}')
    UNSEAL_KEY_3=$(grep 'Unseal Key 3:' vault-init.txt | awk '{print $NF}')
    ROOT_TOKEN=$(grep 'Initial Root Token:' vault-init.txt | awk '{print $NF}')
    
    # Unseal Vault
    echo "🔓 Unsealing Vault..."
    vault operator unseal "$UNSEAL_KEY_1"
    vault operator unseal "$UNSEAL_KEY_2"
    vault operator unseal "$UNSEAL_KEY_3"
    
    # Use root token
    export VAULT_TOKEN="$ROOT_TOKEN"
    echo "Root token: $ROOT_TOKEN"
  else
    echo "Vault is already initialized"
  fi
fi

# Enable audit logging
echo "📝 Enabling audit logging..."
if ! vault audit list | grep -q "file/"; then
  vault audit enable file file_path=/vault/logs/audit.log
  echo "✅ Audit logging enabled"
else
  echo "Audit logging already enabled"
fi

# Enable secret engines
echo "🔑 Setting up secret engines..."

# KV v2 secret engine (usually enabled by default in dev mode)
if ! vault secrets list | grep -q "secret/"; then
  vault secrets enable -path=secret kv-v2
  echo "✅ KV v2 secret engine enabled"
else
  echo "KV v2 secret engine already enabled"
fi

# Transit secret engine for encryption
if ! vault secrets list | grep -q "transit/"; then
  vault secrets enable transit
  echo "✅ Transit secret engine enabled"
else
  echo "Transit secret engine already enabled"
fi

# PKI secret engine for certificates
if ! vault secrets list | grep -q "pki/"; then
  vault secrets enable pki
  vault secrets tune -max-lease-ttl=87600h pki
  echo "✅ PKI secret engine enabled"
else
  echo "PKI secret engine already enabled"
fi

# Database secret engine for dynamic credentials
if ! vault secrets list | grep -q "database/"; then
  vault secrets enable database
  echo "✅ Database secret engine enabled"
else
  echo "Database secret engine already enabled"
fi

# TOTP secret engine for 2FA
if ! vault secrets list | grep -q "totp/"; then
  vault secrets enable totp
  echo "✅ TOTP secret engine enabled"
else
  echo "TOTP secret engine already enabled"
fi

# Create policies
echo "📋 Creating policies..."

# Admin policy
vault policy write admin - <<EOF
# Admin Policy - Full access
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
EOF
echo "✅ Admin policy created"

# Goravel app policy
vault policy write goravel-app - <<EOF
# Goravel Application Policy
path "secret/data/app/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "secret/metadata/app/*" {
  capabilities = ["list", "read", "delete"]
}
path "secret/data/database/*" {
  capabilities = ["read", "list"]
}
path "secret/metadata/database/*" {
  capabilities = ["list", "read"]
}
path "secret/data/services/*" {
  capabilities = ["read", "list"]
}
path "secret/metadata/services/*" {
  capabilities = ["list", "read"]
}
path "secret/data/api/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "secret/metadata/api/*" {
  capabilities = ["list", "read", "delete"]
}
path "auth/token/renew-self" {
  capabilities = ["update"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
path "transit/encrypt/goravel-*" {
  capabilities = ["update"]
}
path "transit/decrypt/goravel-*" {
  capabilities = ["update"]
}
EOF
echo "✅ Goravel app policy created"

# Read-only policy
vault policy write readonly - <<EOF
# Read-Only Policy
path "secret/data/*" {
  capabilities = ["read", "list"]
}
path "secret/metadata/*" {
  capabilities = ["read", "list"]
}
path "sys/health" {
  capabilities = ["read"]
}
path "sys/metrics" {
  capabilities = ["read"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
path "auth/token/renew-self" {
  capabilities = ["update"]
}
EOF
echo "✅ Read-only policy created"

# Enable AppRole auth method
echo "🔐 Setting up authentication methods..."
if ! vault auth list | grep -q "approle/"; then
  vault auth enable approle
  echo "✅ AppRole auth method enabled"
else
  echo "AppRole auth method already enabled"
fi

# Create AppRole for Goravel application
vault write auth/approle/role/goravel-app \
    token_policies="goravel-app" \
    token_ttl=1h \
    token_max_ttl=4h \
    bind_secret_id=true

# Get role ID and secret ID
ROLE_ID=$(vault read -field=role_id auth/approle/role/goravel-app/role-id)
SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/goravel-app/secret-id)

echo "✅ AppRole created for Goravel application"
echo "Role ID: $ROLE_ID"
echo "Secret ID: $SECRET_ID"

# Store AppRole credentials in a secure location
cat > goravel-approle.txt <<EOF
# Goravel AppRole Credentials
# Store these securely and use them in your application
VAULT_ROLE_ID=$ROLE_ID
VAULT_SECRET_ID=$SECRET_ID
EOF

echo "⚠️  AppRole credentials saved to goravel-approle.txt"

# Create transit encryption key for Goravel
echo "🔐 Creating encryption keys..."
vault write -f transit/keys/goravel-master-key
vault write -f transit/keys/goravel-session-key
vault write -f transit/keys/goravel-file-key
echo "✅ Transit encryption keys created"

# Setup PKI root CA
echo "📜 Setting up PKI root CA..."
vault write -field=certificate pki/root/generate/internal \
    common_name="Goravel Root CA" \
    ttl=87600h > goravel-ca.crt

vault write pki/config/urls \
    issuing_certificates="$VAULT_ADDR/v1/pki/ca" \
    crl_distribution_points="$VAULT_ADDR/v1/pki/crl"

# Create PKI role for Goravel
vault write pki/roles/goravel-role \
    allowed_domains="goravel.local,localhost" \
    allow_subdomains=true \
    max_ttl="720h"

echo "✅ PKI root CA and role created"

# Setup database connection (example for PostgreSQL)
echo "🗄️  Setting up database dynamic credentials..."
vault write database/config/postgresql \
    plugin_name=postgresql-database-plugin \
    connection_url="postgresql://{{username}}:{{password}}@postgres:5432/goravel?sslmode=disable" \
    allowed_roles="goravel-readonly,goravel-readwrite" \
    username="goravel" \
    password="goravel_password"

# Create database roles
vault write database/roles/goravel-readonly \
    db_name=postgresql \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"

vault write database/roles/goravel-readwrite \
    db_name=postgresql \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"

echo "✅ Database dynamic credentials configured"

# Create some initial secrets for the application
echo "🔑 Creating initial application secrets..."

# Application master key
vault kv put secret/app/master-key \
    master_key="$(openssl rand -base64 32)" \
    algorithm="AES-256-GCM" \
    created_at="$(date -Iseconds)"

# JWT secret
vault kv put secret/app/jwt-secret \
    jwt_secret="$(openssl rand -base64 64)" \
    algorithm="HS256" \
    access_token_ttl=3600 \
    refresh_token_ttl=2592000 \
    issuer="goravel-app" \
    audience="goravel-users"

# Database credentials
vault kv put secret/database/postgres \
    host="postgres" \
    port="5432" \
    database="goravel" \
    username="goravel" \
    password="goravel_password" \
    ssl_mode="disable" \
    max_connections=100

# Redis configuration
vault kv put secret/database/redis \
    host="redis" \
    port="6379" \
    password="" \
    database=0 \
    max_retries=3 \
    pool_size=10

# MinIO configuration
vault kv put secret/services/minio \
    endpoint="minio:9000" \
    access_key="miniouserroot" \
    secret_key="miniouserrootpassword" \
    bucket="goravelstorage" \
    region="ap-southeast-1" \
    use_ssl=false

echo "✅ Initial application secrets created"

echo ""
echo "🎉 Vault initialization complete!"
echo ""
echo "📋 Summary:"
echo "- Vault Address: $VAULT_ADDR"
echo "- Audit logging: Enabled"
echo "- Secret engines: KV v2, Transit, PKI, Database, TOTP"
echo "- Auth methods: Token, AppRole"
echo "- Policies: admin, goravel-app, readonly"
echo "- Initial secrets: Created for app, database, services"
echo ""
echo "📁 Files created:"
echo "- vault-init.txt (unseal keys and root token)"
echo "- goravel-approle.txt (AppRole credentials)"
echo "- goravel-ca.crt (Root CA certificate)"
echo ""
echo "⚠️  IMPORTANT SECURITY NOTES:"
echo "1. Store vault-init.txt securely and remove it from this location"
echo "2. Use AppRole credentials instead of root token in production"
echo "3. Enable TLS for production deployments"
echo "4. Regularly rotate secrets and tokens"
echo "5. Monitor audit logs for security events"
echo ""
echo "🌐 Access Vault UI at: $VAULT_ADDR"
echo "🔑 Default dev token: myroot" 