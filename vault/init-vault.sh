#!/bin/bash

# Exit on any error
set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Vault configuration
export VAULT_ADDR=${VAULT_ADDR:-"http://localhost:8200"}
export VAULT_TOKEN=${VAULT_TOKEN:-"myroot"}

echo -e "${BLUE}🔐 Initializing HashiCorp Vault for Goravel Application${NC}"
echo ""

# Check if Vault is running
if ! curl -s "$VAULT_ADDR/v1/sys/health" > /dev/null 2>&1; then
    echo -e "${RED}❌ Vault is not running or not accessible at $VAULT_ADDR${NC}"
    echo "Please start Vault first: docker compose up vault -d"
    exit 1
fi

echo -e "${GREEN}✅ Vault is running at $VAULT_ADDR${NC}"

# Enable audit logging
echo "📋 Enabling audit logging..."
vault audit enable file file_path=/vault/logs/audit.log || true

# Enable secret engines
echo "🔧 Enabling secret engines..."

# KV v2 for application secrets
vault secrets enable -version=2 -path=secret kv || true

# Transit engine for encryption as a service
vault secrets enable transit || true

# PKI engine for certificate management
vault secrets enable pki || true

# Database engine for dynamic credentials
vault secrets enable database || true

# TOTP engine for time-based OTP
vault secrets enable totp || true

echo "✅ Secret engines enabled"

# Create policies
echo "📜 Creating Vault policies..."

# Admin policy
vault policy write admin - <<EOF
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
EOF

# Goravel application policy
vault policy write goravel-app - <<EOF
# Application configuration
path "secret/data/app/*" {
  capabilities = ["read"]
}
path "secret/metadata/app/*" {
  capabilities = ["read", "list"]
}

# Database credentials
path "secret/data/database/*" {
  capabilities = ["read"]
}
path "secret/metadata/database/*" {
  capabilities = ["read", "list"]
}

# Services configuration
path "secret/data/services/*" {
  capabilities = ["read"]
}
path "secret/metadata/services/*" {
  capabilities = ["read", "list"]
}

# Authentication configuration
path "secret/data/auth/*" {
  capabilities = ["read"]
}
path "secret/metadata/auth/*" {
  capabilities = ["read", "list"]
}

# Session configuration
path "secret/data/session/*" {
  capabilities = ["read"]
}
path "secret/metadata/session/*" {
  capabilities = ["read", "list"]
}

# Cache configuration
path "secret/data/cache/*" {
  capabilities = ["read"]
}
path "secret/metadata/cache/*" {
  capabilities = ["read", "list"]
}

# Transit engine for encryption
path "transit/encrypt/goravel" {
  capabilities = ["update"]
}
path "transit/decrypt/goravel" {
  capabilities = ["update"]
}

# TOTP for MFA
path "totp/code/*" {
  capabilities = ["read"]
}
path "totp/keys/*" {
  capabilities = ["create", "read", "update", "delete"]
}
EOF

# Read-only policy
vault policy write readonly - <<EOF
path "secret/data/*" {
  capabilities = ["read"]
}
path "secret/metadata/*" {
  capabilities = ["read", "list"]
}
EOF

echo "✅ Policies created"

# Create authentication methods
echo "🔑 Setting up authentication methods..."

# Enable AppRole auth method
vault auth enable approle || true

# Create role for Goravel application
vault write auth/approle/role/goravel \
    token_policies="goravel-app" \
    token_ttl=1h \
    token_max_ttl=4h \
    bind_secret_id=true

echo "✅ Authentication methods configured"

# Configure database dynamic credentials
echo "🗄️ Configuring database dynamic credentials..."

# PostgreSQL database connection
vault write database/config/postgresql \
    plugin_name=postgresql-database-plugin \
    connection_url="postgresql://{{username}}:{{password}}@postgres:5432/goravel?sslmode=disable" \
    allowed_roles="goravel-readwrite" \
    username="goravel" \
    password="goravel_password"

# Create database role
vault write database/roles/goravel-readwrite \
    db_name=postgresql \
    creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
    default_ttl="1h" \
    max_ttl="24h"

echo "✅ Database dynamic credentials configured"

# Create application secrets
echo "🔑 Creating application secrets..."

# Application configuration
vault kv put secret/app/config \
    name="Goravel" \
    env="local" \
    debug=true \
    timezone="UTC" \
    url="http://localhost" \
    host="127.0.0.1" \
    port="3000" \
    locale="en" \
    fallback_locale="en" \
    lang_path="lang"

# Application master key
vault kv put secret/app/master-key \
    master_key="$(openssl rand -base64 32)" \
    algorithm="AES-256-GCM" \
    created_at="$(date -Iseconds)"

# Application encryption key
vault kv put secret/app/app-key \
    key="$(openssl rand -base64 32)" \
    algorithm="AES-256-GCM" \
    created_at="$(date -Iseconds)"

# JWT secret
vault kv put secret/app/jwt-secret \
    jwt_secret="$(openssl rand -base64 64)" \
    algorithm="HS256" \
    access_token_ttl=60 \
    refresh_token_ttl=20160 \
    issuer="goravel" \
    audience="goravel-users"

# Database configuration
vault kv put secret/database/config \
    default="postgres" \
    slow_threshold=200 \
    migrations_table="migrations"

# PostgreSQL credentials
vault kv put secret/database/postgres \
    host="postgres" \
    port=5432 \
    database="goravel" \
    username="goravel" \
    password="goravel_password" \
    sslmode="disable" \
    prefix="" \
    singular=false \
    schema="public"

# Database pool configuration
vault kv put secret/database/pool \
    max_idle_conns=10 \
    max_open_conns=100 \
    conn_max_idletime=3600 \
    conn_max_lifetime=3600

# Redis configuration
vault kv put secret/database/redis \
    host="redis" \
    port=6379 \
    password="" \
    database=0

# Authentication configuration
vault kv put secret/auth/config \
    guard="users" \
    guard_driver="session" \
    provider_driver="database" \
    provider_table="users" \
    password_provider="users" \
    password_table="password_reset_tokens" \
    password_expire=60 \
    password_throttle=60 \
    allowed_redirect_hosts="localhost:3000,127.0.0.1:3000"

# Password rules
vault kv put secret/auth/password_rules \
    min_length=8 \
    require_uppercase=true \
    require_lowercase=true \
    require_numbers=true \
    require_symbols=false \
    check_compromised=true \
    max_attempts=5 \
    lockout_duration=30

# Session configuration
vault kv put secret/auth/session \
    lifetime=120 \
    expire_on_close=false \
    encrypt=false \
    files="storage/framework/sessions" \
    connection="" \
    table="sessions" \
    store="" \
    cookie="goravel_session" \
    path="/" \
    domain="" \
    secure=false \
    same_site="lax"

# MFA configuration
vault kv put secret/auth/mfa \
    enabled=true \
    issuer="Goravel App" \
    digits=6 \
    period=30 \
    backup_codes=8

# Session configuration
vault kv put secret/session/config \
    default="database" \
    connection="default" \
    table="sessions" \
    file_path="storage/framework/sessions" \
    redis_connection="default" \
    lifetime=120 \
    expire_on_close=false \
    encrypt=false \
    files="storage/framework/sessions" \
    gc_interval=30 \
    cookie="goravel_session" \
    path="/" \
    domain="" \
    secure=false \
    http_only=true \
    same_site="lax"

# Cache configuration
vault kv put secret/cache/config \
    default="redis" \
    redis_connection="default" \
    prefix="goravel_cache"

# MinIO configuration
vault kv put secret/services/minio \
    endpoint="minio:9000" \
    access_key="miniouserroot" \
    secret_key="miniouserrootpassword" \
    use_ssl=false \
    region="ap-southeast-1" \
    bucket="goravelstorage" \
    location="ap-southeast-1" \
    logs_bucket="goravel-logs" \
    traces_bucket="goravel-traces" \
    metrics_bucket="goravel-metrics" \
    uploads_bucket="goravelstorage" \
    avatars_bucket="goravelstorage" \
    documents_bucket="goravelstorage" \
    uploads_path="uploads" \
    avatars_path="avatars" \
    documents_path="documents" \
    logs_path="logs" \
    traces_path="traces" \
    metrics_path="metrics" \
    public_read_buckets="goravelstorage" \
    timeout=30 \
    retry_attempts=3 \
    part_size=67108864 \
    auto_create_buckets=true \
    enable_logging=true \
    observability_enabled=true \
    metrics_enabled=true \
    tracing_enabled=true \
    log_operations=true

# Mail configuration
vault kv put secret/services/mail \
    default="log" \
    host="mailpit" \
    port=1025 \
    encryption="tls" \
    username="" \
    password="" \
    timeout=5 \
    local_domain="" \
    ses_key="" \
    ses_secret="" \
    ses_region="us-east-1" \
    log_channel="" \
    from_address="hello@example.com" \
    from_name="Example" \
    markdown_theme="default"

# Google OAuth configuration
vault kv put secret/services/oauth/google \
    enabled=false \
    client_id="" \
    client_secret="" \
    redirect_url="http://localhost:3000/auth/oauth/google/callback" \
    scopes="https://www.googleapis.com/auth/userinfo.email,https://www.googleapis.com/auth/userinfo.profile"

# GitHub OAuth configuration
vault kv put secret/services/oauth/github \
    enabled=false \
    client_id="" \
    client_secret="" \
    redirect_url="http://localhost:3000/auth/oauth/github/callback" \
    scopes="user:email,read:user"

# Microsoft OAuth configuration
vault kv put secret/services/oauth/microsoft \
    enabled=false \
    client_id="" \
    client_secret="" \
    redirect_url="http://localhost:3000/auth/oauth/microsoft/callback" \
    scopes="openid,profile,email"

# Discord OAuth configuration
vault kv put secret/services/oauth/discord \
    enabled=false \
    client_id="" \
    client_secret="" \
    redirect_url="http://localhost:3000/auth/oauth/discord/callback" \
    scopes="identify,email"

# WebAuthn configuration
vault kv put secret/services/webauthn \
    enabled=true \
    rp_id="localhost" \
    rp_name="Goravel App" \
    rp_origin="http://localhost:3000" \
    timeout=60000

echo "✅ Application secrets created"

# Create transit encryption key
echo "🔐 Creating encryption keys..."
vault write -f transit/keys/goravel

echo "✅ Encryption keys created"

# Create AppRole credentials for the application
echo "🔑 Creating AppRole credentials..."
ROLE_ID=$(vault read -field=role_id auth/approle/role/goravel/role-id)
SECRET_ID=$(vault write -field=secret_id -f auth/approle/role/goravel/secret-id)

echo ""
echo "🎉 Vault initialization complete!"
echo ""
echo "📋 Summary:"
echo "- Vault Address: $VAULT_ADDR"
echo "- Audit logging: Enabled"
echo "- Secret engines: KV v2, Transit, PKI, Database, TOTP"
echo "- Auth methods: Token, AppRole"
echo "- Policies: admin, goravel-app, readonly"
echo "- Application secrets: Created for all services"
echo ""
echo "📁 AppRole Credentials for Production:"
echo "- Role ID: $ROLE_ID"
echo "- Secret ID: $SECRET_ID"
echo ""
echo "📁 Secret Organization:"
echo "- Application Config: secret/app/config, secret/app/master-key, secret/app/app-key"
echo "- JWT Configuration: secret/app/jwt-secret"
echo "- Database: secret/database/postgres, secret/database/redis, secret/database/config"
echo "- Authentication: secret/auth/config, secret/auth/session, secret/auth/mfa"
echo "- Session: secret/session/config"
echo "- Cache: secret/cache/config"
echo "- Services: secret/services/minio, secret/services/mail"
echo "- OAuth: secret/services/oauth/google, secret/services/oauth/github, etc."
echo "- WebAuthn: secret/services/webauthn"
echo ""
echo "🌐 Access Vault UI: $VAULT_ADDR"
echo "🔑 Token: $VAULT_TOKEN"
echo ""
echo "🚀 Your application is now fully configured to use HashiCorp Vault!"
echo "   All sensitive configuration has been moved from environment variables to Vault."
echo "" 