# Goravel Application Policy
# This policy defines the permissions for the Goravel application to access secrets

# Application secrets - full access
path "secret/data/app/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/metadata/app/*" {
  capabilities = ["list", "read", "delete"]
}

# Database secrets - read only
path "secret/data/database/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/database/*" {
  capabilities = ["list", "read"]
}

# Service secrets - read only
path "secret/data/services/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/services/*" {
  capabilities = ["list", "read"]
}

# API secrets - read/write
path "secret/data/api/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/metadata/api/*" {
  capabilities = ["list", "read", "delete"]
}

# Environment-specific secrets - read only
path "secret/data/environments/{{identity.entity.aliases.auth_kubernetes_*.metadata.service_account_namespace}}/*" {
  capabilities = ["read", "list"]
}

# Allow token self-renewal
path "auth/token/renew-self" {
  capabilities = ["update"]
}

# Allow token self-lookup
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

# Allow revoking own token
path "auth/token/revoke-self" {
  capabilities = ["update"]
}

# Transit engine for encryption (if enabled)
path "transit/encrypt/goravel-*" {
  capabilities = ["update"]
}

path "transit/decrypt/goravel-*" {
  capabilities = ["update"]
}

path "transit/datakey/plaintext/goravel-*" {
  capabilities = ["update"]
}

# PKI engine for certificate management (if enabled)
path "pki/issue/goravel-role" {
  capabilities = ["update"]
}

# Database engine for dynamic credentials (if enabled)
path "database/creds/goravel-*" {
  capabilities = ["read"]
}

# TOTP engine for 2FA (if enabled)
path "totp/code/goravel-*" {
  capabilities = ["update"]
}

path "totp/keys/goravel-*" {
  capabilities = ["create", "read", "update", "delete", "list"]
} 