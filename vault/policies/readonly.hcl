# Read-Only Policy
# This policy provides read-only access for monitoring and backup services

# Read-only access to all secrets
path "secret/data/*" {
  capabilities = ["read", "list"]
}

path "secret/metadata/*" {
  capabilities = ["read", "list"]
}

# System health and status - read only
path "sys/health" {
  capabilities = ["read"]
}

path "sys/seal-status" {
  capabilities = ["read"]
}

# Metrics access
path "sys/metrics" {
  capabilities = ["read"]
}

# Auth token self-operations
path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}

# List auth methods
path "sys/auth" {
  capabilities = ["read"]
}

# List secret engines
path "sys/mounts" {
  capabilities = ["read"]
}

# List policies
path "sys/policies/acl" {
  capabilities = ["list"]
}

# Read individual policies
path "sys/policies/acl/*" {
  capabilities = ["read"]
}

# Audit log access (for compliance)
path "sys/audit" {
  capabilities = ["read"]
} 