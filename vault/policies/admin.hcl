# Admin Policy
# This policy provides full administrative access to Vault

# Full access to all secret engines
path "*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# System backend - full access
path "sys/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Auth methods - full access
path "auth/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Audit backends - full access
path "sys/audit/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Policies - full access
path "sys/policies/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Mounts - full access
path "sys/mounts/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Health check
path "sys/health" {
  capabilities = ["read", "sudo"]
}

# Metrics
path "sys/metrics" {
  capabilities = ["read"]
}

# Capabilities
path "sys/capabilities" {
  capabilities = ["create", "update"]
}

path "sys/capabilities-self" {
  capabilities = ["create", "update"]
} 