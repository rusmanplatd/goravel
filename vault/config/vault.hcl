# HashiCorp Vault Configuration
# This configuration is suitable for production use with proper security settings

# Storage backend - using file storage for simplicity
# In production, consider using Consul, etcd, or cloud storage
storage "file" {
  path = "/vault/data"
}

# Listener configuration
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1  # Set to 0 in production with proper TLS certificates
  
  # Uncomment for production TLS
  # tls_cert_file = "/vault/config/vault.crt"
  # tls_key_file  = "/vault/config/vault.key"
  # tls_min_version = "tls12"
}

# API address
api_addr = "http://0.0.0.0:8200"

# Cluster address (for HA setups)
cluster_addr = "http://0.0.0.0:8201"

# UI configuration
ui = true

# Logging
log_level = "info"
log_format = "json"

# Disable mlock for containerized environments
disable_mlock = true

# Default lease settings
default_lease_ttl = "168h"    # 1 week
max_lease_ttl = "720h"        # 30 days

# Plugin directory
plugin_directory = "/vault/plugins"

# Seal configuration (Auto-unseal for production)
# Uncomment and configure for production use
# seal "awskms" {
#   region     = "us-west-2"
#   kms_key_id = "your-kms-key-id"
# }

# Telemetry (optional)
telemetry {
  prometheus_retention_time = "30s"
  disable_hostname = true
  
  # Uncomment for metrics collection
  # statsite_address = "statsite:8125"
  # statsd_address = "statsd:8125"
}

# Entropy Augmentation (Enterprise feature)
# entropy "seal" {
#   mode = "augmentation"
# }

# Cluster configuration for HA
# cluster_name = "vault-cluster"

# Raw storage endpoint (disable in production)
raw_storage_endpoint = false

# Cache size (in bytes)
cache_size = 33554432

# Disable clustering for single-node setup
disable_clustering = false

# Disable performance standby
disable_performance_standby = false

# Disable sealwrap
disable_sealwrap = false

# PID file
pid_file = "/vault/vault.pid" 