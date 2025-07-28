#!/bin/bash

# HashiCorp Vault Development Setup Script
# This script sets up a local Vault dev server for E2EE testing

set -e

echo "🔐 Setting up HashiCorp Vault for E2EE development..."

# Check if vault is installed
if ! command -v vault &> /dev/null; then
    echo "❌ Vault CLI not found. Please install HashiCorp Vault first:"
    echo "   https://developer.hashicorp.com/vault/downloads"
    exit 1
fi

# Start Vault dev server in background
echo "🚀 Starting Vault dev server..."
vault server -dev -dev-root-token-id=myroot -dev-listen-address=127.0.0.1:8200 &
VAULT_PID=$!

# Wait for Vault to start
sleep 3

# Set environment variables for this session
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=myroot

echo "⚙️  Configuring Vault for E2EE service..."

# Enable KV secrets engine (usually already enabled in dev mode)
vault secrets enable -path=secret kv-v2 2>/dev/null || echo "KV secrets engine already enabled"

# Create E2EE policy
cat > /tmp/e2ee-policy.hcl << EOF
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
EOF

vault policy write e2ee-policy /tmp/e2ee-policy.hcl

# Create a token for the E2EE service
E2EE_TOKEN=$(vault token create -policy=e2ee-policy -ttl=24h -format=json | jq -r '.auth.client_token')

echo "✅ Vault setup complete!"
echo ""
echo "📝 Add these environment variables to your .env file:"
echo "E2EE_VAULT_ADDR=http://127.0.0.1:8200"
echo "E2EE_VAULT_TOKEN=$E2EE_TOKEN"
echo ""
echo "🔧 Or use the root token for development (less secure):"
echo "E2EE_VAULT_ADDR=http://127.0.0.1:8200"
echo "E2EE_VAULT_TOKEN=myroot"
echo ""
echo "📊 Vault UI available at: http://127.0.0.1:8200/ui"
echo "🔑 Root token: myroot"
echo ""
echo "⚠️  To stop Vault server: kill $VAULT_PID"
echo "💡 Or run: pkill -f 'vault server -dev'"

# Clean up temp file
rm -f /tmp/e2ee-policy.hcl

# Keep script running to show the PID
echo ""
echo "🔄 Vault server running with PID: $VAULT_PID"
echo "Press Ctrl+C to stop this script (Vault will continue running in background)"

# Wait for interrupt
trap "echo ''; echo '🛑 Script stopped. Vault server still running.'; exit 0" INT
while true; do
    sleep 1
done 