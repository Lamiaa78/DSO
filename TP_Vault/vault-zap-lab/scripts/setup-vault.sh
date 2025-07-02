#!/bin/bash

echo "🔐 Configuration de Vault..."

# Attendre que Vault soit prêt
sleep 5

# Variables
VAULT_ADDR="http://localhost:8204"
VAULT_TOKEN="myroot"

# Activer le moteur KV v2
curl -X POST \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"kv-v2"}' \
  $VAULT_ADDR/v1/sys/mounts/secret

# Créer des secrets pour l'application
curl -X POST \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "host": "db.example.com",
      "port": "5432",
      "name": "myapp",
      "username": "app_user",
      "password": "VerySecurePassword123!"
    }
  }' \
  $VAULT_ADDR/v1/secret/data/app/database

# Créer des clés API
curl -X POST \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "api_key": "prod-api-key-987654321",
      "webhook_secret": "webhook-secret-abc123",
      "jwt_secret": "super-secret-jwt-key-xyz789"
    }
  }' \
  $VAULT_ADDR/v1/secret/data/app/api-keys

echo "✅ Vault configuré avec succès!"
echo "🌐 Interface web: http://localhost:8204"
echo "🔑 Token root: $VAULT_TOKEN"