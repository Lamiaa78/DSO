#!/bin/bash

echo "🕷️  Démarrage du scan OWASP ZAP..."

# Variables
ZAP_API_KEY="zap-api-key"
TARGET_URL="http://vulnerable-app:3000"
ZAP_URL="http://localhost:8080"

# Création du répertoire de rapports s'il n'existe pas
mkdir -p ./reports

# Attendre que les services soient prêts
echo "⏳ Attente que les services soient prêts..."
sleep 10

echo "🔍 Lancement du scan de base..."
# Scan rapide avec écriture directe dans le volume monté
docker exec zap-scanner zap-baseline.py -t $TARGET_URL -J zap-report.json -r zap-report.html -w zap-report.md

echo "📄 Rapports générés dans le répertoire ./reports"