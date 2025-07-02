# Lab Vault & OWASP ZAP - Sécurisation et Test d'Applications

## Objectifs pédagogiques
- Comprendre la gestion sécurisée des secrets avec HashiCorp Vault
- Maîtriser les tests de sécurité automatisés avec OWASP ZAP
- Intégrer la sécurité dans le cycle de développement (DevSecOps)
- Identifier et corriger les vulnérabilités courantes

## Prérequis
- Docker et Docker Compose installés
- Git
- Un navigateur web
- 8 Go de RAM disponibles

## Architecture du Lab

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Application   │◄──►│   Vault Server  │◄──►│   OWASP ZAP     │
│   Vulnérable    │    │   (Secrets)     │    │   (Scanner)     │
│   (Port 3000)   │    │   (Port 8200)   │    │   (Port 8080)   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Partie 1 : Configuration de l'environnement

### 1.1 Structure du projet

Créez la structure suivante :
```
vault-zap-lab/
├── docker-compose.yml
├── vault/
│   ├── config.hcl
│   └── policies/
│       └── app-policy.hcl
├── app/
│   ├── Dockerfile
│   ├── package.json
│   ├── server.js
│   └── public/
│       └── index.html
└── scripts/
    ├── setup-vault.sh
    ├── run-zap-scan.sh
    └── vault-integration.js
```

### 1.2 Docker Compose

Créez `docker-compose.yml` :
```yaml
version: '3.8'

services:
  vault:
    image: vault:1.15
    container_name: vault-server
    ports:
      - "8200:8200"
    environment:
      - VAULT_DEV_ROOT_TOKEN_ID=myroot
      - VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200
    cap_add:
      - IPC_LOCK
    volumes:
      - ./vault/config.hcl:/vault/config/config.hcl
      - ./vault/policies:/vault/policies
    networks:
      - lab-network

  vulnerable-app:
    build: ./app
    container_name: vulnerable-app
    ports:
      - "3000:3000"
    environment:
      - VAULT_ADDR=http://vault:8200
      - VAULT_TOKEN=myroot
    depends_on:
      - vault
    networks:
      - lab-network

  owasp-zap:
    image: owasp/zap2docker-stable
    container_name: zap-scanner
    ports:
      - "8080:8080"
    command: zap-webswing.sh
    networks:
      - lab-network

networks:
  lab-network:
    driver: bridge
```

### 1.3 Configuration Vault

Créez `vault/config.hcl` :
```hcl
ui = true
disable_mlock = true

storage "inmem" {}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
}

api_addr = "http://0.0.0.0:8200"
cluster_addr = "https://0.0.0.0:8201"
```

Créez `vault/policies/app-policy.hcl` :
```hcl
# Politique pour l'application
path "secret/data/app/*" {
  capabilities = ["read"]
}

path "secret/metadata/app/*" {
  capabilities = ["list", "read"]
}

path "database/creds/app-role" {
  capabilities = ["read"]
}
```

## Partie 2 : Application vulnérable

### 2.1 Application Node.js

Créez `app/package.json` :
```json
{
  "name": "vulnerable-app",
  "version": "1.0.0",
  "main": "server.js",
  "dependencies": {
    "express": "^4.18.2",
    "node-vault": "^0.10.2",
    "sqlite3": "^5.1.6",
    "bcrypt": "^5.1.0"
  }
}
```

Créez `app/Dockerfile` :
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package.json .
RUN npm install
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
```

Créez `app/server.js` :
```javascript
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const vault = require('node-vault')({
    apiVersion: 'v1',
    endpoint: process.env.VAULT_ADDR,
    token: process.env.VAULT_TOKEN
});

const app = express();
app.use(express.json());
app.use(express.static('public'));

// Base de données SQLite en mémoire
const db = new sqlite3.Database(':memory:');

// Initialisation de la base
db.serialize(() => {
    db.run(`CREATE TABLE users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        password TEXT,
        email TEXT,
        role TEXT DEFAULT 'user'
    )`);
    
    db.run(`INSERT INTO users VALUES 
        (1, 'admin', '$2b$10$8K1p/a0dVpn7N9Q7r5E4Mefm7zG4oC8kF9X2p1Z3q4E5t6R7y8S9', 'admin@example.com', 'admin'),
        (2, 'user', '$2b$10$9L2q/b1eWqo8O0R8s6F5Nfgn8aH5pD9lG0Y3q2a4r5F6g7H8i9J0', 'user@example.com', 'user')`);
});

// VULNÉRABILITÉ 1: Injection SQL
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    // Requête SQL vulnérable à l'injection
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    
    db.get(query, (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // VULNÉRABILITÉ 2: Mot de passe en clair dans les logs
        console.log(`Login attempt: ${username}:${password}`);
        
        bcrypt.compare(password, user.password, (err, result) => {
            if (result) {
                res.json({ 
                    message: 'Login successful', 
                    user: user,
                    // VULNÉRABILITÉ 3: Token JWT hardcodé
                    token: 'hardcoded-jwt-token-123'
                });
            } else {
                res.status(401).json({ error: 'Invalid credentials' });
            }
        });
    });
});

// VULNÉRABILITÉ 4: Endpoint sans authentification exposant des données sensibles
app.get('/admin/users', (req, res) => {
    db.all('SELECT * FROM users', (err, users) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(users);
    });
});

// VULNÉRABILITÉ 5: XSS via paramètre non validé
app.get('/profile/:username', (req, res) => {
    const username = req.params.username;
    res.send(`<h1>Profil de ${username}</h1>`);
});

// Intégration Vault - Version sécurisée
app.get('/secure/config', async (req, res) => {
    try {
        // Récupération sécurisée des secrets depuis Vault
        const secret = await vault.read('secret/data/app/database');
        const dbConfig = secret.data.data;
        
        res.json({ 
            message: 'Configuration retrieved securely',
            // Ne pas exposer les vrais secrets
            database: {
                host: dbConfig.host,
                port: dbConfig.port,
                name: dbConfig.name
                // password non exposé
            }
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to retrieve configuration' });
    }
});

// VULNÉRABILITÉ 6: Secrets hardcodés
const API_KEY = 'sk-1234567890abcdef';
const DB_PASSWORD = 'super_secret_password';

app.get('/api/status', (req, res) => {
    res.json({
        status: 'running',
        api_key: API_KEY, // Exposé par erreur
        database: {
            connected: true,
            password: DB_PASSWORD // Très mauvaise pratique
        }
    });
});

app.listen(3000, () => {
    console.log('Vulnerable app running on port 3000');
});
```

Créez `app/public/index.html` :
```html
<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable App - Lab</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 600px; margin: 0 auto; }
        .form-group { margin: 20px 0; }
        input, button { padding: 10px; margin: 5px; }
        .vulnerability { background: #ffe6e6; padding: 15px; margin: 10px 0; border-left: 4px solid #ff0000; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Application Vulnérable - Lab Sécurité</h1>
        
        <div class="vulnerability">
            <h3>🚨 Vulnérabilités présentes :</h3>
            <ul>
                <li>Injection SQL dans /login</li>
                <li>XSS dans /profile/:username</li>
                <li>Secrets hardcodés exposés</li>
                <li>Endpoints non sécurisés</li>
                <li>Mots de passe loggés</li>
            </ul>
        </div>
        
        <h2>Test de connexion</h2>
        <div class="form-group">
            <input type="text" id="username" placeholder="Username" value="admin">
            <input type="password" id="password" placeholder="Password" value="password">
            <button onclick="login()">Se connecter</button>
        </div>
        
        <h2>Test XSS</h2>
        <div class="form-group">
            <input type="text" id="xss" placeholder="<script>alert('XSS')</script>" value="<script>alert('XSS')</script>">
            <button onclick="testXSS()">Tester XSS</button>
        </div>
        
        <div id="result"></div>
    </div>

    <script>
        async function login() {
            const username = document.getElementById('username').value;
            const password = document.getElementById('password').value;
            
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username, password })
                });
                
                const result = await response.json();
                document.getElementById('result').innerHTML = 
                    `<pre>${JSON.stringify(result, null, 2)}</pre>`;
            } catch (error) {
                document.getElementById('result').innerHTML = 
                    `<p style="color: red;">Erreur: ${error.message}</p>`;
            }
        }
        
        function testXSS() {
            const payload = document.getElementById('xss').value;
            window.open(`/profile/${encodeURIComponent(payload)}`, '_blank');
        }
    </script>
</body>
</html>
```

## Partie 3 : Scripts d'automatisation

### 3.1 Configuration Vault

Créez `scripts/setup-vault.sh` :
```bash
#!/bin/bash

echo "🔐 Configuration de Vault..."

# Attendre que Vault soit prêt
sleep 5

# Variables
VAULT_ADDR="http://localhost:8200"
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
echo "🌐 Interface web: http://localhost:8200"
echo "🔑 Token root: $VAULT_TOKEN"
```

### 3.2 Script de scan ZAP

Créez `scripts/run-zap-scan.sh` :
```bash
#!/bin/bash

echo "🕷️  Démarrage du scan OWASP ZAP..."

# Variables
ZAP_API_KEY="zap-api-key"
TARGET_URL="http://vulnerable-app:3000"
ZAP_URL="http://localhost:8080"

# Attendre que les services soient prêts
sleep 10

# Scan rapide
docker exec zap-scanner zap-baseline.py \
  -t $TARGET_URL \
  -J zap-report.json \
  -H zap-report.html \
  -r zap-report.md

# Copier les rapports
docker cp zap-scanner:/zap/wrk/zap-report.json ./reports/
docker cp zap-scanner:/zap/wrk/zap-report.html ./reports/
docker cp zap-scanner:/zap/wrk/zap-report.md ./reports/

echo "✅ Scan terminé! Rapports dans ./reports/"
```

## Partie 4 : Exercices pratiques

### Exercice 1 : Test des vulnérabilités

1. **Démarrer l'environnement :**
```bash
docker-compose up -d
chmod +x scripts/setup-vault.sh
./scripts/setup-vault.sh
```

2. **Tester l'injection SQL :**
   - Essayez : `admin' OR '1'='1' --`
   - Analysez le comportement
   - Documentez la vulnérabilité

3. **Tester XSS :**
   - Utilisez : `<script>alert('XSS')</script>`
   - Testez dans /profile/:username
   - Vérifiez l'exécution du code

### Exercice 2 : Analyse avec OWASP ZAP

1. **Interface ZAP :**
   - Accédez à http://localhost:8080
   - Configurez le scan automatique
   - Analysez l'application sur http://localhost:3000

2. **Scan manuel :**
   - Utilisez le spider pour découvrir les endpoints
   - Lancez un scan actif
   - Examinez les vulnérabilités détectées

3. **Génération de rapports :**
```bash
mkdir reports
chmod +x scripts/run-zap-scan.sh
./scripts/run-zap-scan.sh
```

### Exercice 3 : Sécurisation avec Vault

1. **Exploration de Vault :**
   - Interface web : http://localhost:8200
   - Token : `myroot`
   - Explorez les secrets créés

2. **Intégration sécurisée :**
   - Modifiez l'application pour utiliser Vault
   - Remplacez les secrets hardcodés
   - Testez l'endpoint `/secure/config`

3. **Correction des vulnérabilités :**
   - Corrigez l'injection SQL (requêtes préparées)
   - Sécurisez les endpoints
   - Validez les entrées utilisateur



### Livrables attendus

1. **Rapport de vulnérabilités** (fichier JSON/HTML de ZAP)
2. **Code corrigé** de l'application
3. **Configuration Vault** optimisée
4. **Procédure** d'intégration continue
5. **Recommandations** de sécurité

## Ressources complémentaires

- [Documentation Vault](https://www.vaultproject.io/docs)
- [Guide OWASP ZAP](https://www.zaproxy.org/docs/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [DevSecOps Best Practices](https://owasp.org/www-project-devsecops-guideline/)

## Nettoyage

Pour arrêter l'environnement :
```bash
docker-compose down -v
docker system prune -f
```
