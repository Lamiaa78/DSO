# 📚 Rapport de Lab DevOps - Sécurité et Gestion des Secrets

## 🎯 Objectifs pédagogiques
- Découvrir les vulnérabilités web de base (OWASP Top 10)
- Apprendre à utiliser HashiCorp Vault pour stocker des secrets
- Comprendre les outils de test de sécurité (OWASP ZAP)
- S'initier aux bonnes pratiques DevSecOps

## � Exercice 1 : Découverte des vulnérabilités

### 1.1 Test d'injection SQL - Niveau débutant

#### 🧪 Ce que j'ai testé
- **Payload utilisé** : `admin' OR '1'='1' --`
- **Résultat** : `{"error": "Invalid credentials"}`
- **URL testée** : `POST http://localhost:3000/login`

#### 📚 Ce que j'ai appris
Quand j'ai essayé l'injection SQL, voici ce qui s'est passé :

1. **Pourquoi cette attaque fonctionne en théorie** :
   - Le code original concatène directement l'input utilisateur dans la requête SQL
   ```javascript
   // Code vulnérable trouvé dans l'application
   const query = `SELECT * FROM users WHERE username = '${username}'`;
   ```
   - Avec mon payload, la requête devient : `SELECT * FROM users WHERE username = 'admin' OR '1'='1' --'`
   - `'1'='1'` est toujours vrai, donc ça devrait contourner l'authentification
   - `--` commente le reste de la requête SQL

2. **Pourquoi l'attaque échoue quand même** :
   - Même si on récupère l'utilisateur admin depuis la base
   - La vérification du mot de passe avec bcrypt échoue car on n'a pas fourni le bon mot de passe

3. **Impact de sécurité découvert** :
   - L'injection SQL existe bel et bien dans le code
   - Un attaquant pourrait extraire des données de la base avec des techniques avancées
   - Avec plus de connaissances, il pourrait contourner complètement l'authentification

#### ✅ Correction appliquée
J'ai corrigé la vulnérabilité en remplaçant la concaténation par des requêtes paramétrées :

```javascript
// ❌ Code vulnérable
const query = `SELECT * FROM users WHERE username = '${username}'`;

// ✅ Code sécurisé
const query = `SELECT * FROM users WHERE username = ?`;
db.get(query, [username], (err, user) => {

});
```

### 1.2 Test XSS (Cross-Site Scripting) - Pratique de sécurisation
   - La double vérification (requête SQL + bcrypt) limite l'impact immédiat

#### Correction recommandée
Pour corriger cette vulnérabilité, il faut utiliser des requêtes préparées:

```javascript
const query = `SELECT * FROM users WHERE username = ?`;
db.get(query, [username], (err, user) => {
    // Suite du code...
});
```

### 2. Test XSS (Cross-Site Scripting)

#### 🧪 Test effectué
- **Payload utilisé** : `<script>alert('XSS')</script>`
- **Point d'injection** : `/profile/:username`
- **Résultat avant correction** : Alerte JavaScript s'affichait
- **URL générée** : `http://localhost:3000/profile/<script>alert('XSS')</script>`

#### 📚 Analyse technique (compréhension DevOps)
1. **Ce qui se passait avant la correction** :
   ```javascript
   // Code vulnérable original
   app.get('/profile/:username', (req, res) => {
       const username = req.params.username;
       res.send(`<h1>Profil de ${username}</h1>`);
   });
   ```
   - L'application affichait directement le paramètre `username` dans la page HTML
   - Le navigateur exécutait le code JavaScript injecté
   - C'est très dangereux car un attaquant peut voler des cookies ou rediriger l'utilisateur

2. **Impact sur les utilisateurs** :
   - Vol de cookies de session
   - Redirection vers des sites malveillants
   - Exécution d'actions non autorisées au nom de l'utilisateur

#### ✅ Correction appliquée
J'ai créé une fonction simple pour échapper les caractères dangereux :

```javascript
// Fonction de protection contre le XSS
function escapeHTML(text) {
    return text
        .replace(/&/g, "&amp;")   // & devient &amp;
        .replace(/</g, "&lt;")    // < devient &lt;
        .replace(/>/g, "&gt;")    // > devient &gt;
        .replace(/"/g, "&quot;")  // " devient &quot;
        .replace(/'/g, "&#039;"); // ' devient &#039;
}

// Utilisation sécurisée
app.get('/profile/:username', (req, res) => {
    const safeUsername = escapeHTML(req.params.username);
    res.send(`<h1>Profil de ${safeUsername}</h1>`);
});
```

## 🕷️ Exercice 2 : Analyse automatisée avec OWASP ZAP

### 2.1 Configuration du scanner

OWASP ZAP (Zed Attack Proxy) est un outil gratuit de test de sécurité qui s'intègre bien dans les pipelines DevOps. J'ai configuré le scan pour analyser mon application sur `http://localhost:3000`.

**Étapes réalisées :**
1. Démarrage de ZAP via Docker
2. Configuration du scan automatique via l'interface web
3. Exploration automatique de l'application (spider)
4. Scan actif des vulnérabilités trouvées

### 2.2 Résultats du scan 

Le scan a révélé plusieurs vulnérabilités dans l'application. Voici mon analyse des principales alertes détectées :

- **CSP: Failure to Define Directive with No Fallback (4)** - Risque moyen
- **Content Security Policy (CSP) Header Not Set (4)** - Risque moyen
- **Missing Anti-clickjacking Header (4)** - Risque moyen
- **Server Leaks Information via "X-Powered-By" HTTP Response Header Field(s) (9)** - Risque bas
- **X-Content-Type-Options Header Missing (4)** - Risque bas
- **Authentication Request Identified (2)** - Information
- **Modern Web Application (3)** - Information

### 3. Analyse des vulnérabilités détectées

#### CSP: Failure to Define Directive with No Fallback & CSP Header Not Set
Ces alertes indiquent que l'application n'implémente pas correctement les Content Security Policies (CSP), qui sont des mécanismes de sécurité permettant de limiter l'exécution de scripts non autorisés. Cette absence facilite les attaques XSS, comme nous l'avons démontré dans l'exercice précédent.

**Correction recommandée** : Implémenter un en-tête CSP strict :
```javascript
// Dans Express.js
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'"
  );
  next();
});
```

#### Missing Anti-clickjacking Header
L'application ne définit pas d'en-tête X-Frame-Options, ce qui la rend vulnérable aux attaques de clickjacking, où un attaquant peut intégrer l'application dans un iframe et tromper les utilisateurs pour qu'ils cliquent sur des éléments sans s'en rendre compte.

**Correction recommandée** : Ajouter l'en-tête X-Frame-Options pour empêcher l'intégration dans des iframes :
```javascript
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});
```

#### Server Leaks Information via "X-Powered-By"
L'en-tête X-Powered-By révèle des informations sur la technologie utilisée par le serveur (Express.js), ce qui peut aider un attaquant à cibler des vulnérabilités spécifiques.

**Correction recommandée** : Supprimer cet en-tête :
```javascript
// Dans Express.js
app.disable('x-powered-by');
```

#### X-Content-Type-Options Header Missing
Sans cet en-tête, les navigateurs peuvent interpréter incorrectement le contenu, ce qui peut conduire à des attaques MIME-sniffing.

**Correction recommandée** : Ajouter l'en-tête X-Content-Type-Options :
```javascript
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});
```

#### Authentication Request Identified
Cette information indique que ZAP a identifié des requêtes d'authentification dans l'application. Ce n'est pas une vulnérabilité en soi, mais un point d'attention pour des analyses approfondies.

## Exercice 3 : Sécurisation avec Vault

### 1. Exploration de Vault

*   **Action :** Connexion à Vault et consultation du chemin `secret/app/`.
*   **Résultat Observé :** Deux secrets disponibles :
    - **api-keys** : contient clés API et secrets JWT  
      • API : `/v1/secret/data/app/api-keys`  
      • CLI : `vault kv get secret/app/api-keys`  
      • Version : 1  
      • Âge : ~2 heures  
    - **database** : contient informations de connexion DB  
      • API : `/v1/secret/data/app/database`  
      • CLI : `vault kv get secret/app/database`  
      • Version : 1  
      • Âge : ~2 heures  
*   **Analyse :** Les secrets sont correctement montés et versionnés, garantissant une gestion sécurisée des configurations sensibles.

### 2. Intégration sécurisée des secrets

#### Modifications effectuées

J'ai implémenté les modifications suivantes pour sécuriser la gestion des secrets dans l'application:

1. **Suppression des secrets hardcodés**:
   - Supprimé les constantes `API_KEY` et `DB_PASSWORD` du code source
   - Remplacé par des appels à Vault pour récupérer les secrets de manière dynamique

2. **Amélioration de l'endpoint `/api/status`**:
   - L'endpoint récupère maintenant les secrets depuis Vault au lieu d'utiliser des valeurs hardcodées
   - Les secrets sensibles (mots de passe, clés complètes) ne sont plus exposés dans la réponse API
   - Seules des versions tronquées des clés sont renvoyées (ex: `****1234`)

3. **Renforcement de l'endpoint `/secure/config`**:
   - Utilisation de la fonction `getSecret` du module `vault-integration.js`
   - Récupération à la fois des informations de base de données et des clés API
   - Masquage approprié des informations sensibles dans la réponse

4. **Gestion des erreurs améliorée**:
   - Meilleure journalisation des erreurs pour faciliter le débogage
   - Réponses d'erreur ne divulguant pas d'informations sensibles

#### Tests de l'endpoint `/secure/config`

J'ai testé l'endpoint `/secure/config` avec les résultats suivants:

1. **Test avec Vault opérationnel**:
   - URL testée: `http://localhost:3000/secure/config`
   - Résultat: La réponse contient les informations de configuration non sensibles
   - Structure de la réponse:
   ```json
   {
     "message": "Configuration retrieved securely",
     "database": {
       "host": "db.example.com",
       "port": "5432",
       "name": "myapp"
     },
     "api": {
       "key_preview": "****1234"
     }
   }
   ```
   - Le mot de passe de la base de données et les secrets complets ne sont pas exposés

2. **Test avec Vault indisponible**:
   - Simulé en utilisant un token Vault invalide
   - La gestion d'erreur fonctionne correctement
   - Message d'erreur générique retourné sans exposer de détails techniques sensibles

3. **Vérification des secrets dans Vault**:
   - Confirmé que les secrets sont correctement stockés dans Vault
   - Les chemins `secret/data/app/database` et `secret/data/app/api-keys` contiennent les valeurs attendues

Cette implémentation respecte les bonnes pratiques de gestion des secrets:
- Aucun secret en dur dans le code
- Accès aux secrets uniquement lorsque nécessaire
- Exposition minimale des informations sensibles
- Robustesse face aux pannes de Vault

## 💡 Bonnes pratiques apprises

**1. Sécurité dès le développement (Shift-Left)**
- Intégrer les tests de sécurité dès le début du projet
- Former les développeurs aux vulnérabilités courantes
- Utiliser des outils d'analyse statique dans l'IDE

**2. Gestion des secrets**
- ❌ Ne jamais : stocker des secrets dans le code source
- ✅ Toujours : utiliser des outils dédiés comme Vault
- ✅ Masquer les secrets dans les logs et réponses API

**3. Tests automatisés**
- Intégrer OWASP ZAP dans les pipelines CI/CD
- Configurer des seuils de sécurité (pas de vulnérabilités high/critical)
- Générer des rapports automatiques pour les équipes

**4. Monitoring et alertes**
- Surveiller les tentatives d'attaques
- Alerter sur les comportements suspects
- Journaliser les événements de sécurité (sans données sensibles)

### 🔄 Intégration DevSecOps

**Pipeline CI/CD sécurisé :**

```yaml
stages:
  - build
  - security-scan
  - test
  - deploy

security-scan:
  stage: security-scan
  script:
    - docker run -t owasp/zap2docker-stable zap-baseline.py -t $TARGET_URL
    - sonarqube-scan --project-key=$PROJECT_KEY
  allow_failure: false  # Bloquer si vulnérabilités critiques
```
