// Application simple pour apprendre la sécurité - Niveau étudiant DevOps
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const { getSecret } = require('../scripts/vault-integration.js');

const app = express();
app.use(express.json());
app.use(express.static('public'));

console.log('🎓 Démarrage de l\'application de lab sécurité...');

// Enlever l'en-tête qui révèle la technologie utilisée
app.disable('x-powered-by');


app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY'); // Empêche les iframe malveillantes
    res.setHeader('X-Content-Type-Options', 'nosniff'); // Empêche le MIME sniffing
    next();
});

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

// Fonction simple pour éviter les attaques XSS (Cross-Site Scripting)
function escapeHTML(text) {
    return text
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Vérification d'authentification simple pour les endpoints protégés
function checkAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'Vous devez être connecté' });
    }
    
    next();
}

// Endpoint de connexion SÉCURISÉ (correction de l'injection SQL)
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    // Vérification basique des données
    if (!username || !password) {
        return res.status(400).json({ error: 'Username et password requis' });
    }
    
    console.log(`Tentative de connexion pour: ${username}`);
    
    // CORRECTION: Utiliser des paramètres pour éviter l'injection SQL
    const query = `SELECT * FROM users WHERE username = ?`;
    
    db.get(query, [username], (err, user) => {
        if (err) {
            console.error('Erreur DB:', err);
            return res.status(500).json({ error: 'Erreur serveur' });
        }
        
        if (!user) {
            return res.status(401).json({ error: 'Utilisateur introuvable' });
        }
        
        // Vérifier le mot de passe avec bcrypt
        bcrypt.compare(password, user.password, (err, isValid) => {
            if (isValid) {
                res.json({ 
                    message: 'Connexion réussie !',
                    user: {
                        id: user.id,
                        username: user.username,
                        role: user.role
                    },
                    token: 'simple-token-' + Date.now() // Token simple pour le lab
                });
            } else {
                res.status(401).json({ error: 'Mot de passe incorrect' });
            }
        });
    });
});

// Endpoint d'administration PROTÉGÉ
app.get('/admin/users', checkAuth, (req, res) => {
    console.log('Accès à la liste des utilisateurs (admin)');
    
    // Récupérer tous les utilisateurs (sans les mots de passe)
    db.all('SELECT id, username, email, role FROM users', (err, users) => {
        if (err) {
            console.error('Erreur DB:', err);
            return res.status(500).json({ error: 'Erreur serveur' });
        }
        res.json(users);
    });
});

// Page de profil SÉCURISÉE (correction XSS)
app.get('/profile/:username', (req, res) => {

    const safeUsername = escapeHTML(req.params.username);
    res.send(`<h1>Profil de ${safeUsername}</h1>`);
});

// Test de récupération sécurisée des secrets depuis Vault
app.get('/secure/config', async (req, res) => {
    console.log('Test de récupération des secrets depuis Vault...');
    
    try {
        // Utiliser notre fonction getSecret pour récupérer les données
        const dbConfig = await getSecret('app/database');
        const apiKeys = await getSecret('app/api-keys');
        
        console.log('Secrets récupérés avec succès depuis Vault');
        
        // Réponse sécurisée : ne pas exposer les vrais secrets
        res.json({ 
            message: 'Configuration récupérée depuis Vault',
            database: {
                host: dbConfig.host,
                port: dbConfig.port,
                name: dbConfig.name
                // Pas de mot de passe dans la réponse !
            },
            api: {
                // Montrer seulement les 4 derniers caractères de la clé
                key_preview: '****' + apiKeys.api_key.slice(-4)
            },
            vault_status: 'Connecté'
        });
        
    } catch (error) {
        console.error('Erreur Vault:', error.message);
        res.status(500).json({ 
            error: 'Impossible de récupérer la configuration',
            vault_status: 'Erreur de connexion'
        });
    }
});

// Status de l'application avec secrets sécurisés
app.get('/api/status', async (req, res) => {
    console.log('Vérification du status de l\'application...');
    
    try {
        // Au lieu d'avoir des secrets en dur, on les récupère depuis Vault
        const dbConfig = await getSecret('app/database');
        const apiKeys = await getSecret('app/api-keys');
        
        res.json({
            status: 'Application running',
            message: 'Lab sécurité - version étudiant DevOps',
            api: {
                configured: true,
                // Afficher seulement un aperçu sécurisé
                key_preview: apiKeys.api_key ? '****' + apiKeys.api_key.slice(-4) : 'Non configurée'
            },
            database: {
                connected: true,
                host: dbConfig.host,
                name: dbConfig.name
                // Jamais de mot de passe dans une réponse API !
            },
            vault_integration: 'Actif'
        });
        
    } catch (error) {
        console.error('Erreur lors de la récupération des secrets:', error.message);
        
        // Réponse de fallback si Vault n'est pas disponible
        res.json({ 
            status: 'Application running (mode dégradé)',
            message: 'Vault non accessible - utilisation de la configuration par défaut',
            api: { configured: false },
            database: { connected: false },
            vault_integration: 'Erreur'
        });
    }
});

app.listen(3000, () => {
    console.log('Application de lab sécurité démarrée sur le port 3000');
});
