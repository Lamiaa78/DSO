const vault = require('node-vault')({
  apiVersion: 'v1',
  endpoint: process.env.VAULT_ADDR || 'http://127.0.0.1:8200',
  token: process.env.VAULT_TOKEN
});

/**
 * Fonction pour récupérer un secret depuis Vault
 * @param {string} path 
 * @returns {Promise<object>} 
 */
async function getSecret(path) {
  try {
    const result = await vault.read(`secret/data/${path}`);
    return result.data.data;
  } catch (error) {
    console.error(`Erreur lors de la récupération du secret '${path}':`, error.message);
    throw error;
  }
}


async function configureApp() {
  try {
    // Récupérer les informations de base de données
    const dbConfig = await getSecret('app/database');
    console.log('Base de données configurée avec succès');
    
    // Récupérer les clés API
    const apiKeys = await getSecret('app/api-keys');
    console.log('API keys récupérées avec succès');
    
    // Configuration sécurisée de l'application
    return {
      database: {
        host: dbConfig.host,
        port: dbConfig.port,
        name: dbConfig.name,
        username: dbConfig.username,
        password: dbConfig.password
      },
      api: {
        key: apiKeys.api_key,
        webhookSecret: apiKeys.webhook_secret,
        jwtSecret: apiKeys.jwt_secret
      }
    };
  } catch (error) {
    console.error('Impossible de configurer l\'application:', error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  configureApp().then(config => {
    console.log('Configuration récupérée avec succès (secrets masqués):');
    console.log({
      database: {
        ...config.database,
        password: '********'
      },
      api: {
        ...config.api,
        key: '****' + config.api.key.slice(-4),
        webhookSecret: '********',
        jwtSecret: '********'
      }
    });
  });
}

module.exports = { getSecret, configureApp };
