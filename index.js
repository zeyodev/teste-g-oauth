import express from 'express';
import "dotenv/config";
import GoogleAuth from './services/google/index.js';
import MetaAuth from './services/meta/index.js';
import CanvaAuth from './services/canva/index.js';

const app = express();

// -----------------------------------------------------------------------------
// CONFIGURAÇÃO
// -----------------------------------------------------------------------------
const PORT = process.env.PORT || 5000;

// Middleware para parsing de JSON (necessário para POST /exchange-token)
app.use(express.json());

// -----------------------------------------------------------------------------
// INICIALIZAÇÃO DA AUTENTICAÇÃO
// -----------------------------------------------------------------------------
// Instanciamos a classe passando o app express.
// Ela configurará automaticamente as sessões, passport e rotas.
new GoogleAuth(app);
new MetaAuth(app);
new CanvaAuth(app);

// -----------------------------------------------------------------------------
// INICIALIZAÇÃO DO SERVIDOR
// -----------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`Servidor a correr em http://localhost:${PORT}`);
});