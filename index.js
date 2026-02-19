const express = require('express');
require('dotenv').config();
const GoogleAuth = require('./googleAuth');

const app = express();

// -----------------------------------------------------------------------------
// CONFIGURAÇÃO
// -----------------------------------------------------------------------------
const PORT = process.env.PORT || 5000;

// -----------------------------------------------------------------------------
// INICIALIZAÇÃO DA AUTENTICAÇÃO
// -----------------------------------------------------------------------------
// Instanciamos a classe passando o app express.
// Ela configurará automaticamente as sessões, passport e rotas.
new GoogleAuth(app);

// -----------------------------------------------------------------------------
// INICIALIZAÇÃO DO SERVIDOR
// -----------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`Servidor a correr em http://localhost:${PORT}`);
});