const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { google } = require('googleapis');
require('dotenv').config();

const app = express();

// -----------------------------------------------------------------------------
// CONFIGURAÇÃO
// -----------------------------------------------------------------------------
// Atualizado para 5000 conforme solicitado
const PORT = process.env.PORT || 5000; 
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'COLOQUE_SEU_CLIENT_ID_AQUI';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || 'COLOQUE_SEU_CLIENT_SECRET_AQUI';

const SCOPES = [
  'profile',
  'email',
  'https://www.googleapis.com/auth/calendar.events',
  'https://www.googleapis.com/auth/meetings.space.created'
];

// -----------------------------------------------------------------------------
// CONFIGURAÇÃO DO PASSPORT
// -----------------------------------------------------------------------------
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: `http://localhost:${PORT}/auth/google/callback`
  },
  function(accessToken, refreshToken, profile, done) {
    // Adicionamos os tokens ao perfil para retornar ao frontend
    profile.accessToken = accessToken;
    profile.refreshToken = refreshToken; 
    return done(null, profile);
  }
));

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

// -----------------------------------------------------------------------------
// MIDDLEWARE
// -----------------------------------------------------------------------------
app.use(session({
  secret: 'segredo_super_secreto_mude_isto',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// -----------------------------------------------------------------------------
// ROTAS DE AUTENTICAÇÃO (MODIFICADAS)
// -----------------------------------------------------------------------------

app.get('/auth/google',
  passport.authenticate('google', { 
    scope: SCOPES,
    accessType: 'offline',
    prompt: 'consent' 
  })
);

// ROTA DE CALLBACK ATUALIZADA
// Ao invés de redirecionar, envia o script para fechar o popup e passar dados
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/auth/failure' }),
  function(req, res) {
    // O usuário autenticado com os tokens
    const user = req.user;
    
    // HTML seguro que envia os dados para a janela pai (opener)
    const script = `
      <script>
        try {
          if (window.opener) {
            window.opener.postMessage({
              type: 'GOOGLE_AUTH_SUCCESS',
              user: ${JSON.stringify(user)}
            }, "*"); // Em produção, substitua "*" pela URL do seu frontend para segurança
          }
          window.close();
        } catch (e) {
          document.body.innerHTML = "Erro ao conectar com a janela principal.";
        }
      </script>
      <h1>Autenticado com sucesso! Fechando...</h1>
    `;
    
    res.send(script);
  }
);

app.get('/auth/failure', (req, res) => {
    res.send('<script>window.close();</script>');
});


// -----------------------------------------------------------------------------
// INICIALIZAÇÃO
// -----------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`Servidor a correr em http://localhost:${PORT}`);
});