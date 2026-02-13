const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { google } = require('googleapis'); // Importar a biblioteca Google
require('dotenv').config();

const app = express();

// -----------------------------------------------------------------------------
// CONFIGURAÇÃO
// -----------------------------------------------------------------------------
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'COLOQUE_SEU_CLIENT_ID_AQUI';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || 'COLOQUE_SEU_CLIENT_SECRET_AQUI';
const PORT = process.env.PORT || 3000;

// Scopes: Permissões que vamos pedir ao utilizador
const SCOPES = [
  'profile',
  'email',
  'https://www.googleapis.com/auth/calendar.events',       // Ler e escrever no calendário
  'https://www.googleapis.com/auth/meetings.space.created' // Criar reuniões no Meet
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
    // IMPORTANTE: Guardamos o accessToken no perfil do utilizador
    // para podermos usar as APIs da Google mais tarde.
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

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/');
}

// Helper: Cria um cliente autenticado para o utilizador atual
function getAuthClient(user) {
  const oAuth2Client = new google.auth.OAuth2(
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    `http://localhost:${PORT}/auth/google/callback`
  );
  oAuth2Client.setCredentials({
    access_token: user.accessToken,
    refresh_token: user.refreshToken
  });
  return oAuth2Client;
}

// -----------------------------------------------------------------------------
// ROTAS E VISTAS
// -----------------------------------------------------------------------------

app.get('/', (req, res) => {
  const user = req.user;
  res.send(`
    <!DOCTYPE html>
    <html lang="pt">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Google Calendar & Meet API Demo</title>
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; background-color: #f0f2f5; margin: 0; }
        .card { background: white; padding: 2rem; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); text-align: center; max-width: 500px; width: 100%; }
        .btn { display: inline-block; padding: 10px 20px; background-color: #4285F4; color: white; text-decoration: none; border-radius: 5px; font-weight: bold; margin: 5px; transition: background 0.2s; border: none; cursor: pointer;}
        .btn:hover { background-color: #357ae8; }
        .btn-green { background-color: #34A853; }
        .btn-green:hover { background-color: #2d8f47; }
        .btn-logout { background-color: #db4437; }
        .btn-logout:hover { background-color: #c53929; }
        h1 { color: #333; margin-top: 0; }
        ul { text-align: left; background: #fafafa; padding: 1rem 2rem; border-radius: 8px; list-style: none; }
        li { margin-bottom: 0.5rem; border-bottom: 1px solid #eee; padding-bottom: 0.5rem; }
        a { color: #4285F4; text-decoration: none; }
      </style>
    </head>
    <body>
      <div class="card">
        ${user 
          ? `
            <img src="${user.photos[0].value}" alt="Foto" style="border-radius: 50%; width: 60px; height: 60px;">
            <h2>Olá, ${user.displayName}</h2>
            
            <div style="margin: 20px 0;">
              <a href="/calendar" class="btn">📅 Ver Próximos Eventos</a>
              <a href="/create-meet" class="btn btn-green">📹 Criar Nova Reunião Meet</a>
            </div>

            <a href="/logout" class="btn btn-logout">Sair</a>
          ` 
          : `
            <h1>Google Workspace Demo</h1>
            <p>Faça login para gerir Calendário e Reuniões.</p>
            <a href="/auth/google" class="btn">Entrar com Google</a>
          `
        }
      </div>
    </body>
    </html>
  `);
});

// -----------------------------------------------------------------------------
// ROTAS DE API (CALENDAR, MEET, WORKSPACE EVENTS)
// -----------------------------------------------------------------------------

// 1. Google Calendar API: Listar Eventos
app.get('/calendar', ensureAuthenticated, async (req, res) => {
  try {
    const auth = getAuthClient(req.user);
    const calendar = google.calendar({ version: 'v3', auth });
    
    const response = await calendar.events.list({
      calendarId: 'primary',
      timeMin: (new Date()).toISOString(),
      maxResults: 10,
      singleEvents: true,
      orderBy: 'startTime',
    });
    
    const events = response.data.items;
    let html = `<h1>Próximos 10 Eventos</h1><a href="/">Voltar</a><ul>`;
    
    if (events.length) {
      events.map((event, i) => {
        const start = event.start.dateTime || event.start.date;
        html += `<li><b>${start}</b> - ${event.summary} ${event.htmlLink ? `<a href="${event.htmlLink}" target="_blank">Abrir</a>` : ''}</li>`;
      });
    } else {
      html += '<p>Nenhum evento encontrado.</p>';
    }
    html += '</ul>';
    res.send(html);

  } catch (error) {
    console.error('Erro no Calendário:', error);
    res.status(500).send('Erro ao procurar eventos.');
  }
});

// 2. Google Meet API: Criar um Espaço de Reunião
app.get('/create-meet', ensureAuthenticated, async (req, res) => {
  try {
    const auth = getAuthClient(req.user);
    // Nota: O uso da API 'meet' v2 requer o scope meetings.space.created
    const meet = google.meet({ version: 'v2', auth });

    const response = await meet.spaces.create({
      requestBody: {
        // config: { accessType: 'OPEN' } // Opcional
      }
    });

    res.send(`
      <h1>Reunião Criada!</h1>
      <p>Link da reunião: <a href="${response.data.meetingUri}" target="_blank">${response.data.meetingUri}</a></p>
      <p>ID do espaço: ${response.data.name}</p>
      <br>
      <a href="/">Voltar</a>
    `);

  } catch (error) {
    console.error('Erro ao criar Meet:', error);
    res.send(`Erro ao criar reunião: ${error.message} <br> <a href="/">Voltar</a>`);
  }
});

// 3. Google Workspace Events API (Setup)
// Esta API é usada para subscrever a mudanças (webhooks).
// Exige um domínio público (não localhost) para funcionar plenamente.
app.get('/workspace-events-info', ensureAuthenticated, async (req, res) => {
    // Apenas instanciamos o cliente para demonstrar a implementação
    const auth = getAuthClient(req.user);
    const workspaceEvents = google.workspaceevents({ version: 'v1', auth });
    
    res.send(`
      <h1>Workspace Events API</h1>
      <p>O cliente da API foi inicializado com sucesso.</p>
      <p>Para criar subscrições reais, este servidor precisaria de estar num domínio HTTPS público para receber webhooks.</p>
      <a href="/">Voltar</a>
    `);
});


// -----------------------------------------------------------------------------
// ROTAS DE AUTENTICAÇÃO
// -----------------------------------------------------------------------------

app.get('/auth/google',
  passport.authenticate('google', { 
    scope: SCOPES,
    accessType: 'offline', // Importante para obter refresh_token se necessário
    prompt: 'consent'      // Força o ecrã de consentimento para garantir refresh_token
  })
);

app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/' }),
  function(req, res) {
    res.redirect('/');
  }
);

app.get('/logout', (req, res, next) => {
  req.logout((err) => {
    if (err) { return next(err); }
    res.redirect('/');
  });
});

app.listen(PORT, () => {
  console.log(`Servidor a correr em http://localhost:${PORT}`);
});