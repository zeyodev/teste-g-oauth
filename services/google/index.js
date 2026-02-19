import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import session from 'express-session';

export default class GoogleAuth {
  constructor(app) {
    this.app = app;
    
    // Configurações e Constantes
    this.port = process.env.PORT || 5000;
    this.clientId = process.env.GOOGLE_CLIENT_ID || 'COLOQUE_SEU_CLIENT_ID_AQUI';
    this.clientSecret = process.env.GOOGLE_CLIENT_SECRET || 'COLOQUE_SEU_CLIENT_SECRET_AQUI';
    this.callbackUrl = `http://localhost:${this.port}/auth/google/callback`;
    
    this.scopes = [
      'profile',
      'email',
      'https://www.googleapis.com/auth/calendar.events',
      'https://www.googleapis.com/auth/meetings.space.created'
    ];

    // Inicializa tudo na ordem correta
    this.configureSession();
    this.configurePassport();
    this.configureRoutes();
  }

  /**
   * Configura o middleware de sessão necessário para o Passport
   */
  configureSession() {
    this.app.use(session({
      secret: 'segredo_super_secreto_mude_isto',
      resave: false,
      saveUninitialized: false
    }));

    this.app.use(passport.initialize());
    this.app.use(passport.session());
  }

  /**
   * Configura a estratégia do Google e Serialização
   */
  configurePassport() {
    passport.use(new GoogleStrategy({
        clientID: this.clientId,
        clientSecret: this.clientSecret,
        callbackURL: this.callbackUrl
      },
      (accessToken, refreshToken, profile, done) => {
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
  }

  /**
   * Define as rotas de autenticação
   */
  configureRoutes() {
    // Rota de início da autenticação
    this.app.get('/auth/google',
      passport.authenticate('google', { 
        scope: this.scopes,
        accessType: 'offline',
        prompt: 'consent' 
      })
    );

    // Rota de Callback
    this.app.get('/auth/google/callback', 
      passport.authenticate('google', { failureRedirect: '/auth/failure' }),
      (req, res) => {
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

    // Rota de falha
    this.app.get('/auth/failure', (req, res) => {
        res.send('<script>window.close();</script>');
    });
  }
}