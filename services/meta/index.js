import passport from 'passport';
import { Strategy as FacebookStrategy } from 'passport-facebook';

export default class MetaAuth {
  constructor(app) {
    this.app = app;

    this.clientId = process.env.META_APP_ID;
    this.clientSecret = process.env.META_APP_SECRET;
    this.callbackUrl = `https://oauth.metaorg.app/auth/meta/callback`;
    this.redirectUri = process.env.META_REDIRECT_URI || this.callbackUrl;

    this.scopes = ['ads_read', 'read_insights', 'business_management'];

    this.configurePassport();
    this.configureRoutes();
  }

  /**
   * Configura a estratégia do Facebook/Meta
   */
  configurePassport() {
    passport.use(new FacebookStrategy({
        clientID: this.clientId,
        clientSecret: this.clientSecret,
        callbackURL: this.callbackUrl,
        profileFields: ['id', 'displayName', 'email']
      },
      (accessToken, refreshToken, profile, done) => {
        profile.accessToken = accessToken;
        profile.refreshToken = refreshToken;
        return done(null, profile);
      }
    ));
  }

  /**
   * Define as rotas de autenticação Meta
   */
  configureRoutes() {
    // Rota de início da autenticação
    // TODO: aqui não tem que usar scopes mas sim config_id
    this.app.get('/auth/meta',
      passport.authenticate('facebook', {
        config_id: 794947280335543,
        authType: 'rerequest'
      })
    );

    // Rota de Callback
    this.app.get('/auth/meta/callback',
      passport.authenticate('facebook', { failureRedirect: '/auth/failure' }),
      (req, res) => {
        const user = req.user;

        const script = `
          <script>
            try {
              if (window.opener) {
                window.opener.postMessage({
                  type: 'META_AUTH_SUCCESS',
                  user: ${JSON.stringify(user)}
                }, "*");
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

    // Endpoint de troca manual de code por access_token
    this.app.post('/exchange-token', async (req, res) => {
      const { code } = req.body;

      if (!code) {
        return res.status(400).json({ error: 'O código de autorização (code) é obrigatório.' });
      }

      const url = `https://graph.facebook.com/v23.0/oauth/access_token?client_id=${this.clientId}&client_secret=${this.clientSecret}&redirect_uri=${encodeURIComponent(this.redirectUri)}&code=${code}`;

      try {
        const fbResponse = await fetch(url, {
          method: 'GET',
          headers: { 'Accept': 'application/json' },
        });

        const data = await fbResponse.json();

        if (data.error) {
          return res.status(400).json({ error: 'Falha ao trocar o código pelo token.', details: data.error });
        }

        res.status(200).json({ accessToken: data.access_token });
      } catch (error) {
        res.status(500).json({ error: 'Erro interno ao comunicar com o Facebook.' });
      }
    });
  }
}
