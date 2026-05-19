import crypto from 'crypto';
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
   * Decodifica e valida o signed_request do Meta (HMAC-SHA256)
   */
  parseSignedRequest(signedRequest) {
    const [encodedSig, payload] = signedRequest.split('.', 2);
    if (!encodedSig || !payload) return null;

    const sig = Buffer.from(encodedSig.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    const expectedSig = crypto.createHmac('sha256', this.clientSecret).update(payload).digest();

    if (!crypto.timingSafeEqual(sig, expectedSig)) return null;

    const data = JSON.parse(Buffer.from(payload.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8'));
    if (data.algorithm?.toUpperCase() !== 'HMAC-SHA256') return null;

    return data;
  }

  /**
   * Define as rotas de autenticação Meta
   */
  configureRoutes() {
    // Rota de início da autenticação — redirecionamento manual para o dialog do Meta
    this.app.get('/auth/meta', (req, res) => {
      const params = new URLSearchParams({
        auth_type: 'rerequest',
        response_type: 'code',
        redirect_uri: this.callbackUrl,
        client_id: this.clientId,
        config_id: '794947280335543',
      });

      res.redirect(`https://www.facebook.com/v23.0/dialog/oauth?${params.toString()}`);
    });

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

    // Data Deletion Callback (exigido pelo Meta)
    // https://developers.facebook.com/docs/development/create-an-app/app-dashboard/data-deletion-callback
    this.app.post('/auth/meta/data-deletion', (req, res) => {
      const signedRequest = req.body.signed_request;
      if (!signedRequest) {
        return res.status(400).json({ error: 'signed_request é obrigatório.' });
      }

      const data = this.parseSignedRequest(signedRequest);
      if (!data) {
        return res.status(403).json({ error: 'Assinatura inválida.' });
      }

      const userId = data.user_id;
      const confirmationCode = crypto.randomUUID();
      const statusUrl = `https://oauth.metaorg.app/auth/meta/deletion-status?code=${confirmationCode}`;

      // TODO: implementar exclusão real dos dados do usuário no MongoDB
      // e persistir o confirmationCode para consulta de status

      res.json({
        url: statusUrl,
        confirmation_code: confirmationCode,
      });
    });

    // Página de status da exclusão de dados
    this.app.get('/auth/meta/deletion-status', (req, res) => {
      const { code } = req.query;
      if (!code) {
        return res.status(400).send('Código de confirmação não informado.');
      }

      // TODO: consultar status real da exclusão no banco
      res.send(`
        <h1>Status da Exclusão de Dados</h1>
        <p>Código de confirmação: <strong>${code}</strong></p>
        <p>Seus dados foram marcados para exclusão.</p>
      `);
    });

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
