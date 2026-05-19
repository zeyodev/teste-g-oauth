import crypto from 'crypto';

export default class CanvaAuth {
  constructor(app) {
    this.app = app;

    this.clientId = process.env.CANVA_CLIENT_ID;
    this.clientSecret = process.env.CANVA_CLIENT_SECRET;
    this.callbackUrl = `https://oauth.metaorg.app/auth/canva/callback`;
    this.redirectUri = process.env.CANVA_REDIRECT_URI || this.callbackUrl;

    // https://www.canva.dev/docs/connect/authentication/scopes/
    this.scopes = [
      'profile:read',
      'asset:read',
      'asset:write',
      'design:meta:read',
      'design:content:read',
      'design:content:write',
      'brandtemplate:meta:read',
      'brandtemplate:content:read',
    ];

    this.authorizeUrl = 'https://www.canva.com/api/oauth/authorize';
    this.tokenUrl = 'https://api.canva.com/rest/v1/oauth/token';

    this.configureRoutes();
  }

  /**
   * Gera o par PKCE (code_verifier + code_challenge S256)
   */
  generatePkce() {
    const codeVerifier = crypto.randomBytes(64).toString('base64url');
    const codeChallenge = crypto
      .createHash('sha256')
      .update(codeVerifier)
      .digest('base64url');
    return { codeVerifier, codeChallenge };
  }

  /**
   * Header Basic auth com client_id:client_secret (exigido pelo /oauth/token)
   */
  basicAuthHeader() {
    return 'Basic ' + Buffer.from(`${this.clientId}:${this.clientSecret}`).toString('base64');
  }

  /**
   * Define as rotas de autenticação Canva
   */
  configureRoutes() {
    // Início da autenticação — redireciona para o dialog do Canva com PKCE
    this.app.get('/auth/canva', (req, res) => {
      const { codeVerifier, codeChallenge } = this.generatePkce();
      const state = crypto.randomBytes(16).toString('hex');

      // Persistimos verifier + state na sessão para validar no callback
      req.session.canvaOAuth = { codeVerifier, state };

      const params = new URLSearchParams({
        response_type: 'code',
        client_id: this.clientId,
        redirect_uri: this.redirectUri,
        scope: this.scopes.join(' '),
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state,
      });

      res.redirect(`${this.authorizeUrl}?${params.toString()}`);
    });

    // Callback — troca o code pelo access_token
    this.app.get('/auth/canva/callback', async (req, res) => {
      const { code, state, error, error_description } = req.query;

      if (error) {
        return res.status(400).send(`Erro de autorização Canva: ${error_description || error}`);
      }

      const stored = req.session.canvaOAuth;
      if (!stored || !stored.codeVerifier) {
        return res.status(400).send('Sessão OAuth Canva não encontrada ou expirada.');
      }
      if (!state || state !== stored.state) {
        return res.status(403).send('State inválido — possível CSRF.');
      }
      if (!code) {
        return res.status(400).send('Código de autorização ausente.');
      }

      try {
        const body = new URLSearchParams({
          grant_type: 'authorization_code',
          code: String(code),
          code_verifier: stored.codeVerifier,
          redirect_uri: this.redirectUri,
        });

        const tokenResponse = await fetch(this.tokenUrl, {
          method: 'POST',
          headers: {
            'Authorization': this.basicAuthHeader(),
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
          },
          body: body.toString(),
        });

        const data = await tokenResponse.json();

        // Limpa a sessão antes de responder
        delete req.session.canvaOAuth;

        if (!tokenResponse.ok || data.error) {
          return res.status(400).json({
            error: 'Falha ao trocar o código pelo token.',
            details: data,
          });
        }

        const user = {
          accessToken: data.access_token,
          refreshToken: data.refresh_token,
          expiresIn: data.expires_in,
          tokenType: data.token_type,
          scope: data.scope,
        };

        const script = `
          <script>
            try {
              if (window.opener) {
                window.opener.postMessage({
                  type: 'CANVA_AUTH_SUCCESS',
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
      } catch (err) {
        res.status(500).json({ error: 'Erro interno ao comunicar com o Canva.', message: err.message });
      }
    });

    // Refresh manual de access_token via refresh_token
    this.app.post('/auth/canva/refresh', async (req, res) => {
      const { refreshToken } = req.body;
      if (!refreshToken) {
        return res.status(400).json({ error: 'refreshToken é obrigatório.' });
      }

      try {
        const body = new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
        });

        const tokenResponse = await fetch(this.tokenUrl, {
          method: 'POST',
          headers: {
            'Authorization': this.basicAuthHeader(),
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
          },
          body: body.toString(),
        });

        const data = await tokenResponse.json();

        if (!tokenResponse.ok || data.error) {
          return res.status(400).json({ error: 'Falha ao renovar o token.', details: data });
        }

        res.status(200).json({
          accessToken: data.access_token,
          refreshToken: data.refresh_token,
          expiresIn: data.expires_in,
        });
      } catch (err) {
        res.status(500).json({ error: 'Erro interno ao renovar token Canva.', message: err.message });
      }
    });
  }
}
