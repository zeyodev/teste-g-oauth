// Classe genérica que lê um JSON em oauth/providers/*.json e instala as rotas
// /auth/:provider/start, /auth/:provider/callback e /refresh/:provider.
//
// Decisões (DESIGN-oauth-credentials.md §2.5, §2.6):
//  - start: backend é quem gerou state JWT; este endpoint só monta o
//    authorize_url e redireciona (response 302) ou devolve JSON quando
//    chamado server-to-server.
//  - callback: troca code→tokens, busca profile, POST server-to-server pro
//    backend, fecha popup (sem postMessage).
//  - refresh: server-to-server only (x-oauth-token).
//
// PKCE: opt-in via `pkce: true`. Sessão temporária em memória mapeada por
// state (frontend só persiste state).

import crypto from "crypto";
import { backendPost } from "./backend.js";
import metaSignedRequest from "./extensions/meta_signed_request.js";

const EXTENSIONS = {
  meta_signed_request: metaSignedRequest,
};

// state → { codeVerifier, createdAt }  (TTL 10min)
const _pkceCache = new Map();
setInterval(() => {
  const cutoff = Date.now() - 10 * 60 * 1000;
  for (const [k, v] of _pkceCache.entries()) {
    if (v.createdAt < cutoff) _pkceCache.delete(k);
  }
}, 60 * 1000).unref?.();

function getByPath(obj, path) {
  if (!path) return undefined;
  return path.split(".").reduce((acc, seg) => (acc == null ? acc : acc[seg]), obj);
}

function mapProfile(raw, profile_map) {
  const out = {};
  for (const k of Object.keys(profile_map || {})) {
    const v = getByPath(raw, profile_map[k]);
    if (v !== undefined && v !== null) out[k] = v;
  }
  return out;
}

function pkcePair() {
  const codeVerifier = crypto.randomBytes(64).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  return { codeVerifier, codeChallenge };
}

export default class OAuth2Provider {
  constructor(config) {
    this.name = config.name;
    this.config = config;
    this.clientId = process.env[config.client_id_env];
    this.clientSecret = process.env[config.client_secret_env];
    this.publicBaseUrl = process.env.OAUTH_PUBLIC_BASE_URL || "https://oauth.metaorg.app";
    this.callbackUrl = `${this.publicBaseUrl}/auth/${this.name}/callback`;
  }

  install(app) {
    if (!this.clientId || !this.clientSecret) {
      console.warn(`[oauth/${this.name}] disabled: env ${this.config.client_id_env}/${this.config.client_secret_env} ausentes`);
      return;
    }
    const base = `/auth/${this.name}`;
    app.get(`${base}/start`, (req, res) => this.handleStart(req, res));
    app.get(`${base}/callback`, (req, res) => this.handleCallback(req, res));
    app.post(`/refresh/${this.name}`, (req, res) => this.handleRefresh(req, res));
    app.post(`/revoke/${this.name}`, (req, res) => this.handleRevoke(req, res));
    for (const extName of this.config.extensions || []) {
      const ext = EXTENSIONS[extName];
      if (!ext) {
        console.warn(`[oauth/${this.name}] extension desconhecida: ${extName}`);
        continue;
      }
      ext(app, this);
    }
    console.log(`[oauth/${this.name}] instalado em ${base}`);
  }

  authorizeUrl({ state, scopes, extra }) {
    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.clientId,
      redirect_uri: this.callbackUrl,
      scope: (scopes || []).join(" "),
      state,
    });
    for (const [k, v] of Object.entries(this.config.authorize_extra || {})) {
      params.set(k, v);
    }
    for (const [k, v] of Object.entries(extra || {})) {
      params.set(k, v);
    }
    if (this.config.pkce) {
      const { codeVerifier, codeChallenge } = pkcePair();
      _pkceCache.set(state, { codeVerifier, createdAt: Date.now() });
      params.set("code_challenge", codeChallenge);
      params.set("code_challenge_method", "S256");
    }
    return `${this.config.authorize_url}?${params.toString()}`;
  }

  handleStart(req, res) {
    const state = req.query.state;
    const pack = req.query.pack || Object.keys(this.config.packs)[0];
    if (!state) return res.status(400).send("state ausente — o flow deve começar no backend");
    const packCfg = this.config.packs[pack];
    if (!packCfg) return res.status(400).send(`pack desconhecido: ${pack}`);
    const url = this.authorizeUrl({ state, scopes: packCfg.scopes });
    res.redirect(url);
  }

  async exchangeCodeForTokens({ code, state }) {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.callbackUrl,
    });
    const headers = {
      "content-type": "application/x-www-form-urlencoded",
      "accept": "application/json",
    };
    if (this.config.token_auth_kind === "basic") {
      headers.authorization =
        "Basic " + Buffer.from(`${this.clientId}:${this.clientSecret}`).toString("base64");
    } else {
      body.set("client_id", this.clientId);
      body.set("client_secret", this.clientSecret);
    }
    if (this.config.pkce) {
      const pkce = _pkceCache.get(state);
      _pkceCache.delete(state);
      if (!pkce) throw new Error("PKCE verifier ausente — state inválido ou expirado");
      body.set("code_verifier", pkce.codeVerifier);
    }
    const resp = await fetch(this.config.token_url, { method: "POST", headers, body });
    const text = await resp.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { raw: text }; }
    if (!resp.ok || data.error) {
      throw new Error(`token exchange ${resp.status}: ${JSON.stringify(data).slice(0, 300)}`);
    }
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token || null,
      expiresIn: data.expires_in,
      scope: typeof data.scope === "string" ? data.scope.split(/[ ,]+/).filter(Boolean) : null,
      raw: data,
    };
  }

  async fetchProfile(accessToken) {
    if (!this.config.profile_url) return {};
    const url = new URL(this.config.profile_url);
    for (const [k, v] of Object.entries(this.config.profile_url_params || {})) {
      url.searchParams.set(k, v);
    }
    const headers = { accept: "application/json" };
    if (this.config.auth_token_in_header !== false) {
      headers.authorization = `Bearer ${accessToken}`;
    } else {
      url.searchParams.set("access_token", accessToken);
    }
    const resp = await fetch(url.toString(), { headers });
    const text = await resp.text();
    let raw;
    try { raw = JSON.parse(text); } catch { raw = {}; }
    if (!resp.ok) {
      throw new Error(`profile fetch ${resp.status}: ${text.slice(0, 200)}`);
    }
    const mapped = mapProfile(raw, this.config.profile_map);
    return { ...mapped, raw };
  }

  async handleCallback(req, res) {
    const { code, state, error, error_description } = req.query;
    if (error) {
      return res.send(this.popupHtml({ ok: false, message: error_description || error }));
    }
    if (!code || !state) {
      return res.status(400).send(this.popupHtml({ ok: false, message: "code/state ausente" }));
    }
    try {
      const tokens = await this.exchangeCodeForTokens({ code, state });
      let profile = {};
      try {
        profile = await this.fetchProfile(tokens.accessToken);
      } catch (e) {
        console.warn(`[oauth/${this.name}] profile fetch falhou:`, e.message);
      }
      let expiresAt = null;
      if (tokens.expiresIn) {
        expiresAt = new Date(Date.now() + tokens.expiresIn * 1000).toISOString();
      }
      const result = await backendPost("/api/oauth/callback", {
        provider: this.name,
        state,
        tokens: {
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          scopes: tokens.scope,
          expiresAt,
        },
        profile,
      });
      res.send(this.popupHtml({ ok: true, message: "Conectado", credentialId: result?.[0]?.id }));
    } catch (e) {
      console.error(`[oauth/${this.name}] callback erro:`, e);
      res.status(500).send(this.popupHtml({ ok: false, message: e.message }));
    }
  }

  async refreshTokens({ refreshToken }) {
    if (!refreshToken) throw new Error("refresh_token ausente");
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    });
    const headers = {
      "content-type": "application/x-www-form-urlencoded",
      "accept": "application/json",
    };
    if (this.config.token_auth_kind === "basic") {
      headers.authorization =
        "Basic " + Buffer.from(`${this.clientId}:${this.clientSecret}`).toString("base64");
    } else {
      body.set("client_id", this.clientId);
      body.set("client_secret", this.clientSecret);
    }
    const resp = await fetch(this.config.token_url, { method: "POST", headers, body });
    const text = await resp.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { raw: text }; }
    if (!resp.ok || data.error) {
      throw new Error(`refresh ${resp.status}: ${JSON.stringify(data).slice(0, 300)}`);
    }
    let expiresAt = null;
    if (data.expires_in) {
      expiresAt = new Date(Date.now() + Number(data.expires_in) * 1000).toISOString();
    }
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token || null,
      expiresAt,
      raw: data,
    };
  }

  async handleRefresh(req, res) {
    if (req.headers["x-oauth-token"] !== process.env.OAUTH_BACKEND_TOKEN) {
      return res.status(401).json({ error: "endpoint server-to-server" });
    }
    try {
      const tokens = await this.refreshTokens({ refreshToken: req.body?.refreshToken });
      res.json({
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        expiresAt: tokens.expiresAt,
      });
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  }

  async revokeTokens({ accessToken, refreshToken }) {
    if (!this.config.revoke_url) return { ok: true };
    const method = (this.config.revoke_method || "POST").toUpperCase();
    const url = new URL(this.config.revoke_url);
    const headers = { accept: "application/json" };
    let body;
    if (this.config.revoke_body_kind === "form" || method === "POST") {
      const form = new URLSearchParams({ token: accessToken || refreshToken || "" });
      for (const [k, v] of Object.entries(this.config.revoke_body_extra || {})) form.set(k, v);
      headers["content-type"] = "application/x-www-form-urlencoded";
      if (this.config.token_auth_kind === "basic") {
        headers.authorization =
          "Basic " + Buffer.from(`${this.clientId}:${this.clientSecret}`).toString("base64");
      }
      body = form;
    } else if (method === "DELETE") {
      if (accessToken) url.searchParams.set("access_token", accessToken);
    }
    const resp = await fetch(url.toString(), { method, headers, body });
    return { ok: resp.ok, status: resp.status };
  }

  async handleRevoke(req, res) {
    if (req.headers["x-oauth-token"] !== process.env.OAUTH_BACKEND_TOKEN) {
      return res.status(401).json({ error: "endpoint server-to-server" });
    }
    try {
      const out = await this.revokeTokens({
        accessToken: req.body?.accessToken,
        refreshToken: req.body?.refreshToken,
      });
      res.json(out);
    } catch (e) {
      res.status(400).json({ error: e.message });
    }
  }

  popupHtml({ ok, message, credentialId }) {
    const safeMsg = String(message || "").replace(/[<>"]/g, "");
    return `<!doctype html><html><head><meta charset="utf-8"><title>${ok ? "Conectado" : "Erro"}</title></head>
<body style="font-family: system-ui, -apple-system, Segoe UI, sans-serif; padding: 24px; max-width: 480px;">
  <h2>${ok ? "Conectado com sucesso!" : "Erro na conexão"}</h2>
  <p>${safeMsg}</p>
  <p style="color:#666;font-size:12px;">Você pode fechar esta janela${credentialId ? ` — id: ${credentialId}` : ""}.</p>
  <script>setTimeout(() => { try { window.close(); } catch(e) {} }, 1500);</script>
</body></html>`;
  }
}
