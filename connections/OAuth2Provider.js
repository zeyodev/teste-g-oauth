// Adapter (DESIGN-zkeys §5): endpoints heterogêneos de cada provider atrás de
// uma interface uniforme — authorizeUrl / exchangeCodeForTokens / fetchProfile /
// refreshTokens / revokeTokens. Config vem de providers/*.json (OCP: provider
// novo = JSON novo, zero mudança aqui).
//
// Sem Express nesta classe: as rotas start/callback vivem em
// connections/routes.js; hooks por-provider (ex: data-deletion do Meta) são
// instalados via installExtensions(). PKCE: o par é gerado pela rota de start
// e o verifier persiste na linha de oauth_states (fim do cache em memória).

import crypto from "crypto";

function getByPath(obj, path) {
  if (!path) return undefined;
  return path.split(".").reduce((acc, seg) => (acc == null ? acc : acc[seg]), obj);
}

function mapProfile(raw, profileMap) {
  const out = {};
  for (const k of Object.keys(profileMap || {})) {
    const v = getByPath(raw, profileMap[k]);
    if (v !== undefined && v !== null) out[k] = v;
  }
  return out;
}

export function pkcePair() {
  const codeVerifier = crypto.randomBytes(64).toString("base64url");
  const codeChallenge = crypto.createHash("sha256").update(codeVerifier).digest("base64url");
  return { codeVerifier, codeChallenge };
}

export default class OAuth2Provider {
  constructor(config, { publicBaseUrl, env = process.env }) {
    this.name = config.name;
    this.config = config;
    this.clientId = env[config.client_id_env];
    this.clientSecret = env[config.client_secret_env];
    this.publicBaseUrl = publicBaseUrl;
    this.callbackUrl = `${publicBaseUrl}/auth/${this.name}/callback`;
  }

  get enabled() {
    return Boolean(this.clientId && this.clientSecret);
  }

  get packs() {
    return this.config.packs || {};
  }

  authorizeUrl({ state, scopes, codeChallenge = null, extra = {} }) {
    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.clientId,
      redirect_uri: this.callbackUrl,
      scope: (scopes || []).join(" "),
      state,
    });
    for (const [k, v] of Object.entries(this.config.authorize_extra || {})) params.set(k, v);
    for (const [k, v] of Object.entries(extra)) params.set(k, v);
    if (codeChallenge) {
      params.set("code_challenge", codeChallenge);
      params.set("code_challenge_method", "S256");
    }
    return `${this.config.authorize_url}?${params.toString()}`;
  }

  _clientAuth(headers, body) {
    if (this.config.token_auth_kind === "basic") {
      headers.authorization =
        "Basic " + Buffer.from(`${this.clientId}:${this.clientSecret}`).toString("base64");
    } else {
      body.set("client_id", this.clientId);
      body.set("client_secret", this.clientSecret);
    }
  }

  async _tokenRequest(body, label) {
    const headers = {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
    };
    this._clientAuth(headers, body);
    const resp = await fetch(this.config.token_url, { method: "POST", headers, body });
    const text = await resp.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { raw: text }; }
    if (!resp.ok || data.error) {
      throw new Error(`${label} ${resp.status}: ${JSON.stringify(data).slice(0, 300)}`);
    }
    return data;
  }

  async exchangeCodeForTokens({ code, codeVerifier = null }) {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.callbackUrl,
    });
    if (this.config.pkce) {
      if (!codeVerifier) throw new Error("PKCE verifier ausente — state inválido ou expirado");
      body.set("code_verifier", codeVerifier);
    }
    const data = await this._tokenRequest(body, "token exchange");
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token || null,
      expiresIn: data.expires_in ? Number(data.expires_in) : null,
      scope: typeof data.scope === "string" ? data.scope.split(/[ ,]+/).filter(Boolean) : null,
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
    if (!resp.ok) throw new Error(`profile fetch ${resp.status}: ${text.slice(0, 200)}`);
    return mapProfile(raw, this.config.profile_map);
  }

  async refreshTokens({ refreshToken }) {
    if (!refreshToken) throw new Error("refresh_token ausente");
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
    });
    const data = await this._tokenRequest(body, "refresh");
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token || null, // rotação: alguns providers devolvem novo
      expiresIn: data.expires_in ? Number(data.expires_in) : null,
    };
  }

  async revokeTokens({ accessToken, refreshToken }) {
    if (!this.config.revoke_url) return { ok: true, skipped: true };
    const method = (this.config.revoke_method || "POST").toUpperCase();
    const url = new URL(this.config.revoke_url);
    const headers = { accept: "application/json" };
    let body;
    if (method === "POST") {
      const form = new URLSearchParams({ token: accessToken || refreshToken || "" });
      for (const [k, v] of Object.entries(this.config.revoke_body_extra || {})) form.set(k, v);
      headers["content-type"] = "application/x-www-form-urlencoded";
      if (this.config.token_auth_kind === "basic") {
        headers.authorization =
          "Basic " + Buffer.from(`${this.clientId}:${this.clientSecret}`).toString("base64");
      }
      body = form;
    } else if (method === "DELETE" && accessToken) {
      url.searchParams.set("access_token", accessToken);
    }
    const resp = await fetch(url.toString(), { method, headers, body });
    return { ok: resp.ok, status: resp.status };
  }

  // Hooks por-provider (Strategy, §6): rotas extras declaradas em
  // config.extensions (ex: meta_signed_request → data-deletion callback).
  installExtensions(app, hooks) {
    for (const extName of this.config.extensions || []) {
      const ext = hooks[extName];
      if (!ext) {
        console.warn(`[zkeys/${this.name}] extension desconhecida: ${extName}`);
        continue;
      }
      ext(app, this);
    }
  }
}
