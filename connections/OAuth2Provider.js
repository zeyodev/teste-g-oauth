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
    // Verify token do webhook (inbound). Mesmo padrão *_env do id/secret: fica
    // fora do repo, lido só aqui via env injetado. Usado pelo hook de webhook
    // no handshake GET (hub.verify_token). Opcional — provider sem webhook não
    // declara a env e isto fica null.
    this.webhookVerifyToken = config.webhook_verify_token_env
      ? env[config.webhook_verify_token_env] || null
      : null;
    this.publicBaseUrl = publicBaseUrl;
    this.callbackUrl = `${publicBaseUrl}/auth/${this.name}/callback`;
    // Params extras do authorize: `authorize_extra` são estáticos no JSON;
    // `authorize_extra_env` mapeia param→NOME_DA_ENV (mesmo padrão *_env do
    // client id/secret — mantém id/segredo fora do repo). Env ausente = param
    // omitido (ex: Meta sem config_id cai no login clássico por scope).
    this.authorizeExtra = { ...(config.authorize_extra || {}) };
    for (const [param, envName] of Object.entries(config.authorize_extra_env || {})) {
      const v = env[envName];
      if (v) this.authorizeExtra[param] = v;
    }
  }

  get enabled() {
    return Boolean(this.clientId && this.clientSecret);
  }

  get packs() {
    return this.config.packs || {};
  }

  // Pack-aware discovery config: pack-level account_discovery cai de volta
  // pro provider-level (ex: whatsapp.json declara account_discovery no
  // provider, não no pack). Retorna null se nenhum configurar descoberta.
  _discoveryConfig(packId) {
    return this.config.packs?.[packId]?.account_discovery
      ?? this.config.account_discovery ?? null;
  }

  // Fetch + parse JSON, throw com label legível em caso de erro.
  async _graphGet(url, label) {
    const resp = await fetch(url.toString(), { headers: { accept: "application/json" } });
    const text = await resp.text();
    let data;
    try { data = JSON.parse(text); } catch { data = {}; }
    if (!resp.ok) throw new Error(`${label} ${resp.status}: ${text.slice(0, 200)}`);
    return data;
  }

  authorizeUrl({ state, scopes, codeChallenge = null, extra = {} }) {
    const params = new URLSearchParams({
      response_type: "code",
      client_id: this.clientId,
      redirect_uri: this.callbackUrl,
      state,
    });
    // Embedded Signup (WhatsApp/Meta/Instagram): config_id dirige as permissões
    // e substitui `scope` — se há config_id nos extras (estático ou do pack),
    // NÃO mandamos scope (evita conflito e URL mais limpa).
    // Separador de scopes configurável: dialog do Instagram usa vírgula
    // (scope_separator no provider json); o resto usa espaço (padrão OAuth).
    const scope = (scopes || []).join(this.config.scope_separator || " ");
    const hasConfigId = "config_id" in this.authorizeExtra ||
                        "config_id" in extra;
    if (scope && !hasConfigId) params.set("scope", scope);
    for (const [k, v] of Object.entries(this.authorizeExtra)) params.set(k, v);
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
    let accessToken = data.access_token;
    let refreshToken = data.refresh_token || null;
    let expiresIn = data.expires_in ? Number(data.expires_in) : null;
    // Instagram-login: o code exchange devolve um token short-lived (~1h) sem
    // refresh_token nem expires_in. `long_lived_exchange` troca por um token de
    // ~60 dias em graph.instagram.com (GET com client_secret + o token curto).
    if (this.config.long_lived_exchange) {
      const ll = await this._longLivedExchange(accessToken);
      accessToken = ll.accessToken;
      expiresIn = ll.expiresIn;
    }
    // `self_refresh`: providers sem refresh_token dedicado (Instagram) renovam o
    // PRÓPRIO access token. Persistimos o long-lived também como refresh_token
    // (a semente do refresh) pra o fresh() do proxy disparar perto do vencimento.
    if (this.config.self_refresh && !refreshToken) refreshToken = accessToken;
    return {
      accessToken,
      refreshToken,
      expiresIn,
      scope: typeof data.scope === "string" ? data.scope.split(/[ ,]+/).filter(Boolean) : null,
    };
  }

  // Troca short-lived → long-lived. Ex: Instagram clássico usa GET
  // graph.instagram.com/access_token?grant_type=ig_exchange_token&client_secret=…
  // &access_token=curto; Facebook usa fb_exchange_token como token_param +
  // send_client_id: true (exige client_id). Config do provider define token_param
  // (default "access_token") e send_client_id (default false).
  async _longLivedExchange(shortToken) {
    const cfg = this.config.long_lived_exchange;
    const url = new URL(cfg.url);
    url.searchParams.set("grant_type", cfg.grant_type);
    if (cfg.send_client_id) url.searchParams.set("client_id", this.clientId);
    url.searchParams.set("client_secret", this.clientSecret);
    const tokenParam = cfg.token_param || "access_token";
    url.searchParams.set(tokenParam, shortToken);
    const resp = await fetch(url.toString(), { headers: { accept: "application/json" } });
    const text = await resp.text();
    let data; try { data = JSON.parse(text); } catch { data = {}; }
    if (!resp.ok || !data.access_token) {
      throw new Error(`long-lived exchange ${resp.status}: ${text.slice(0, 200)}`);
    }
    return { accessToken: data.access_token, expiresIn: data.expires_in ? Number(data.expires_in) : null };
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

  // Descoberta de conta pós-token (WhatsApp Embedded Signup / coexistence). O
  // token de ES é business-scoped e /me NÃO identifica o número; e como o zkeys
  // é redirect puro (sem o FB JS SDK capturando o evento WA_EMBEDDED_SIGNUP),
  // descobrimos por Graph: debug_token → waba_id (granular scope) →
  // /{waba_id}/phone_numbers → phone_number_id. Gated por `account_discovery`
  // no JSON (OCP: só o WhatsApp declara; providers sem isso não descobrem).
  // Best-effort: o caller trata como opcional — falha aqui não derruba o connect.
  async discoverAccount(accessToken) {
    const cfg = this.config.account_discovery;
    if (!cfg) return null;
    const wabaId = await this._discoverWabaId(accessToken, cfg.scope);
    if (!wabaId) return null;
    const number = await this._discoverPhoneNumber(accessToken, wabaId);
    return {
      externalId: wabaId,
      name: number?.verified_name || number?.display_phone_number || wabaId,
      metadata: { waba_id: wabaId, ...(number || {}) },
    };
  }

  // App access token (`APP_ID|APP_SECRET`) — usado no debug_token, que inspeciona
  // um token de USUÁRIO a partir das credenciais do app (não do próprio token).
  _appAccessToken() {
    return `${this.clientId}|${this.clientSecret}`;
  }

  _appsecretProof(accessToken) {
    return crypto.createHmac("sha256", this.clientSecret).update(String(accessToken)).digest("hex");
  }

  // debug_token: inspeciona um token (usuário/página) com as credenciais do
  // app. Retorna data.data (campos: app_id, type, expires_at, granular_scopes,
  // etc.). appsecret_proof quando sign exige (Meta family).
  async _debugToken(inputToken) {
    const url = new URL(`${this.config.api_base_url}/debug_token`);
    url.searchParams.set("input_token", inputToken);
    url.searchParams.set("access_token", this._appAccessToken());
    if (this.config.sign === "appsecret_proof") {
      url.searchParams.set("appsecret_proof", this._appsecretProof(inputToken));
    }
    const data = await this._graphGet(url, "debug_token");
    return data?.data ?? null;
  }

  // debug_token → granular_scopes[].target_ids: os IDs de WABA que o token
  // enxerga sob o scope de management. Pega o primeiro do scope pedido (fallback:
  // primeiro scope que traga target_ids).
  async _discoverWabaId(accessToken, scopeName) {
    const dd = await this._debugToken(accessToken);
    const gs = dd?.granular_scopes || [];
    const match =
      gs.find((g) => g.scope === scopeName && g.target_ids?.length) ||
      gs.find((g) => Array.isArray(g.target_ids) && g.target_ids.length);
    return match?.target_ids?.[0] || null;
  }

  // GET /{waba_id}/phone_numbers → o número de origem (phone_number_id) que a
  // org usa pra enviar. appsecret_proof quando o provider exige (sign=…proof).
  async _discoverPhoneNumber(accessToken, wabaId) {
    const url = new URL(`${this.config.api_base_url}/${wabaId}/phone_numbers`);
    url.searchParams.set("access_token", accessToken);
    url.searchParams.set("fields", "id,display_phone_number,verified_name");
    if (this.config.sign === "appsecret_proof") {
      url.searchParams.set("appsecret_proof", this._appsecretProof(accessToken));
    }
    const data = await this._graphGet(url, "phone_numbers");
    const n = Array.isArray(data?.data) ? data.data[0] : null;
    if (!n) return null;
    return {
      phone_number_id: n.id,
      display_phone_number: n.display_phone_number || null,
      verified_name: n.verified_name || null,
    };
  }

  async refreshTokens({ refreshToken, connection = null }) {
    if (!refreshToken) throw new Error("refresh_token ausente");
    // Page Access Token: re-busca com o User Token (refresh_token_enc).
    // O User Token long-lived é usado pra obter um Page Token fresco do
    // endpoint /{page_id}?fields=access_token. O refreshToken aqui É o
    // User Token (armazenado como refresh_token_enc na conexão de página).
    if (this.config.page_token_refresh && connection) {
      let meta;
      try { meta = connection.metadata_json ? JSON.parse(connection.metadata_json) : {}; } catch { meta = {}; }
      if (meta.page_id) {
        const fresh = await this._refreshPageToken(refreshToken, meta.page_id);
        // Tenta descobrir o expires_at real via debug_token; fallback ~60d
        let expiresIn = 60 * 24 * 3600;
        try {
          const diag = await this._debugToken(fresh);
          if (diag?.expires_at) {
            expiresIn = Math.max(60, diag.expires_at - Math.floor(Date.now() / 1000));
          }
        } catch { /* debug_token é best-effort */ }
        // refreshToken: null → COALESCE do store preserva o User Token
        return { accessToken: fresh, refreshToken: null, expiresIn };
      }
    }
    // self_refresh: provider sem refresh_token dedicado renova o próprio
    // access token (ex: Instagram clássico usa ig_refresh_token; Facebook usa
    // fb_exchange_token com o long-lived como token). Config define token_param
    // (default "access_token") e send_client_id (default false).
    if (this.config.self_refresh) {
      const cfg = this.config.self_refresh;
      const url = new URL(cfg.url);
      url.searchParams.set("grant_type", cfg.grant_type);
      if (cfg.send_client_id) url.searchParams.set("client_id", this.clientId);
      url.searchParams.set("client_secret", this.clientSecret);
      const tokenParam = cfg.token_param || "access_token";
      url.searchParams.set(tokenParam, refreshToken);
      const resp = await fetch(url.toString(), { headers: { accept: "application/json" } });
      const text = await resp.text();
      let data; try { data = JSON.parse(text); } catch { data = {}; }
      if (!resp.ok || !data.access_token) {
        throw new Error(`self-refresh ${resp.status}: ${text.slice(0, 200)}`);
      }
      return {
        accessToken: data.access_token,
        refreshToken: data.access_token,
        expiresIn: data.expires_in ? Number(data.expires_in) : null,
      };
    }
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

  async revokeTokens({ accessToken, refreshToken, connection = null }) {
    // Page connection: não há endpoint pra revogar só o token da página;
    // DELETE /me/permissions com o User Token (refresh) derrubaria TODAS as
    // conexões de página da mesma OAuth. Soft-delete: remove a linha, o token
    // da página expira sozinho em ~60d.
    let meta;
    try { meta = connection?.metadata_json ? JSON.parse(connection.metadata_json) : {}; } catch { meta = {}; }
    if (meta.page_id) return { ok: true, skipped: true, reason: "page-token — soft-delete" };
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

  // Plural: pack-aware, retorna array (ou null p/ cair no fallback single).
  // O callback itera sobre o array e cria uma conexão por item.
  async discoverAccounts(accessToken, packId) {
    const cfg = this._discoveryConfig(packId);
    if (!cfg) return null;                          // provider/pack sem descoberta
    if (cfg.kind === "instagram") return this._discoverInstagramPages(accessToken);
    if (cfg.kind === "unified_instagram") return this._discoverUnifiedInstagramAccounts(accessToken);
    // WhatsApp e futuros: fallback singular (compatibilidade)
    const one = await this.discoverAccount(accessToken);
    return one ? [one] : null;
  }

  // Unified Login (docs Meta: get-started#instagram-account-ids): o token é um
  // SUAT do business portfolio — /me NÃO retorna a conta IG. Descoberta:
  //   GET /me?fields=client_business_id  → business id do cliente (metadado)
  //   GET /me/assigned_instagram_accounts?fields=id,username → contas IG
  // Todas as conexões compartilham o MESMO SUAT (cobre os assets compartilhados).
  async _discoverUnifiedInstagramAccounts(accessToken) {
    const meUrl = new URL(`${this.config.api_base_url}/me`);
    meUrl.searchParams.set("fields", "client_business_id");
    meUrl.searchParams.set("access_token", accessToken);
    if (this.config.sign === "appsecret_proof") {
      meUrl.searchParams.set("appsecret_proof", this._appsecretProof(accessToken));
    }
    let businessId = null;
    try {
      const me = await this._graphGet(meUrl, "me(client_business_id)");
      businessId = me?.client_business_id || null;
    } catch (e) {
      console.warn(`[zkeys/${this.name}] client_business_id indisponível:`, e.message);
    }

    const url = new URL(`${this.config.api_base_url}/me/assigned_instagram_accounts`);
    url.searchParams.set("fields", "id,username");
    url.searchParams.set("access_token", accessToken);
    if (this.config.sign === "appsecret_proof") {
      url.searchParams.set("appsecret_proof", this._appsecretProof(accessToken));
    }
    const data = await this._graphGet(url, "assigned_instagram_accounts");
    const out = [];
    for (const acct of (data?.data || [])) {
      if (!acct?.id) continue;
      out.push({
        externalId: String(acct.id),          // Instagram professional account ID = entry.id do webhook
        name: acct.username || null,
        metadata: {
          client_business_id: businessId,
          ig_username: acct.username || null,
          login: "unified",
        },
        accessToken,                          // SUAT cobre todos os assets compartilhados
        expiresIn: null,                      // vencimento depende da Configuration; gestão via BISU Token API
      });
    }
    return out;
  }

  // GET /me/accounts → filtra páginas com instagram_business_account → troca
  // cada Page Token por long-lived → retorna array (vazio = sem páginas IG).
  async _discoverInstagramPages(userToken) {
    const url = new URL(`${this.config.api_base_url}/me/accounts`);
    url.searchParams.set("access_token", userToken);
    url.searchParams.set("fields", "id,name,category,access_token,instagram_business_account{id,username,name}");
    if (this.config.sign === "appsecret_proof") {
      url.searchParams.set("appsecret_proof", this._appsecretProof(userToken));
    }
    const data = await this._graphGet(url, "me/accounts");
    const out = [];
    for (const page of (data?.data || [])) {
      const ig = page.instagram_business_account;
      if (!ig?.id || !page.access_token) continue;      // página sem IG business → pula
      try {
        const ll = await this._longLivedExchange(page.access_token); // fb_exchange_token
        out.push({
          externalId: ig.id,                            // ig_business_account_id = account_key
          name: page.name,
          metadata: {
            page_id: page.id,
            page_name: page.name,
            page_category: page.category || null,
            ig_business_account_id: ig.id,
            ig_username: ig.username || null,
          },
          accessToken: ll.accessToken,                  // Page Token long-lived
          expiresIn: ll.expiresIn,
        });
      } catch (e) {
        console.warn(`[zkeys/${this.name}] página ${page.id} sem long-lived exchange:`, e.message);
      }
    }
    return out;
  }

  // GET /{page_id}?fields=access_token usando o User Token (refresh_token_enc)
  // → devolve um Page Token fresco (long-lived ~60d, padrão Meta documentado).
  async _refreshPageToken(userToken, pageId) {
    const url = new URL(`${this.config.api_base_url}/${encodeURIComponent(pageId)}`);
    const fields = this.config.page_token_refresh?.fields || "access_token";
    url.searchParams.set("fields", fields);
    url.searchParams.set("access_token", userToken);
    if (this.config.sign === "appsecret_proof") {
      url.searchParams.set("appsecret_proof", this._appsecretProof(userToken));
    }
    const data = await this._graphGet(url, `page ${pageId} access_token`);
    if (!data.access_token) {
      throw new Error(`page ${pageId} não retornou access_token`);
    }
    return data.access_token;
  }

  // Hooks por-provider (Strategy, §6): rotas extras declaradas em
  // config.extensions (ex: meta_signed_request → data-deletion callback).
  installExtensions(app, hooks, ctx = {}) {
    for (const extName of this.config.extensions || []) {
      const ext = hooks[extName];
      if (!ext) {
        console.warn(`[zkeys/${this.name}] extension desconhecida: ${extName}`);
        continue;
      }
      ext(app, this, ctx);
    }
  }
}
