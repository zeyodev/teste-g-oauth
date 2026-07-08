// Pipeline do proxy (DESIGN-zkeys §6, passos 1-4): authN → authZ → resolve →
// fresh. Chain of Responsibility em middlewares Express; cada elo pendura o
// que resolveu em req.zkeys (token → userId → provider+connection) e o
// forward consome no fim da cadeia.
//
// DIP (§5): recebe store/cryptoBox/registry injetados — nada de env ou
// SQLite aqui. Token (zwt_ ou de provider) nunca aparece em log/resposta.

import { hashToken } from "../lib/crypto.js";

// Passo 4: refresh se expires_at ausente ou faltando menos que isto.
const REFRESH_SKEW_MS = 60_000;

export function createProxyPipeline({ store, cryptoBox, registry }) {
  // Single-flight por connection id: N requests simultâneos com o token
  // vencendo disparam UM refresh; os demais aguardam a mesma promise
  // (evita corrida de rotação de refresh token no provider).
  const inflight = new Map();

  function refreshConnection(connection, provider) {
    if (inflight.has(connection.id)) return inflight.get(connection.id);
    const p = (async () => {
      const refreshToken = cryptoBox.decrypt(connection.refresh_token_enc);
      if (!refreshToken) throw new Error("connection sem refresh_token — precisa re-OAuth");
      const t = await provider.refreshTokens({ refreshToken });
      store.connections.updateTokens(connection.id, {
        accessTokenEnc: cryptoBox.encrypt(t.accessToken),
        // null aqui → COALESCE do store preserva o refresh antigo (rotação
        // só sobrescreve quando o provider mandou um novo).
        refreshTokenEnc: t.refreshToken ? cryptoBox.encrypt(t.refreshToken) : null,
        expiresAt: t.expiresIn
          ? new Date(Date.now() + t.expiresIn * 1000).toISOString()
          : null,
      });
      return store.connections.findById(connection.id);
    })().finally(() => inflight.delete(connection.id));
    inflight.set(connection.id, p);
    return p;
  }

  // Passo 1 — authN: Bearer zwt_… → sha-256 → workspace_tokens ativo → user.
  // findActiveByHash já toca last_used_at.
  function authN(req, res, next) {
    const m = /^Bearer\s+(zwt_[A-Za-z0-9_-]+)$/i.exec(req.headers.authorization || "");
    const token = m ? store.workspaceTokens.findActiveByHash(hashToken(m[1])) : null;
    if (!token) {
      return res.status(401).json({ error: "workspace token ausente, inválido ou revogado" });
    }
    req.zkeys = { token, userId: token.user_id };
    next();
  }

  // Passo 2 — authZ: :provider ∈ scopes_json do token (["*"] libera todos).
  function authZ(req, res, next) {
    const providerName = req.params.provider;
    let scopes;
    try { scopes = JSON.parse(req.zkeys.token.scopes_json || "[]"); } catch { scopes = []; }
    if (!scopes.includes("*") && !scopes.includes(providerName)) {
      store.audit("proxy.deny", {
        userId: req.zkeys.userId,
        provider: providerName,
        detail: `token ${req.zkeys.token.id} (${req.zkeys.token.name}) sem escopo`,
      });
      return res.status(403).json({ error: `token sem escopo pro provider ${providerName}` });
    }
    next();
  }

  // Passo 3 — resolve: connection default do (user, provider); seleção
  // explícita por ?account=<alias> ou header X-Zkeys-Account. Provider
  // desconhecido responde igual a não-conectado (404, não vaza catálogo).
  function resolve(req, res, next) {
    const providerName = req.params.provider;
    const provider = registry.get(providerName);
    const alias = req.query.account || req.headers["x-zkeys-account"];
    const connection = !provider
      ? null
      : alias
        ? store.connections.findByAlias(req.zkeys.userId, providerName, String(alias))
        : store.connections.findDefault(req.zkeys.userId, providerName);
    if (!connection) {
      return res.status(404).json({
        error: `nenhuma conexão ${providerName}${alias ? ` com alias "${alias}"` : ""} — conecte no zkeys`,
      });
    }
    req.zkeys.provider = provider;
    req.zkeys.connection = connection;
    next();
  }

  // Passo 4 — fresh: refresha antes do forward se ausente/expirando. Falha
  // aqui não bloqueia: segue com o token atual e o retry-on-401 do forward
  // decide (ainda 401 → repassa cru, a conexão precisa re-OAuth).
  async function fresh(req, res, next) {
    const { connection, provider } = req.zkeys;
    const msLeft = connection.expires_at
      ? Date.parse(connection.expires_at) - Date.now()
      : -Infinity;
    if (msLeft < REFRESH_SKEW_MS && connection.refresh_token_enc) {
      try {
        req.zkeys.connection = await refreshConnection(connection, provider);
      } catch (e) {
        console.warn(`[zkeys/proxy] refresh ${provider.name}/${connection.id} falhou: ${e.message}`);
      }
    }
    next();
  }

  return { authN, authZ, resolve, fresh, refreshConnection };
}
