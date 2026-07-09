// Config fail-fast (DESIGN-zkeys §4): único lugar que lê process.env.
// O resto do app recebe o objeto `config` injetado — nada de env espalhado.

import "dotenv/config";
import path from "path";
import { fileURLToPath } from "url";

const ROOT = path.dirname(fileURLToPath(import.meta.url));

export function loadConfig(env = process.env) {
  const missing = [];
  const need = (name) => {
    const v = env[name];
    if (!v) missing.push(name);
    return v;
  };

  const masterKeyHex = need("ZKEYS_MASTER_KEY");
  const pepper = need("ZKEYS_AUTH_PEPPER");
  const sessionSecret = need("ZKEYS_SESSION_SECRET");
  if (missing.length) {
    throw new Error(
      `[zkeys/config] env obrigatória ausente: ${missing.join(", ")} — ` +
      `gerar com \`openssl rand -hex 32\`, ver .env.example`
    );
  }

  const masterKey = /^[0-9a-fA-F]{64}$/.test(masterKeyHex)
    ? Buffer.from(masterKeyHex, "hex")
    : null;
  if (!masterKey) {
    throw new Error(
      "[zkeys/config] ZKEYS_MASTER_KEY deve ser 32 bytes em hex (64 chars) — openssl rand -hex 32"
    );
  }

  // Número positivo com fallback (rate limit / trust proxy). Ignora lixo.
  const num = (name, def) => {
    const n = Number(env[name]);
    return Number.isFinite(n) && n > 0 ? n : def;
  };

  return {
    port: Number(env.PORT || 5000),
    // redirect_uri dos providers = `${publicBaseUrl}/auth/<name>/callback`
    publicBaseUrl: (env.OAUTH_PUBLIC_BASE_URL || "https://zkeys.metaorg.app").replace(/\/$/, ""),
    dbPath: env.ZKEYS_DB_PATH || path.join(ROOT, "data", "zkeys.db"),
    providersDir: env.ZKEYS_PROVIDERS_DIR || path.join(ROOT, "providers"),
    masterKey,
    pepper,
    sessionSecret,
    sessionTtlSeconds: 12 * 3600,       // mesma política do agente (auth.py)
    stateTtlSeconds: 10 * 60,           // OAuth state single-use (§9)
    // Secure nos cookies por default; ZKEYS_INSECURE_COOKIE=1 só pra dev em http.
    secureCookies: env.ZKEYS_INSECURE_COOKIE !== "1",
    // Express trust proxy (§9): atrás do cloud-proxy/tunnel, req.ip é o proxy —
    // o IP real vem do X-Forwarded-For. Default 1 = confia UM hop (o tunnel).
    // Aceita número (n hops), "true"/"false" ou string (ex: "loopback").
    trustProxy: parseTrustProxy(env.ZKEYS_TRUST_PROXY),
    // Rate limit in-memory (§9). Login: anti-brute-force por IP e por email.
    // Proxy: anti-abuso por IP (pré-authN) e por token id (pós-authN).
    // Single-process (1 host); escala horizontal exigiria store compartilhado.
    rateLimit: {
      login: { max: num("ZKEYS_RL_LOGIN_MAX", 10), windowMs: num("ZKEYS_RL_LOGIN_WINDOW_S", 300) * 1000 },
      proxy: { max: num("ZKEYS_RL_PROXY_MAX", 600), windowMs: num("ZKEYS_RL_PROXY_WINDOW_S", 60) * 1000 },
    },
  };
}

// ZKEYS_TRUST_PROXY → valor aceito por app.set("trust proxy", …).
function parseTrustProxy(raw) {
  if (raw == null || raw === "") return 1;              // default: um hop (tunnel)
  if (raw === "true") return true;
  if (raw === "false") return false;
  if (/^\d+$/.test(raw)) return Number(raw);
  return raw;                                            // "loopback", subnet, etc.
}
