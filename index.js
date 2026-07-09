// zkeys — cofre de credenciais multi-tenant + proxy de integrações.
// Ver DESIGN-zkeys.md (raiz do metaorg). F1: login + conectar + cofre.
// F2: proxy transparente /p/:provider/* + emissão mínima de zwt_.
// F3: ciclo de zwt_ + appsecret_proof do Meta. F4: rate limit + auditoria
// exposta + CSRF + envelope encryption (hardening §8/§9).
//
// Composition root (DIP, §5): carrega config, constrói as dependências
// (store, crypto, passwords, sessions, rate limit, csrf, registry) e as injeta
// nas rotas. Nenhum outro módulo lê env ou abre banco.

import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { loadConfig } from "./config.js";
import { createStore } from "./lib/store.js";
import { createCrypto } from "./lib/crypto.js";
import { createPasswords } from "./lib/passwords.js";
import { createSessions } from "./lib/session.js";
import { createRateLimiter } from "./lib/ratelimit.js";
import { createCsrf } from "./lib/csrf.js";
import { loadProviders, HOOKS } from "./connections/registry.js";
import { createAuthRoutes } from "./auth/routes.js";
import { createWorkspaceTokenRoutes } from "./auth/tokens.js";
import { createConnectionRoutes } from "./connections/routes.js";
import { createAuditRoutes } from "./auth/audit.js";
import { createProxyRouter } from "./proxy/router.js";

const ROOT = path.dirname(fileURLToPath(import.meta.url));

export function createApp(config) {
  const store = createStore(config.dbPath);
  const cryptoBox = createCrypto(config.masterKey);
  const passwords = createPasswords(config.pepper);
  const sessions = createSessions({
    secret: config.sessionSecret,
    ttlSeconds: config.sessionTtlSeconds,
    secure: config.secureCookies,
  });
  const registry = loadProviders({
    providersDir: config.providersDir,
    publicBaseUrl: config.publicBaseUrl,
  });
  // Rate limit (§9): um limiter por política (login, proxy); as chaves são
  // namespaced (ip:/email:/tok:). CSRF (§9): double-submit pras rotas web.
  const loginLimiter = createRateLimiter(config.rateLimit.login);
  const proxyLimiter = createRateLimiter(config.rateLimit.proxy);
  const csrf = createCsrf({ secure: config.secureCookies });

  const app = express();
  // req.ip vem do X-Forwarded-For atrás do cloud-proxy/tunnel (§9). Default 1
  // hop; ajuste via ZKEYS_TRUST_PROXY se a cadeia for mais profunda.
  app.set("trust proxy", config.trustProxy);
  // Proxy ANTES dos body parsers (§6): /p/* repassa o body CRU pro upstream;
  // express.json() consumiria o stream e quebraria o forward. Rate limit por
  // IP/token vive DENTRO do router, respeitando essa ordem.
  app.use(createProxyRouter({ store, cryptoBox, registry, rateLimit: proxyLimiter }));
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  // Emite o cookie CSRF em GETs (rotas web); o proxy /p/* já retornou acima.
  app.use(csrf.issue);

  app.get("/healthz", (_req, res) => res.json({ ok: true, providers: [...registry.keys()] }));
  app.get("/auth/csrf", sessions.requireSession, csrf.token);

  app.use(createAuthRoutes({ store, passwords, sessions, rateLimit: loginLimiter, csrf }));
  app.use(createWorkspaceTokenRoutes({ store, sessions, csrf }));
  app.use(createConnectionRoutes({
    store, cryptoBox, registry, sessions, csrf,
    stateTtlSeconds: config.stateTtlSeconds,
  }));
  app.use(createAuditRoutes({ store, sessions }));

  // Hooks por-provider que instalam rotas próprias (ex: data-deletion do Meta).
  for (const provider of registry.values()) provider.installExtensions(app, HOOKS);

  // UI mínima (F1). F4 evolui.
  app.use("/", express.static(path.join(ROOT, "web")));

  return { app, store, registry };
}

// Boot direto (testes importam createApp e sobem com config próprio).
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const config = loadConfig();
  const { app, registry } = createApp(config);
  app.listen(config.port, () => {
    console.log(
      `[zkeys] http://localhost:${config.port} — providers: ${[...registry.keys()].join(", ") || "(nenhum habilitado)"}`
    );
  });
}
