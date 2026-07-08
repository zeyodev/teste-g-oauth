// zkeys — cofre de credenciais multi-tenant + proxy de integrações.
// Ver DESIGN-zkeys.md (raiz do metaorg). F1: login + conectar + cofre.
//
// Composition root (DIP, §5): carrega config, constrói as dependências
// (store, crypto, passwords, sessions, registry de providers) e as injeta
// nas rotas. Nenhum outro módulo lê env ou abre banco.

import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { loadConfig } from "./config.js";
import { createStore } from "./lib/store.js";
import { createCrypto } from "./lib/crypto.js";
import { createPasswords } from "./lib/passwords.js";
import { createSessions } from "./lib/session.js";
import { loadProviders, HOOKS } from "./connections/registry.js";
import { createAuthRoutes } from "./auth/routes.js";
import { createConnectionRoutes } from "./connections/routes.js";

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

  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  app.get("/healthz", (_req, res) => res.json({ ok: true, providers: [...registry.keys()] }));

  app.use(createAuthRoutes({ store, passwords, sessions }));
  app.use(createConnectionRoutes({
    store, cryptoBox, registry, sessions,
    stateTtlSeconds: config.stateTtlSeconds,
  }));

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
