// E2E da F2 (proxy transparente) contra mocks locais, sem rede externa:
// emissão de zwt_ → forward com Bearer real injetado (nunca o zwt_) →
// auth_injection query → 403 escopo → 404 não-conectado → refresh-on-401 →
// fresh-by-expiry → revogação → body POST íntegro. Roda com `npm test`.
//
// Dois servidores mock: um faz papel de provider OAuth (token/profile) e
// outro de API upstream (grava tudo que recebe e ecoa/simula falhas).

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";

// ── env de teste ANTES de importar config ────────────────────────────────
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zkeys-proxy-e2e-"));
process.env.ZKEYS_MASTER_KEY = crypto.randomBytes(32).toString("hex");
process.env.ZKEYS_AUTH_PEPPER = "pepper-de-teste";
process.env.ZKEYS_SESSION_SECRET = "session-secret-de-teste";
process.env.ZKEYS_INSECURE_COOKIE = "1";
process.env.ZKEYS_DB_PATH = path.join(tmp, "zkeys.db");
process.env.ZKEYS_PROVIDERS_DIR = path.join(tmp, "providers");
process.env.MOCK_CLIENT_ID = "mock-client-id";
process.env.MOCK_CLIENT_SECRET = "mock-client-secret";

const { loadConfig } = await import("../config.js");
const { createApp } = await import("../index.js");
const { createPasswords } = await import("../lib/passwords.js");
const { createCrypto } = await import("../lib/crypto.js");

// ── provider OAuth mock (token exchange + refresh com rotação) ───────────
let codeExchanges = 0;
let refreshes = 0;
const oauth = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  if (req.method === "POST" && url.pathname === "/token") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const form = new URLSearchParams(body);
      res.setHeader("content-type", "application/json");
      if (form.get("grant_type") === "refresh_token") {
        refreshes++;
        res.end(JSON.stringify({
          access_token: `at-refresh-${refreshes}`,
          refresh_token: `rt-refresh-${refreshes}`, // rotação: manda um novo
          expires_in: 3600,
        }));
      } else {
        codeExchanges++;
        res.end(JSON.stringify({
          access_token: `at-code-${codeExchanges}`,
          refresh_token: `rt-code-${codeExchanges}`,
          expires_in: 3600, scope: "email perfil",
        }));
      }
    });
    return;
  }
  if (req.method === "GET" && url.pathname === "/profile") {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ sub: `conta-${codeExchanges}`, email: "pessoa@example.com" }));
    return;
  }
  res.statusCode = 404;
  res.end();
});
await new Promise((r) => oauth.listen(0, r));
const oauthBase = `http://localhost:${oauth.address().port}`;

// ── API upstream mock (grava requests; ecoa; simula 401 sob demanda) ─────
const upstreamSeen = [];
let failNextWith401 = false;
const upstream = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const rec = {
      method: req.method, url: req.url,
      headers: { ...req.headers }, body: Buffer.concat(chunks).toString("utf8"),
    };
    upstreamSeen.push(rec);
    if (failNextWith401) {
      failNextWith401 = false;
      res.statusCode = 401;
      res.setHeader("content-type", "application/json");
      return res.end(JSON.stringify({ error: "token expirado" }));
    }
    const url = new URL(req.url, "http://x");
    if (url.pathname === "/echo") {
      res.setHeader("content-type", req.headers["content-type"] || "application/octet-stream");
      return res.end(rec.body);
    }
    if (url.pathname === "/teapot") {
      res.statusCode = 418;
      return res.end("chá");
    }
    res.setHeader("content-type", "application/json");
    res.setHeader("x-upstream", "sim");
    res.end(JSON.stringify({ ok: true, path: req.url }));
  });
});
await new Promise((r) => upstream.listen(0, r));
const upstreamBase = `http://localhost:${upstream.address().port}`;

// ── providers de teste: bearer, query e um nunca-conectado ───────────────
fs.mkdirSync(process.env.ZKEYS_PROVIDERS_DIR, { recursive: true });
const providerBase = {
  authorize_url: `${oauthBase}/authorize`,
  token_url: `${oauthBase}/token`,
  profile_url: `${oauthBase}/profile`,
  profile_map: { externalId: "sub", email: "email" },
  client_id_env: "MOCK_CLIENT_ID",
  client_secret_env: "MOCK_CLIENT_SECRET",
  packs: { basico: { label: "Básico", scopes: ["email"] } },
};
const writeProvider = (name, extra) =>
  fs.writeFileSync(
    path.join(process.env.ZKEYS_PROVIDERS_DIR, `${name}.json`),
    JSON.stringify({ ...providerBase, name, displayName: name, ...extra })
  );
writeProvider("mock", {
  api_base_url: upstreamBase,
  auth_injection: { kind: "bearer" },
  pkce: true,
});
writeProvider("mockq", {
  api_base_url: `${upstreamBase}/v9`, // base com path, como o Graph do Meta
  auth_injection: { kind: "query", param: "access_token" },
});
writeProvider("mocknc", { api_base_url: upstreamBase, auth_injection: { kind: "bearer" } });

// ── app zkeys + usuário + conexões via fluxo OAuth real (mock) ───────────
const config = loadConfig();
config.publicBaseUrl = "http://localhost:0";
const { app, store } = createApp(config);
const server = app.listen(0);
await new Promise((r) => server.on("listening", r));
const base = `http://localhost:${server.address().port}`;

const passwords = createPasswords(config.pepper);
const cryptoBox = createCrypto(config.masterKey);
const admin = store.users.create({
  email: "admin@test.dev",
  passwordHash: await passwords.hash("senha-forte-123"),
  role: "admin",
});

const login = await fetch(`${base}/auth/login`, {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ email: "admin@test.dev", password: "senha-forte-123" }),
});
const cookie = login.headers.get("set-cookie").split(";")[0];

async function connect(provider) {
  const start = await fetch(`${base}/auth/${provider}/start?pack=basico`, {
    headers: { cookie }, redirect: "manual",
  });
  const state = new URL(start.headers.get("location")).searchParams.get("state");
  const cb = await fetch(`${base}/auth/${provider}/callback?code=abc&state=${state}`, {
    headers: { cookie },
  });
  assert.equal(cb.status, 200, `connect ${provider}`);
}
await connect("mock");   // at-code-1
await connect("mockq");  // at-code-2

let passed = 0;
const ok = (name) => { passed++; console.log(`  ✓ ${name}`); };

// ── emissão mínima de zwt_ (item 4) ──────────────────────────────────────
assert.equal(
  (await fetch(`${base}/auth/workspace-tokens`, { method: "POST" })).status, 401
);
const badScopes = await fetch(`${base}/auth/workspace-tokens`, {
  method: "POST", headers: { cookie, "content-type": "application/json" },
  body: JSON.stringify({ name: "x", scopes: [] }),
});
assert.equal(badScopes.status, 400);
const issue = await fetch(`${base}/auth/workspace-tokens`, {
  method: "POST", headers: { cookie, "content-type": "application/json" },
  body: JSON.stringify({ name: "ws só mock", scopes: ["mock"] }),
});
assert.equal(issue.status, 201);
const scoped = await issue.json();
assert.match(scoped.token, /^zwt_[A-Za-z0-9_-]{40,}$/);
const issueAll = await fetch(`${base}/auth/workspace-tokens`, {
  method: "POST", headers: { cookie, "content-type": "application/json" },
  body: JSON.stringify({ name: "ws total", scopes: ["*"] }),
});
const all = await issueAll.json();
const hashRow = store.db
  .prepare("SELECT token_hash FROM workspace_tokens WHERE id = ?").get(scoped.id);
assert.ok(!hashRow.token_hash.includes(scoped.token), "banco guarda só o hash");
ok("POST /auth/workspace-tokens: sessão exige, valida scopes, devolve zwt_ 1x, guarda hash");

const zwt = (t) => ({ authorization: `Bearer ${t}` });

// ── (i) GET com bearer: upstream recebe o token REAL, não o zwt_ ─────────
const r1 = await fetch(`${base}/p/mock/gmail/v1/users/me?q=oi`, { headers: zwt(scoped.token) });
assert.equal(r1.status, 200);
assert.equal(r1.headers.get("x-upstream"), "sim", "header do upstream atravessa");
assert.deepEqual(await r1.json(), { ok: true, path: "/gmail/v1/users/me?q=oi" });
let seen = upstreamSeen.at(-1);
assert.equal(seen.headers.authorization, "Bearer at-code-1", "Bearer REAL injetado");
ok("(i) GET /p/mock/… → 200, path+query preservados, Bearer real (não o zwt_)");

// status não-2xx atravessa cru
assert.equal((await fetch(`${base}/p/mock/teapot`, { headers: zwt(scoped.token) })).status, 418);
ok("status do upstream atravessa cru (418)");

// ── (ii) auth_injection kind=query injeta access_token= na URL ───────────
const r2 = await fetch(`${base}/p/mockq/me/adaccounts?fields=id`, { headers: zwt(all.token) });
assert.equal(r2.status, 200);
seen = upstreamSeen.at(-1);
assert.equal(seen.url, "/v9/me/adaccounts?fields=id&access_token=at-code-2",
  "query injection + api_base_url com path");
assert.equal(seen.headers.authorization, undefined, "sem header authorization no kind=query");
ok("(ii) kind=query → access_token= na URL, sem Authorization");

// ── (iii) escopo errado → 403 + audit proxy.deny ─────────────────────────
assert.equal((await fetch(`${base}/p/mockq/x`, { headers: zwt(scoped.token) })).status, 403);
const denies = store.db
  .prepare("SELECT * FROM audit_log WHERE action = 'proxy.deny'").all();
assert.equal(denies.length, 1);
assert.ok(!JSON.stringify(denies).includes(scoped.token), "token não vaza no audit");
ok("(iii) escopo errado → 403 + audit proxy.deny");

// ── (iv) provider não conectado (ou inexistente) → 404 ───────────────────
assert.equal((await fetch(`${base}/p/mocknc/x`, { headers: zwt(all.token) })).status, 404);
assert.equal((await fetch(`${base}/p/naoexiste/x`, { headers: zwt(all.token) })).status, 404);
ok("(iv) não conectado / provider desconhecido → 404");

// ── (v) upstream 401 → refresh → retry → 200 + token novo cifrado ────────
failNextWith401 = true;
const r5 = await fetch(`${base}/p/mock/depois-do-refresh`, { headers: zwt(scoped.token) });
assert.equal(r5.status, 200, "retry pós-refresh devolve 200");
seen = upstreamSeen.at(-1);
assert.equal(seen.headers.authorization, "Bearer at-refresh-1", "retry usa o token novo");
assert.equal(refreshes, 1, "exatamente 1 refresh");
const mockConn = store.db
  .prepare("SELECT * FROM connections WHERE provider = 'mock'").get();
assert.equal(cryptoBox.decrypt(mockConn.access_token_enc), "at-refresh-1",
  "access novo regravado cifrado");
assert.equal(cryptoBox.decrypt(mockConn.refresh_token_enc), "rt-refresh-1",
  "rotação de refresh token persistida");
ok("(v) 401 → refresh 1x → retry 200; tokens novos cifrados no cofre");

// fresh (passo 4): expires_at no passado refresha ANTES do forward, sem 401
store.db.prepare("UPDATE connections SET expires_at = ? WHERE id = ?")
  .run(new Date(Date.now() - 1000).toISOString(), mockConn.id);
const r5b = await fetch(`${base}/p/mock/fresh`, { headers: zwt(scoped.token) });
assert.equal(r5b.status, 200);
assert.equal(upstreamSeen.at(-1).headers.authorization, "Bearer at-refresh-2");
assert.equal(refreshes, 2);
ok("fresh: expirado refresha antes do forward (sem 401 no meio)");

// seleção explícita por alias + strip do ?account= antes do upstream
store.db.prepare("UPDATE connections SET alias = 'principal' WHERE id = ?").run(mockConn.id);
const r6 = await fetch(`${base}/p/mock/sel?account=principal&x=1`, { headers: zwt(scoped.token) });
assert.equal(r6.status, 200);
assert.equal(upstreamSeen.at(-1).url, "/sel?x=1", "account= não vaza pro upstream");
assert.equal(
  (await fetch(`${base}/p/mock/sel?account=inexistente`, { headers: zwt(scoped.token) })).status,
  404
);
ok("?account=<alias> seleciona conexão e é removido da query upstream");

// ── (vii) POST com body JSON atravessa íntegro ───────────────────────────
const payload = JSON.stringify({ msg: "olá, proxy — acentuação íntegra", n: [1, 2, 3] });
const r7 = await fetch(`${base}/p/mock/echo`, {
  method: "POST",
  headers: { ...zwt(scoped.token), "content-type": "application/json" },
  body: payload,
});
assert.equal(r7.status, 200);
assert.equal(await r7.text(), payload, "resposta ecoada chega intacta (stream)");
assert.equal(upstreamSeen.at(-1).body, payload, "upstream recebeu o body byte a byte");
ok("(vii) POST body JSON atravessa íntegro (raw antes dos parsers)");

// ── (vi) zwt_ revogado → 401 ─────────────────────────────────────────────
assert.ok(store.workspaceTokens.revoke(admin.id, scoped.id));
assert.equal((await fetch(`${base}/p/mock/x`, { headers: zwt(scoped.token) })).status, 401);
assert.equal((await fetch(`${base}/p/mock/x`)).status, 401, "sem token também 401");
ok("(vi) zwt_ revogado/ausente → 401");

// ── segurança transversal: o zwt_ NUNCA chegou no upstream ───────────────
const dump = JSON.stringify(upstreamSeen);
assert.ok(!dump.includes("zwt_"), "nenhum request upstream carrega zwt_");
assert.ok(!dump.includes(config.sessionSecret), "nada de segredo de sessão upstream");
const audits = store.db.prepare("SELECT action FROM audit_log").all().map((r) => r.action);
assert.ok(audits.includes("token.issue"));
ok("zwt_ nunca atravessa; audit token.issue registrado");

console.log(`\nPASS — ${passed} checks (proxy F2)`);
server.close();
oauth.close();
upstream.close();
fs.rmSync(tmp, { recursive: true, force: true });
process.exit(0);
