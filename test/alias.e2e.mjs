// E2E da base alias (`connection_provider`, DESIGN-zkeys §6): um provider com
// host/API próprio (ex: google-workspace-events → workspaceevents.googleapis.com)
// que REUSA a conexão OAuth de outro provider (ex: a `google`). Sem rede externa:
// mocks locais de OAuth + upstream.
//
// Cobre: catálogo marca connectable:false · /auth/<alias>/start → 400 · proxy
// injeta o Bearer da conexão DONA · authZ pelo nome do alias na URL · seleção
// por ?account usa a conexão dona · 404 quando o dono não conectou · refresh
// on-401 roda com o client do alias e regrava a conexão dona. `npm run test:alias`.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { mkCsrf } from "./helpers.mjs";

// ── env de teste ANTES de importar config ────────────────────────────────
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zkeys-alias-e2e-"));
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
          refresh_token: `rt-refresh-${refreshes}`,
          expires_in: 3600,
        }));
      } else {
        res.end(JSON.stringify({
          access_token: "at-code-1", refresh_token: "rt-code-1",
          expires_in: 3600, scope: "email perfil",
        }));
      }
    });
    return;
  }
  if (req.method === "GET" && url.pathname === "/profile") {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ sub: "conta-1", email: "pessoa@example.com" }));
    return;
  }
  res.statusCode = 404;
  res.end();
});
await new Promise((r) => oauth.listen(0, r));
const oauthBase = `http://localhost:${oauth.address().port}`;

// ── API upstream mock (grava requests; ecoa; 401 sob demanda) ────────────
const upstreamSeen = [];
let failNextWith401 = false;
const upstream = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    upstreamSeen.push({
      method: req.method, url: req.url,
      headers: { ...req.headers }, body: Buffer.concat(chunks).toString("utf8"),
    });
    if (failNextWith401) {
      failNextWith401 = false;
      res.statusCode = 401;
      res.setHeader("content-type", "application/json");
      return res.end(JSON.stringify({ error: "token expirado" }));
    }
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ ok: true, path: req.url }));
  });
});
await new Promise((r) => upstream.listen(0, r));
const upstreamBase = `http://localhost:${upstream.address().port}`;

// ── providers de teste: dono da conexão (mock) + alias (mockalias) ───────
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
// Base alias: outro "host" (path /wse simula workspaceevents.googleapis.com),
// conexão OAuth = a do `mock`; não-conectável, sem OAuth próprio.
writeProvider("mockalias", {
  api_base_url: `${upstreamBase}/wse`,
  auth_injection: { kind: "bearer" },
  connectable: false,
  connection_provider: "mock",
  packs: {},
});

// ── app zkeys + usuários ─────────────────────────────────────────────────
const config = loadConfig();
config.publicBaseUrl = "http://localhost:0";
const { app, store } = createApp(config);
const server = app.listen(0);
await new Promise((r) => server.on("listening", r));
const base = `http://localhost:${server.address().port}`;

const passwords = createPasswords(config.pepper);
const cryptoBox = createCrypto(config.masterKey);
async function makeUser(email, role = "user") {
  const u = store.users.create({
    email,
    passwordHash: await passwords.hash("senha-forte-123"),
    role,
  });
  const login = await fetch(`${base}/auth/login`, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password: "senha-forte-123" }),
  });
  const cookie = login.headers.get("set-cookie").split(";")[0];
  return { id: u.id, cookie, csrf: await mkCsrf(base, cookie) };
}
const admin = await makeUser("admin@test.dev", "admin");   // vai conectar o mock
const outsider = await makeUser("outsider@test.dev");      // nunca conecta nada

async function issueToken(user, name, scopes) {
  const res = await fetch(`${base}/auth/workspace-tokens`, {
    method: "POST", headers: user.csrf.headers(),
    body: JSON.stringify({ name, scopes }),
  });
  assert.equal(res.status, 201);
  return (await res.json()).token;
}
const aliasToken = await issueToken(admin, "ws alias", ["mockalias"]);
const ownerOnlyToken = await issueToken(admin, "ws só dono", ["mock"]);
const wildcardOutsider = await issueToken(outsider, "ws outsider", ["*"]);

async function connect(provider) {
  const start = await fetch(`${base}/auth/${provider}/start?pack=basico`, {
    headers: { cookie: admin.cookie }, redirect: "manual",
  });
  const state = new URL(start.headers.get("location")).searchParams.get("state");
  const cb = await fetch(`${base}/auth/${provider}/callback?code=abc&state=${state}`, {
    headers: { cookie: admin.cookie },
  });
  assert.equal(cb.status, 200, `connect ${provider}`);
}
await connect("mock");   // conexão dona: at-code-1

let passed = 0;
const ok = (name) => { passed++; console.log(`  ✓ ${name}`); };
const zwt = (t) => ({ authorization: `Bearer ${t}` });

// ── (a) catálogo: alias aparece como não-conectável ──────────────────────
const provs = await (await fetch(`${base}/providers`, { headers: { cookie: admin.csrf.cookie } })).json();
const mockMeta = provs.find((p) => p.name === "mock");
const aliasMeta = provs.find((p) => p.name === "mockalias");
assert.equal(mockMeta.connectable, true);
assert.equal(aliasMeta.connectable, false, "base alias não é conectável");
ok("GET /providers marca connectable:false pro alias (e true pro dono)");

// ── (b) /auth/<alias>/start → 400 (sem OAuth próprio) ────────────────────
const startAlias = await fetch(`${base}/auth/mockalias/start`, {
  headers: { cookie: admin.cookie }, redirect: "manual",
});
assert.equal(startAlias.status, 400);
ok("/auth/mockalias/start → 400 (não conectável)");

// ── (c) proxy do alias injeta o Bearer da conexão DONA ───────────────────
const r3 = await fetch(`${base}/p/mockalias/v1/subscriptions`, {
  method: "POST",
  headers: { ...zwt(aliasToken), "content-type": "application/json" },
  body: JSON.stringify({ eventTypes: ["google.workspace.meet.conference.v2.started"] }),
});
assert.equal(r3.status, 200);
let seen = upstreamSeen.at(-1);
assert.equal(seen.url, "/wse/v1/subscriptions", "base própria do alias (não a do dono)");
assert.equal(seen.headers.authorization, "Bearer at-code-1", "Bearer REAL da conexão mock");
assert.equal(seen.body, JSON.stringify({ eventTypes: ["google.workspace.meet.conference.v2.started"] }));
ok("POST /p/mockalias/… → base do alias + token da conexão google (mock) + body íntegro");

// ── (d) authZ é pelo nome do alias na URL ────────────────────────────────
assert.equal(
  (await fetch(`${base}/p/mockalias/v1/subscriptions`, { headers: zwt(ownerOnlyToken) })).status,
  403,
  "token só com escopo do dono NÃO acessa o alias"
);
ok("escopo do zwt_ é por provider da URL (mockalias ≠ mock) → 403");

// ── (e) ?account=<alias> seleciona na conexão DONA ───────────────────────
store.db.prepare("UPDATE connections SET alias = 'principal' WHERE provider = 'mock'").run();
const r5 = await fetch(`${base}/p/mockalias/v1/operations/op-1?account=principal&x=2`, {
  headers: zwt(aliasToken),
});
assert.equal(r5.status, 200);
seen = upstreamSeen.at(-1);
assert.equal(seen.url, "/wse/v1/operations/op-1?x=2", "account= removido, path próprio");
assert.equal(seen.headers.authorization, "Bearer at-code-1");
ok("?account seleciona alias na conexão dona e não vaza pro upstream");

// ── (f) dono nunca conectou → 404 nomeando o dono ────────────────────────
const r6 = await fetch(`${base}/p/mockalias/v1/subscriptions`, { headers: zwt(wildcardOutsider) });
assert.equal(r6.status, 404);
const err6 = await r6.json();
assert.match(err6.error, /nenhuma conexão mock/, "mensagem aponta a conexão dona");
ok("usuário sem conexão dona → 404 mencionando o provider dono");

// ── (g) upstream 401 → refresh com o client do ALIAS → retry 200 ─────────
failNextWith401 = true;
const r7 = await fetch(`${base}/p/mockalias/v1/subscriptions`, {
  method: "POST",
  headers: { ...zwt(aliasToken), "content-type": "application/json" },
  body: JSON.stringify({}),
});
assert.equal(r7.status, 200, "retry pós-refresh devolve 200");
seen = upstreamSeen.at(-1);
assert.equal(seen.headers.authorization, "Bearer at-refresh-1", "retry usa o token novo");
assert.equal(refreshes, 1, "exatamente 1 refresh");
const mockConn = store.db.prepare("SELECT * FROM connections WHERE provider = 'mock'").get();
const mockBox = cryptoBox.openConnection(mockConn);
assert.equal(mockBox.decrypt(mockConn.access_token_enc), "at-refresh-1",
  "refresh via alias regrava o access na conexão DONA, cifrado");
assert.equal(mockBox.decrypt(mockConn.refresh_token_enc), "rt-refresh-1",
  "rotação de refresh token persistida na conexão dona");
ok("401 → refresh 1x (client do alias = mesmo OAuth) → retry 200; tokens novos na conexão dona");

// ── segurança transversal ────────────────────────────────────────────────
const dump = JSON.stringify(upstreamSeen);
assert.ok(!dump.includes("zwt_"), "nenhum request upstream carrega zwt_");
ok("zwt_ nunca atravessa pro upstream");

console.log(`\nPASS — ${passed} checks (base alias)`);
server.close();
oauth.close();
upstream.close();
fs.rmSync(tmp, { recursive: true, force: true });
process.exit(0);
