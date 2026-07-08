// E2E da F1 contra um provider MOCK local (sem rede externa):
// login → start (PKCE) → callback persiste → lista → default → re-uso de state
// nega → delete revoga → guards 401. Roda com `npm test`.
//
// Sobe o app real (createApp) com config de teste + um servidor http fazendo
// papel de provider OAuth (token/profile/revoke).

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";

// ── env de teste ANTES de importar config ────────────────────────────────
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zkeys-e2e-"));
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

// ── provider mock ────────────────────────────────────────────────────────
const seen = { tokenBody: null, revoked: false };
const mock = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  if (req.method === "POST" && url.pathname === "/token") {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      seen.tokenBody = new URLSearchParams(body);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({
        access_token: "at-secreto-1", refresh_token: "rt-secreto-1",
        expires_in: 3600, scope: "email perfil",
      }));
    });
    return;
  }
  if (req.method === "GET" && url.pathname === "/profile") {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ sub: "conta-123", email: "pessoa@example.com", name: "Pessoa" }));
    return;
  }
  if (req.method === "POST" && url.pathname === "/revoke") {
    seen.revoked = true;
    res.end("{}");
    return;
  }
  res.statusCode = 404;
  res.end();
});
await new Promise((r) => mock.listen(0, r));
const mockBase = `http://localhost:${mock.address().port}`;

fs.mkdirSync(process.env.ZKEYS_PROVIDERS_DIR, { recursive: true });
fs.writeFileSync(path.join(process.env.ZKEYS_PROVIDERS_DIR, "mock.json"), JSON.stringify({
  name: "mock",
  displayName: "Mock",
  authorize_url: `${mockBase}/authorize`,
  token_url: `${mockBase}/token`,
  revoke_url: `${mockBase}/revoke`,
  profile_url: `${mockBase}/profile`,
  profile_map: { externalId: "sub", email: "email", name: "name" },
  pkce: true,
  client_id_env: "MOCK_CLIENT_ID",
  client_secret_env: "MOCK_CLIENT_SECRET",
  packs: { basico: { label: "Básico", scopes: ["email", "perfil"] } },
}));

// ── app zkeys ────────────────────────────────────────────────────────────
const config = loadConfig();
config.publicBaseUrl = "http://localhost:0"; // callbackUrl não é chamado no teste
const { app, store } = createApp(config);
const server = app.listen(0);
await new Promise((r) => server.on("listening", r));
const base = `http://localhost:${server.address().port}`;

// admin de teste direto no store (bootstrap = create-user.js em prod)
const passwords = createPasswords(config.pepper);
store.users.create({
  email: "admin@test.dev",
  passwordHash: await passwords.hash("senha-forte-123"),
  role: "admin",
});

let passed = 0;
const ok = (name) => { passed++; console.log(`  ✓ ${name}`); };

// ── fluxo ────────────────────────────────────────────────────────────────
// guards sem sessão
assert.equal((await fetch(`${base}/connections`)).status, 401);
assert.equal((await fetch(`${base}/auth/mock/start`)).status, 401);
ok("401 sem sessão (connections, start)");

// login errado
const bad = await fetch(`${base}/auth/login`, {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ email: "admin@test.dev", password: "errada-xxxxx" }),
});
assert.equal(bad.status, 401);
ok("login com senha errada → 401");

// login certo
const login = await fetch(`${base}/auth/login`, {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ email: "admin@test.dev", password: "senha-forte-123" }),
});
assert.equal(login.status, 200);
const cookie = login.headers.get("set-cookie").split(";")[0];
ok("login → cookie de sessão");

const me = await (await fetch(`${base}/auth/me`, { headers: { cookie } })).json();
assert.equal(me.email, "admin@test.dev");
ok("GET /auth/me");

// start → 302 com state + PKCE challenge
const start = await fetch(`${base}/auth/mock/start?pack=basico`, {
  headers: { cookie }, redirect: "manual",
});
assert.equal(start.status, 302);
const authorizeUrl = new URL(start.headers.get("location"));
const state = authorizeUrl.searchParams.get("state");
assert.ok(state && state.length > 30, "state presente e longo");
assert.ok(authorizeUrl.searchParams.get("code_challenge"), "PKCE challenge presente");
assert.equal(authorizeUrl.searchParams.get("client_id"), "mock-client-id");
ok("start → 302 com state + code_challenge");

// callback → troca code, persiste cifrado
const cb = await fetch(`${base}/auth/mock/callback?code=abc&state=${state}`, { headers: { cookie } });
assert.equal(cb.status, 200);
assert.match(await cb.text(), /Conectado/);
assert.ok(seen.tokenBody.get("code_verifier"), "code_verifier chegou no provider");
assert.equal(seen.tokenBody.get("code"), "abc");
ok("callback → token exchange (PKCE) + popup ok");

// state é single-use
const replay = await fetch(`${base}/auth/mock/callback?code=abc&state=${state}`, { headers: { cookie } });
assert.equal(replay.status, 400);
ok("replay do state → 400 (single-use)");

// lista: metadata only, sem token
const conns = await (await fetch(`${base}/connections`, { headers: { cookie } })).json();
assert.equal(conns.length, 1);
const conn = conns[0];
assert.equal(conn.provider, "mock");
assert.equal(conn.email, "pessoa@example.com");
assert.equal(conn.is_default, 1);
const asText = JSON.stringify(conns);
assert.ok(!asText.includes("at-secreto"), "access token NÃO aparece na listagem");
assert.ok(!asText.includes("_enc"), "colunas _enc NÃO aparecem na listagem");
ok("GET /connections → metadata, default, zero token");

// at-rest: BLOB cifrado de verdade
const raw = store.db.prepare("SELECT access_token_enc FROM connections WHERE id = ?").get(conn.id);
const blob = Buffer.from(raw.access_token_enc);
assert.ok(!blob.toString("latin1").includes("at-secreto"), "BLOB não contém plaintext");
assert.ok(blob.length >= 28, "formato nonce+ct+tag");
ok("token cifrado at-rest (AES-256-GCM)");

// default explícito
const def = await fetch(`${base}/connections/${conn.id}/default`, { method: "POST", headers: { cookie } });
assert.equal(def.status, 200);
ok("POST default");

// alias
const alias = await fetch(`${base}/connections/${conn.id}`, {
  method: "PATCH", headers: { cookie, "content-type": "application/json" },
  body: JSON.stringify({ alias: "conta principal" }),
});
assert.equal(alias.status, 200);
ok("PATCH alias");

// delete → revoke no provider + some da lista
const del = await fetch(`${base}/connections/${conn.id}`, { method: "DELETE", headers: { cookie } });
assert.equal(del.status, 200);
assert.equal(seen.revoked, true, "revoke chegou no provider");
const after = await (await fetch(`${base}/connections`, { headers: { cookie } })).json();
assert.equal(after.length, 0);
ok("DELETE → revoke real + cofre limpo");

// admin cria usuário; user comum não
const mk = await fetch(`${base}/auth/users`, {
  method: "POST", headers: { cookie, "content-type": "application/json" },
  body: JSON.stringify({ email: "user@test.dev", password: "outra-senha-123" }),
});
assert.equal(mk.status, 201);
const ulogin = await fetch(`${base}/auth/login`, {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ email: "user@test.dev", password: "outra-senha-123" }),
});
const ucookie = ulogin.headers.get("set-cookie").split(";")[0];
const forbidden = await fetch(`${base}/auth/users`, {
  method: "POST", headers: { cookie: ucookie, "content-type": "application/json" },
  body: JSON.stringify({ email: "x@test.dev", password: "12345678" }),
});
assert.equal(forbidden.status, 403);
ok("admin cria usuário; user comum → 403");

// auditoria registrou o ciclo
const audits = store.db.prepare("SELECT action FROM audit_log ORDER BY at").all().map((r) => r.action);
assert.ok(audits.includes("connection.connect"));
assert.ok(audits.includes("connection.revoke"));
assert.ok(audits.includes("login.fail"));
assert.ok(audits.includes("user.create"));
ok("audit_log cobre connect/revoke/login.fail/user.create");

console.log(`\nPASS — ${passed} checks`);
server.close();
mock.close();
fs.rmSync(tmp, { recursive: true, force: true });
process.exit(0);
