// E2E da F4 (hardening §8/§9) contra mocks locais, sem rede externa:
//   (A) rate limit  — login por IP e por email (+ janela expira); proxy por
//                     token id e por IP (pré-authN). 429 + Retry-After.
//   (B) auditoria   — GET /audit lista os eventos do usuário sem segredo;
//                     user A NÃO vê eventos de B (isolamento).
//   (C) envelope    — token v2 decifra; dois connections têm dek_wrapped
//                     diferentes; a migração v1→v2 (script real) preserva o
//                     plaintext; dump sem o KEK é indecifrável.
//   (D) csrf        — mutação via cookie SEM token → 403; COM → 201.
// Roda com `npm test`.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { mkCsrf } from "./helpers.mjs";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, "..");

// ── env de teste ANTES de importar config ────────────────────────────────
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zkeys-hardening-e2e-"));
process.env.ZKEYS_MASTER_KEY = crypto.randomBytes(32).toString("hex");
process.env.ZKEYS_AUTH_PEPPER = "pepper-de-teste";
process.env.ZKEYS_SESSION_SECRET = "session-secret-de-teste";
process.env.ZKEYS_INSECURE_COOKIE = "1";
process.env.ZKEYS_DB_PATH = path.join(tmp, "zkeys.db");
process.env.ZKEYS_PROVIDERS_DIR = path.join(tmp, "providers");
process.env.MOCK_CLIENT_ID = "mock-client-id";
process.env.MOCK_CLIENT_SECRET = "mock-client-secret";
// req.ip vem do X-Forwarded-For (§9); os testes variam o XFF pra isolar chaves.
process.env.ZKEYS_TRUST_PROXY = "1";
process.env.ZKEYS_RL_LOGIN_MAX = "3";
process.env.ZKEYS_RL_LOGIN_WINDOW_S = "1";     // 1s → testa expiração sem esperar muito
process.env.ZKEYS_RL_PROXY_MAX = "4";
process.env.ZKEYS_RL_PROXY_WINDOW_S = "60";

const { loadConfig } = await import("../config.js");
const { createApp } = await import("../index.js");
const { createPasswords } = await import("../lib/passwords.js");
const { createCrypto } = await import("../lib/crypto.js");

// ── provider OAuth mock + API upstream mock ──────────────────────────────
let codeExchanges = 0;
const oauth = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  if (req.method === "POST" && url.pathname === "/token") {
    let body = ""; req.on("data", (c) => (body += c));
    req.on("end", () => {
      codeExchanges++;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({
        access_token: `at-code-${codeExchanges}`, refresh_token: `rt-code-${codeExchanges}`,
        expires_in: 3600, scope: "email",
      }));
    });
    return;
  }
  if (req.method === "GET" && url.pathname === "/profile") {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ sub: `conta-${codeExchanges}`, email: "pessoa@example.com" }));
    return;
  }
  res.statusCode = 404; res.end();
});
await new Promise((r) => oauth.listen(0, r));
const oauthBase = `http://localhost:${oauth.address().port}`;

const upstream = http.createServer((req, res) => {
  req.on("data", () => {}); req.on("end", () => {
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ ok: true, url: req.url }));
  });
});
await new Promise((r) => upstream.listen(0, r));
const upstreamBase = `http://localhost:${upstream.address().port}`;

fs.mkdirSync(process.env.ZKEYS_PROVIDERS_DIR, { recursive: true });
fs.writeFileSync(path.join(process.env.ZKEYS_PROVIDERS_DIR, "mock.json"), JSON.stringify({
  name: "mock", displayName: "Mock",
  authorize_url: `${oauthBase}/authorize`, token_url: `${oauthBase}/token`,
  profile_url: `${oauthBase}/profile`, profile_map: { externalId: "sub", email: "email" },
  api_base_url: upstreamBase, auth_injection: { kind: "bearer" }, pkce: true,
  client_id_env: "MOCK_CLIENT_ID", client_secret_env: "MOCK_CLIENT_SECRET",
  packs: { basico: { label: "Básico", scopes: ["email"] } },
}));

// ── app zkeys ────────────────────────────────────────────────────────────
const config = loadConfig();
config.publicBaseUrl = "http://localhost:0";
const { app, store } = createApp(config);
const server = app.listen(0);
await new Promise((r) => server.on("listening", r));
const base = `http://localhost:${server.address().port}`;

const passwords = createPasswords(config.pepper);
await passwords.hash("warmup");
const admin = store.users.create({
  email: "admin@test.dev", passwordHash: await passwords.hash("senha-forte-123"), role: "admin",
});

let passed = 0;
const ok = (name) => { passed++; console.log(`  ✓ ${name}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// login com XFF controlado (req.ip = o XFF, via trust proxy=1).
async function login(ip, email, password) {
  return fetch(`${base}/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-forwarded-for": ip },
    body: JSON.stringify({ email, password }),
  });
}
async function loginOk(ip, email, password) {
  const r = await login(ip, email, password);
  assert.equal(r.status, 200, `login ${email}`);
  return r.headers.get("set-cookie").split(";")[0];
}

// ═══ (A) RATE LIMIT — login ═══════════════════════════════════════════════
// Por IP: 3 falhas do mesmo IP (emails distintos p/ não tocar o teto de email)
// → 401; a 4ª → 429 + Retry-After. IP diferente não é afetado.
const ipA = "10.0.0.1";
for (let i = 0; i < 3; i++) assert.equal((await login(ipA, `u${i}@x.dev`, "errada")).status, 401);
const over = await login(ipA, "novo@x.dev", "errada");
assert.equal(over.status, 429);
assert.ok(Number(over.headers.get("retry-after")) >= 0, "Retry-After presente");
assert.equal((await login("10.0.0.2", "u@x.dev", "errada")).status, 401, "IP diferente não afetado");
ok("(A.1) login: 3 falhas/IP → 4ª = 429 + Retry-After; outro IP livre");

// Por email: 3 falhas do MESMO email em IPs distintos (IP nunca acumula) → a
// 4ª (IP fresco) estoura o teto de email. Email diferente não é afetado.
const victim = "victim@x.dev";
for (let i = 0; i < 3; i++) assert.equal((await login(`172.16.0.${i}`, victim, "errada")).status, 401);
assert.equal((await login("172.16.9.9", victim, "errada")).status, 429, "teto por email estoura");
assert.equal((await login("172.16.9.10", "outro@x.dev", "errada")).status, 401, "email diferente livre");
ok("(A.2) login: 3 falhas/email (IPs distintos) → 4ª = 429; outro email livre");

// Janela expira e libera (window=1s).
const ipW = "10.5.5.5";
for (let i = 0; i < 3; i++) await login(ipW, `w${i}@x.dev`, "errada");
assert.equal((await login(ipW, "w@x.dev", "errada")).status, 429, "estourou");
await sleep(1100);
assert.equal((await login(ipW, "w@x.dev", "errada")).status, 401, "janela expirou → liberou");
ok("(A.3) login: janela expira e libera");

// auditoria registrou os bloqueios (sem vazar credencial).
const rl = store.db.prepare("SELECT * FROM audit_log WHERE action = 'login.ratelimited'").all();
assert.ok(rl.length >= 3, "login.ratelimited auditado");
assert.ok(!JSON.stringify(rl).includes("errada"), "senha nunca no audit");
ok("(A.4) login.ratelimited auditado, sem credencial");

// ═══ Setup autenticado (IPs dedicados p/ não colidir com o rate limit) ════
const cookie = await loginOk("192.0.2.1", "admin@test.dev", "senha-forte-123");
const csrf = await mkCsrf(base, cookie);

async function connect(provider, c = cookie) {
  const start = await fetch(`${base}/auth/${provider}/start?pack=basico`, {
    headers: { cookie: c, "x-forwarded-for": "192.0.2.1" }, redirect: "manual",
  });
  const state = new URL(start.headers.get("location")).searchParams.get("state");
  const cb = await fetch(`${base}/auth/${provider}/callback?code=abc&state=${state}`, {
    headers: { cookie: c },
  });
  assert.equal(cb.status, 200, `connect ${provider}`);
}
await connect("mock");   // conexão v2 (nasce envelope)

// ═══ (D) CSRF ═════════════════════════════════════════════════════════════
const noCsrf = await fetch(`${base}/auth/workspace-tokens`, {
  method: "POST", headers: { cookie, "content-type": "application/json" },
  body: JSON.stringify({ name: "sem csrf", scopes: ["mock"] }),
});
assert.equal(noCsrf.status, 403, "mutação sem X-CSRF-Token → 403");
const withCsrf = await fetch(`${base}/auth/workspace-tokens`, {
  method: "POST", headers: csrf.headers(),
  body: JSON.stringify({ name: "com csrf", scopes: ["*"] }),
});
assert.equal(withCsrf.status, 201, "mutação com token CSRF → 201");
const tk = (await withCsrf.json()).token;
// O proxy usa Bearer, não cookie → NÃO exige CSRF (imune).
assert.equal((await fetch(`${base}/p/mock/ping`, {
  headers: { authorization: `Bearer ${tk}`, "x-forwarded-for": "198.51.100.200" },
})).status, 200, "proxy Bearer é imune a CSRF");
ok("(D) CSRF: sem token → 403; com token → 201; proxy Bearer imune");

// ═══ (A) RATE LIMIT — proxy ═══════════════════════════════════════════════
// Por token id: token FRESCO (o tk já gastou 1 slot no check de CSRF acima),
// IPs variando (ipLimit não acumula) → a 5ª (max=4) dá 429. Token diferente
// (IP fresco) não é afetado.
const tkP = (await (await fetch(`${base}/auth/workspace-tokens`, {
  method: "POST", headers: csrf.headers(), body: JSON.stringify({ name: "proxy-rl", scopes: ["*"] }),
})).json()).token;
for (let i = 0; i < 4; i++) {
  const r = await fetch(`${base}/p/mock/ping`, {
    headers: { authorization: `Bearer ${tkP}`, "x-forwarded-for": `198.51.100.${i}` },
  });
  assert.equal(r.status, 200, `req ${i}`);
}
const overTok = await fetch(`${base}/p/mock/ping`, {
  headers: { authorization: `Bearer ${tkP}`, "x-forwarded-for": "198.51.100.9" },
});
assert.equal(overTok.status, 429, "5ª com o mesmo token → 429");
assert.ok(Number(overTok.headers.get("retry-after")) >= 0, "Retry-After presente");
const tk2 = (await (await fetch(`${base}/auth/workspace-tokens`, {
  method: "POST", headers: csrf.headers(), body: JSON.stringify({ name: "outro", scopes: ["*"] }),
})).json()).token;
assert.equal((await fetch(`${base}/p/mock/ping`, {
  headers: { authorization: `Bearer ${tk2}`, "x-forwarded-for": "198.51.100.30" },
})).status, 200, "outro token não afetado");
ok("(A.5) proxy: 5ª chamada/token → 429; outro token livre");

// Por IP (pré-authN): mesma IP sem token → ipLimit estoura ANTES do authN.
const ipX = "203.0.113.7";
for (let i = 0; i < 4; i++) {
  assert.equal((await fetch(`${base}/p/mock/x`, { headers: { "x-forwarded-for": ipX } })).status, 401);
}
const overIp = await fetch(`${base}/p/mock/x`, { headers: { "x-forwarded-for": ipX } });
assert.equal(overIp.status, 429, "5ª do mesmo IP → 429 (pré-authN)");
assert.equal((await fetch(`${base}/p/mock/x`, { headers: { "x-forwarded-for": "203.0.113.8" } })).status,
  401, "IP diferente não afetado");
ok("(A.6) proxy: teto por IP dispara pré-authN; outro IP livre");

const prl = store.db.prepare("SELECT * FROM audit_log WHERE action = 'proxy.ratelimited'").all();
assert.ok(prl.length >= 2 && !JSON.stringify(prl).includes("zwt_"), "proxy.ratelimited auditado, sem zwt_");
ok("(A.7) proxy.ratelimited auditado, sem token");

// ═══ (B) AUDITORIA exposta + isolamento ══════════════════════════════════
const auditA = await (await fetch(`${base}/audit`, { headers: { cookie } })).json();
assert.ok(Array.isArray(auditA) && auditA.length > 0, "GET /audit devolve eventos");
const actionsA = auditA.map((e) => e.action);
assert.ok(actionsA.includes("connection.connect") && actionsA.includes("token.issue"));
// Nenhum segredo aparece: nem zwt_, nem token_hash, nem senha.
const dumpA = JSON.stringify(auditA);
assert.ok(!dumpA.includes("zwt_") && !dumpA.includes("errada") && !dumpA.toLowerCase().includes("token_hash"),
  "sem segredo no /audit");
ok("(B.1) GET /audit lista eventos do usuário, sem segredo");

// Isolamento: cria userB, ele gera um token com nome único; A não vê o evento de B.
const mkB = await fetch(`${base}/auth/users`, {
  method: "POST", headers: csrf.headers(),
  body: JSON.stringify({ email: "userb@test.dev", password: "senha-b-12345", role: "user" }),
});
assert.equal(mkB.status, 201);
const cookieB = await loginOk("192.0.2.2", "userb@test.dev", "senha-b-12345");
const csrfB = await mkCsrf(base, cookieB);
const SECRET_NAME = "token-exclusivo-do-B-xyz";
await fetch(`${base}/auth/workspace-tokens`, {
  method: "POST", headers: csrfB.headers(), body: JSON.stringify({ name: SECRET_NAME, scopes: ["mock"] }),
});
const auditB = await (await fetch(`${base}/audit`, { headers: { cookie: cookieB } })).json();
assert.ok(JSON.stringify(auditB).includes(SECRET_NAME), "B vê o próprio evento");
const auditA2 = await (await fetch(`${base}/audit`, { headers: { cookie } })).json();
assert.ok(!JSON.stringify(auditA2).includes(SECRET_NAME), "A NÃO vê o evento de B (isolamento)");
// E B não vê nada de A (a conexão mock foi do admin A).
assert.ok(!auditB.some((e) => e.action === "connection.connect"), "B não vê connect de A");
ok("(B.2) isolamento: A não vê eventos de B e vice-versa");

// ═══ (C) ENVELOPE ════════════════════════════════════════════════════════
const cryptoBox = createCrypto(config.masterKey);
// A conexão mock (do callback) é v2: tem dek_wrapped e decifra certo.
const mockConn = store.db.prepare("SELECT * FROM connections WHERE provider='mock'").get();
assert.ok(mockConn.dek_wrapped, "conexão nova nasce v2 (dek_wrapped presente)");
assert.equal(Buffer.from(mockConn.access_token_enc)[0], 0x02, "blob v2 tem byte de versão 0x02");
assert.equal(cryptoBox.openConnection(mockConn).decrypt(mockConn.access_token_enc), "at-code-1",
  "v2 decifra com o DEK da linha");
ok("(C.1) conexão nova é v2 (dek_wrapped + byte 0x02) e decifra certo");

// Insere uma conexão LEGADA v1 (KEK direto, sem dek_wrapped) — simula dado F1-F3.
const V1_ACCESS = "at-v1-plaintext-secreto";
const V1_REFRESH = "rt-v1-plaintext-secreto";
const v1Id = crypto.randomUUID();
const nowIso = new Date().toISOString();
store.db.prepare(`
  INSERT INTO connections (id, user_id, provider, account_key, scopes_json,
    access_token_enc, refresh_token_enc, dek_wrapped, expires_at, is_default, created_at, updated_at)
  VALUES (?, ?, 'mock', 'v1acct', '[]', ?, ?, NULL, NULL, 0, ?, ?)
`).run(v1Id, admin.id, cryptoBox.encrypt(V1_ACCESS), cryptoBox.encrypt(V1_REFRESH), nowIso, nowIso);
const v1Before = store.connections.findById(v1Id);
assert.equal(v1Before.dek_wrapped, null, "linha legada é v1 (dek_wrapped NULL)");
assert.equal(cryptoBox.decrypt(v1Before.access_token_enc), V1_ACCESS, "v1 decifra com KEK direto");

// Roda a MIGRAÇÃO real (script) contra o mesmo banco.
execFileSync("node", [path.join(REPO, "scripts/migrate-envelope.js")], {
  env: process.env, stdio: "pipe",
});
const v1After = store.connections.findById(v1Id);
assert.ok(v1After.dek_wrapped, "após migração: dek_wrapped preenchido (v2)");
assert.equal(Buffer.from(v1After.access_token_enc)[0], 0x02, "após migração: blob v2");
const openedV1 = cryptoBox.openConnection(v1After);
assert.equal(openedV1.decrypt(v1After.access_token_enc), V1_ACCESS, "plaintext do access PRESERVADO");
assert.equal(openedV1.decrypt(v1After.refresh_token_enc), V1_REFRESH, "plaintext do refresh PRESERVADO");
ok("(C.2) migração v1→v2 (script real) preserva o plaintext de access e refresh");

// Idempotência: rodar de novo não altera a linha já-v2 nem quebra o plaintext.
const wrappedBefore = Buffer.from(v1After.dek_wrapped).toString("hex");
execFileSync("node", [path.join(REPO, "scripts/migrate-envelope.js")], { env: process.env, stdio: "pipe" });
const v1Again = store.connections.findById(v1Id);
assert.equal(Buffer.from(v1Again.dek_wrapped).toString("hex"), wrappedBefore, "2ª migração é no-op");
assert.equal(cryptoBox.openConnection(v1Again).decrypt(v1Again.access_token_enc), V1_ACCESS);
ok("(C.3) migração idempotente (2ª passada = no-op, plaintext intacto)");

// Dois connections têm DEKs (dek_wrapped) diferentes.
assert.notEqual(
  Buffer.from(mockConn.dek_wrapped).toString("hex"),
  Buffer.from(v1After.dek_wrapped).toString("hex"),
  "cada connection tem um dek_wrapped próprio"
);
ok("(C.4) DEK por-connection: dek_wrapped distintos entre conexões");

// Dump sem o KEK é indecifrável: KEK errado não abre o DEK.
const wrongKek = createCrypto(crypto.randomBytes(32));
assert.throws(() => wrongKek.openConnection(mockConn).decrypt(mockConn.access_token_enc),
  "sem o KEK certo, o dek_wrapped não abre → indecifrável");
// E os blobs crus não contêm plaintext.
assert.ok(!Buffer.from(v1After.access_token_enc).toString("latin1").includes(V1_ACCESS),
  "blob v2 não contém plaintext");
ok("(C.5) dump sem KEK é inútil (dek_wrapped não abre; blob sem plaintext)");

console.log(`\nPASS — ${passed} checks (hardening F4: rate limit + auditoria + envelope + csrf)`);
server.close();
oauth.close();
upstream.close();
fs.rmSync(tmp, { recursive: true, force: true });
process.exit(0);
