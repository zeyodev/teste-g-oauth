// E2E da F3 (ciclo de workspace tokens + appsecret_proof do Meta) contra
// mocks locais, sem rede externa:
//   (i)   POST emite zwt_; GET lista sem hash/segredo; DELETE revoga → o mesmo
//         zwt_ no proxy passa a dar 401.
//   (ii)  provider com sign:"appsecret_proof" + auth_injection query → o upstream
//         recebe appsecret_proof = hex(hmac-sha256(app_secret, access_token)).
//   (iii) após refresh-on-401, o proof é RECALCULADO com o token novo (valores
//         diferentes; cada um bate com o hmac do respectivo token).
//   (iv)  provider sem sign → nenhum appsecret_proof na URL.
// Roda com `npm test`.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";

// ── env de teste ANTES de importar config ────────────────────────────────
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zkeys-tokens-e2e-"));
process.env.ZKEYS_MASTER_KEY = crypto.randomBytes(32).toString("hex");
process.env.ZKEYS_AUTH_PEPPER = "pepper-de-teste";
process.env.ZKEYS_SESSION_SECRET = "session-secret-de-teste";
process.env.ZKEYS_INSECURE_COOKIE = "1";
process.env.ZKEYS_DB_PATH = path.join(tmp, "zkeys.db");
process.env.ZKEYS_PROVIDERS_DIR = path.join(tmp, "providers");
process.env.MOCK_CLIENT_ID = "mock-app-id";
process.env.MOCK_CLIENT_SECRET = "mock-app-secret"; // vira o app secret do sign

const { loadConfig } = await import("../config.js");
const { createApp } = await import("../index.js");
const { createPasswords } = await import("../lib/passwords.js");
const { appsecretProof } = await import("../providers/hooks/meta_signed_request.js");

const APP_SECRET = process.env.MOCK_CLIENT_SECRET;
// Recompute independente (não usa a primitiva do app) pra provar o valor.
const proofRef = (token) =>
  crypto.createHmac("sha256", APP_SECRET).update(token).digest("hex");

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
          refresh_token: `rt-refresh-${refreshes}`,
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

// ── API upstream mock (grava requests; simula 401 sob demanda) ───────────
const upstreamSeen = [];
let failNextWith401 = false;
const upstream = http.createServer((req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    upstreamSeen.push({ method: req.method, url: req.url, headers: { ...req.headers } });
    if (failNextWith401) {
      failNextWith401 = false;
      res.statusCode = 401;
      res.setHeader("content-type", "application/json");
      return res.end(JSON.stringify({ error: "token expirado" }));
    }
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify({ ok: true, url: req.url }));
  });
});
await new Promise((r) => upstream.listen(0, r));
const upstreamBase = `http://localhost:${upstream.address().port}`;

// ── providers de teste: um assinado (Meta-like), um sem sign (Google-like) ─
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
// metasign: access_token na query + appsecret_proof (exatamente o Meta).
writeProvider("metasign", {
  api_base_url: `${upstreamBase}/v23.0`,
  auth_injection: { kind: "query", param: "access_token" },
  sign: "appsecret_proof",
});
// nosign: bearer no header, sem assinatura (exatamente o Google).
writeProvider("nosign", {
  api_base_url: upstreamBase,
  auth_injection: { kind: "bearer" },
});

// ── app zkeys + usuário + conexões via fluxo OAuth real (mock) ───────────
const config = loadConfig();
config.publicBaseUrl = "http://localhost:0";
const { app, store } = createApp(config);
const server = app.listen(0);
await new Promise((r) => server.on("listening", r));
const base = `http://localhost:${server.address().port}`;

const passwords = createPasswords(config.pepper);
await passwords.hash("warmup"); // aquece o argon2 antes do 1º login
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
await connect("metasign"); // at-code-1
await connect("nosign");   // at-code-2

const zwt = (t) => ({ authorization: `Bearer ${t}` });
const lastUrl = () => new URL(upstreamSeen.at(-1).url, "http://x");
let passed = 0;
const ok = (name) => { passed++; console.log(`  ✓ ${name}`); };

// ── (i) ciclo do zwt_: emitir → listar (sem segredo) → revogar → 401 ─────
// GET exige sessão.
assert.equal((await fetch(`${base}/auth/workspace-tokens`)).status, 401);
const issue = await fetch(`${base}/auth/workspace-tokens`, {
  method: "POST", headers: { cookie, "content-type": "application/json" },
  body: JSON.stringify({ name: "ws duo", scopes: ["metasign", "nosign"] }),
});
assert.equal(issue.status, 201);
const tok = await issue.json();
assert.match(tok.token, /^zwt_[A-Za-z0-9_-]{40,}$/);

const list1 = await (await fetch(`${base}/auth/workspace-tokens`, { headers: { cookie } })).json();
assert.equal(list1.length, 1);
const listed = list1[0];
assert.equal(listed.id, tok.id);
assert.equal(listed.name, "ws duo");
assert.deepEqual(listed.scopes, ["metasign", "nosign"]);
assert.ok(listed.created_at && !listed.revoked_at);
assert.equal(listed.last_used_at, null, "ainda não usado");
// Nem o segredo nem o hash aparecem na listagem.
assert.ok(!JSON.stringify(list1).includes(tok.token), "segredo não vaza no GET");
assert.ok(!JSON.stringify(list1).toLowerCase().includes("hash"), "hash não aparece");
const hashRow = store.db
  .prepare("SELECT token_hash FROM workspace_tokens WHERE id = ?").get(tok.id);
assert.ok(!JSON.stringify(list1).includes(hashRow.token_hash), "token_hash não vaza no GET");
ok("(i.a) POST emite zwt_ 1x; GET lista sem hash nem segredo (nome/escopos/criado)");

// O zwt_ passa no proxy ANTES de revogar.
assert.equal((await fetch(`${base}/p/nosign/ping`, { headers: zwt(tok.token) })).status, 200);
const listUsed = await (await fetch(`${base}/auth/workspace-tokens`, { headers: { cookie } })).json();
assert.ok(listUsed[0].last_used_at, "last_used_at preenchido após uso");

// DELETE revoga; 404 pra id alheio/inexistente e pra re-revogação.
assert.equal(
  (await fetch(`${base}/auth/workspace-tokens/naoexiste`, { method: "DELETE", headers: { cookie } })).status,
  404
);
assert.equal(
  (await fetch(`${base}/auth/workspace-tokens/${tok.id}`, { method: "DELETE" })).status,
  401, "DELETE exige sessão"
);
assert.equal(
  (await fetch(`${base}/auth/workspace-tokens/${tok.id}`, { method: "DELETE", headers: { cookie } })).status,
  200
);
assert.equal(
  (await fetch(`${base}/auth/workspace-tokens/${tok.id}`, { method: "DELETE", headers: { cookie } })).status,
  404, "re-revogar → 404"
);
const list2 = await (await fetch(`${base}/auth/workspace-tokens`, { headers: { cookie } })).json();
assert.ok(list2[0].revoked_at, "aparece como revogado na listagem");
// E o zwt_ revogado não passa mais no proxy.
assert.equal((await fetch(`${base}/p/nosign/ping`, { headers: zwt(tok.token) })).status, 401);
const revAudit = store.db.prepare("SELECT * FROM audit_log WHERE action = 'token.revoke'").all();
assert.equal(revAudit.length, 1);
assert.ok(!JSON.stringify(revAudit).includes(tok.token), "token não vaza no audit");
ok("(i.b) DELETE revoga (404 alheio/já-revogado) → zwt_ revogado dá 401 no proxy");

// Token novo, escopo total, pros testes de sign.
const t2 = await (await fetch(`${base}/auth/workspace-tokens`, {
  method: "POST", headers: { cookie, "content-type": "application/json" },
  body: JSON.stringify({ name: "ws total", scopes: ["*"] }),
})).json();

// ── (ii) sign appsecret_proof: proof = hmac(app_secret, access_token) ────
const r2 = await fetch(`${base}/p/metasign/me/adaccounts?fields=id`, { headers: zwt(t2.token) });
assert.equal(r2.status, 200);
let u = lastUrl();
assert.equal(u.pathname, "/v23.0/me/adaccounts", "api_base_url com path preservado");
assert.equal(u.searchParams.get("fields"), "id", "query original preservada");
assert.equal(u.searchParams.get("access_token"), "at-code-1", "token real na query (kind=query)");
assert.equal(u.searchParams.get("appsecret_proof"), proofRef("at-code-1"),
  "appsecret_proof = hex(hmac-sha256(app_secret, access_token))");
assert.equal(upstreamSeen.at(-1).headers.authorization, undefined, "sem Authorization no kind=query");
ok("(ii) sign → appsecret_proof correto injetado na query (recomputado à parte)");

// ── (iii) refresh-on-401 recalcula o proof com o TOKEN NOVO ──────────────
failNextWith401 = true;
const r3 = await fetch(`${base}/p/metasign/me/insights`, { headers: zwt(t2.token) });
assert.equal(r3.status, 200, "retry pós-refresh devolve 200");
assert.equal(refreshes, 1, "exatamente 1 refresh");
// Duas requests no upstream: a que tomou 401 (token velho) e o retry (token novo).
const insights = upstreamSeen.filter((s) => new URL(s.url, "http://x").pathname === "/v23.0/me/insights");
assert.equal(insights.length, 2, "1 tentativa + 1 retry");
const p0 = new URL(insights[0].url, "http://x").searchParams;
const p1 = new URL(insights[1].url, "http://x").searchParams;
assert.equal(p0.get("access_token"), "at-code-1");
assert.equal(p0.get("appsecret_proof"), proofRef("at-code-1"), "proof da 1ª tentativa = token velho");
assert.equal(p1.get("access_token"), "at-refresh-1");
assert.equal(p1.get("appsecret_proof"), proofRef("at-refresh-1"), "proof do retry = token novo");
assert.notEqual(p0.get("appsecret_proof"), p1.get("appsecret_proof"), "proof recalculado (valores diferentes)");
ok("(iii) refresh-on-401 → appsecret_proof recalculado com o token novo");

// ── (iv) provider sem sign → nenhum appsecret_proof ──────────────────────
const r4 = await fetch(`${base}/p/nosign/data?x=1`, { headers: zwt(t2.token) });
assert.equal(r4.status, 200);
u = lastUrl();
assert.equal(u.searchParams.get("appsecret_proof"), null, "sem sign → sem appsecret_proof");
assert.equal(u.searchParams.get("access_token"), null, "kind=bearer não põe token na query");
assert.equal(upstreamSeen.at(-1).headers.authorization, "Bearer at-code-2", "Bearer real no header");
ok("(iv) provider sem sign (bearer) → nenhum appsecret_proof, Bearer no header");

// ── segurança transversal: nem zwt_ nem app secret nunca vão pro upstream ─
const dump = JSON.stringify(upstreamSeen);
assert.ok(!dump.includes("zwt_"), "nenhum request upstream carrega zwt_");
assert.ok(!dump.includes(APP_SECRET), "app secret cru nunca vai pro upstream (só o HMAC)");
ok("zwt_ e app secret nunca atravessam pro upstream");

console.log(`\nPASS — ${passed} checks (tokens + appsecret_proof F3)`);
void admin;
server.close();
oauth.close();
upstream.close();
fs.rmSync(tmp, { recursive: true, force: true });
process.exit(0);
