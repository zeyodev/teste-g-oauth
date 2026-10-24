// E2E do Instagram (login direto) — F2 do PLAN-instagram-automation, sem rede
// externa:
//   (A) callback → profile em graph.instagram.com/me (user_id/username) vira
//       connection com account_key = user_id (IGSID — o mesmo id que a Meta
//       manda em entry[].id dos webhooks).
//   (B) setup-webhook (Bearer zwt_): assina object=instagram no nível do app
//       (POST /{app_id}/subscriptions, com verify_token do env) + grava
//       webhook_forward_url na connection; webhook-status reflete o estado.
//   (C) webhook POST assinado (X-Hub-Signature-256) com entry.id = user_id é
//       ROTEADO pra org (forward no mock receiver) — e entry desconhecido não.
// Roda com `npm test`. Provider aponta pra um mock Graph local.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { mkCsrf } from "./helpers.mjs";

// ── env de teste ANTES de importar config ────────────────────────────────
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zkeys-ig-e2e-"));
process.env.ZKEYS_MASTER_KEY = crypto.randomBytes(32).toString("hex");
process.env.ZKEYS_AUTH_PEPPER = "pepper-de-teste";
process.env.ZKEYS_SESSION_SECRET = "session-secret-de-teste";
process.env.ZKEYS_INSECURE_COOKIE = "1";
process.env.ZKEYS_DB_PATH = path.join(tmp, "zkeys.db");
process.env.ZKEYS_PROVIDERS_DIR = path.join(tmp, "providers");

const APP_ID = "ig-app-id";
const APP_SECRET = "ig-app-secret";
const VERIFY_TOKEN = "verify-ig-de-teste";
process.env.INSTAGRAM_APP_ID = APP_ID;
process.env.INSTAGRAM_APP_SECRET = APP_SECRET;
process.env.INSTAGRAM_WEBHOOK_VERIFY_TOKEN = VERIFY_TOKEN;

const IG_USER_ID = "17841400000000001"; // user_id (IGSID) da conta profissional
const IG_USERNAME = "marquinhos.duo";
const SHORT_TOKEN = "ig-short-token";
const LONG_TOKEN = "ig-long-token";
// ── mock Graph ─────────────────────────────────────────────────────────────
const seen = { subscriptions: null };
const mock = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  const json = (o) => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify(o)); };

  if (req.method === "POST" && url.pathname === "/token") {
    return json({ access_token: SHORT_TOKEN, token_type: "bearer" });
  }
  if (req.method === "GET" && url.pathname === "/oauth/access_token"
      && url.searchParams.get("grant_type") === "ig_exchange_token") {
    seen.exchangeClientSecret = url.searchParams.get("client_secret");
    return json({ access_token: LONG_TOKEN, token_type: "bearer", expires_in: 5184000 });
  }
  if (req.method === "GET" && url.pathname === "/me") {
    return json({ user_id: IG_USER_ID, username: IG_USERNAME, name: "Maurício" });
  }
  if (req.method === "POST" && url.pathname === `/${APP_ID}/subscriptions`) {
    seen.subscriptions = Object.fromEntries(url.searchParams);
    return json({ success: true });
  }
  if (req.method === "GET" && url.pathname === `/${APP_ID}/subscriptions`) {
    return json({ data: [
      { object: "instagram", callback_url: seen.subscriptions?.callback_url, active: true,
        fields: (seen.subscriptions?.fields || "").split(",").filter(Boolean).map((name) => ({ name })) },
    ] });
  }
  res.statusCode = 404; res.end();
});
await new Promise((r) => mock.listen(0, r));
const mockBase = `http://localhost:${mock.address().port}`;

// ── mock org (receiver dos forwards) ──────────────────────────────────────
const org = { events: [] };
const orgServer = http.createServer((req, res) => {
  if (req.method === "POST" && req.url === "/api/webhooks/instagram") {
    let body = ""; req.on("data", (c) => (body += c));
    req.on("end", () => {
      org.events.push({ body: JSON.parse(body), provider: req.headers["x-zkeys-webhook"] });
      res.end("ok");
    });
    return;
  }
  res.statusCode = 404; res.end();
});
await new Promise((r) => orgServer.listen(0, r));
const orgBase = `http://localhost:${orgServer.address().port}`;

// ── app zkeys com provider instagram-like (mesma forma do instagram.json) ──
fs.mkdirSync(process.env.ZKEYS_PROVIDERS_DIR, { recursive: true });
fs.writeFileSync(path.join(process.env.ZKEYS_PROVIDERS_DIR, "instagram.json"), JSON.stringify({
  name: "instagram", displayName: "Instagram",
  authorize_url: `${mockBase}/authorize`, token_url: `${mockBase}/token`,
  profile_url: `${mockBase}/me`, profile_url_params: { fields: "user_id,username,name" },
  profile_map: { externalId: "user_id", name: "username" },
  api_base_url: mockBase,
  auth_injection: { kind: "query", param: "access_token" },
  sign: "appsecret_proof",
  pkce: false, auth_token_in_header: false,
  client_id_env: "INSTAGRAM_APP_ID", client_secret_env: "INSTAGRAM_APP_SECRET",
  webhook_verify_token_env: "INSTAGRAM_WEBHOOK_VERIFY_TOKEN",
  long_lived_exchange: {
    url: `${mockBase}/oauth/access_token`, grant_type: "ig_exchange_token",
    token_param: "access_token", send_client_id: false,
  },
  self_refresh: {
    url: `${mockBase}/oauth/access_token`, grant_type: "ig_refresh_token",
    token_param: "access_token", send_client_id: false,
  },
  packs: { manage: { label: "Gerenciar", scopes: ["instagram_business_basic"] } },
  extensions: ["graph_webhook"],
}));

const { loadConfig } = await import("../config.js");
const { createApp } = await import("../index.js");
const { createPasswords } = await import("../lib/passwords.js");

const config = loadConfig();
config.publicBaseUrl = "http://localhost:0";
const { app, store } = createApp(config);
const server = app.listen(0);
await new Promise((r) => server.on("listening", r));
const base = `http://localhost:${server.address().port}`;

const passwords = createPasswords(config.pepper);
store.users.create({
  email: "admin@test.dev",
  passwordHash: await passwords.hash("senha-forte-123"),
  role: "admin",
});

let passed = 0;
const ok = (name) => { passed++; console.log(`  ✓ ${name}`); };

const login = await fetch(`${base}/auth/login`, {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ email: "admin@test.dev", password: "senha-forte-123" }),
});
const cookie = login.headers.get("set-cookie").split(";")[0];

// ── (A) callback → connection com account_key = user_id ───────────────────
const start = await fetch(`${base}/auth/instagram/start?pack=manage`, { headers: { cookie }, redirect: "manual" });
assert.equal(start.status, 302);
const state = new URL(start.headers.get("location")).searchParams.get("state");
const cb = await fetch(`${base}/auth/instagram/callback?code=abc&state=${state}`, { headers: { cookie } });
assert.equal(cb.status, 200);
assert.match(await cb.text(), /Conectado/);
ok("callback → 200 (Conectado)");

const conns = await (await fetch(`${base}/connections`, { headers: { cookie } })).json();
assert.equal(conns.length, 1);
assert.equal(seen.exchangeClientSecret, APP_SECRET, "ig_exchange_token usa client_secret");
assert.equal(conns[0].account_key, IG_USER_ID, "account_key = user_id (roteável por entry.id)");
assert.equal(conns[0].display_name, IG_USERNAME, "display_name = username");
assert.ok(!JSON.stringify(conns).includes(LONG_TOKEN), "token NÃO vaza na listagem");
ok("connection com account_key=user_id + username");

// ── (B) setup-webhook (Bearer zwt_) ───────────────────────────────────────
const wt = await (await fetch(`${base}/auth/workspace-tokens`, {
  method: "POST", headers: await mkCsrfHeaders(),
  body: JSON.stringify({ name: "ws", scopes: ["instagram"] }),
})).json();
assert.ok(wt.token, "zwt_ emitido");

async function mkCsrfHeaders() {
  const h = await mkCsrf(base, cookie);
  return h.headers();
}
const setup = await fetch(`${base}/auth/instagram/setup-webhook`, {
  method: "POST",
  headers: { authorization: `Bearer ${wt.token}`, "content-type": "application/json" },
  body: JSON.stringify({ forward_url: `${orgBase}/api/webhooks/instagram` }),
});
assert.equal(setup.status, 200);
const setupData = await setup.json();
assert.equal(setupData.steps.app_subscription.ok, true, "app_subscription ok");
assert.equal(setupData.steps.forward_url.ok, true, "forward_url ok");
assert.equal(setupData.account_key, IG_USER_ID);
assert.equal(seen.subscriptions.object, "instagram", "object=instagram");
assert.equal(seen.subscriptions.verify_token, VERIFY_TOKEN, "verify_token do env no subscribe");
assert.ok(seen.subscriptions.callback_url.includes("/auth/instagram/webhook"), "callback_url do receiver");
assert.equal(seen.subscriptions.access_token, `${APP_ID}|${APP_SECRET}`, "subscribe usa app access token");
ok("setup-webhook: assina app-level + grava forward_url");

const status = await (await fetch(`${base}/auth/instagram/webhook-status`, {
  headers: { authorization: `Bearer ${wt.token}` },
})).json();
assert.equal(status.app_subscribed, true, "status: app_subscribed");
assert.ok(status.fields.includes("messages"), "status: campos assinados");
assert.equal(status.connections.length, 1);
assert.equal(status.connections[0].forward_url, `${orgBase}/api/webhooks/instagram`, "status: forward_url da connection");
ok("webhook-status reflete assinatura + forward_url");

// ── (C) webhook assinado → roteado pra org ────────────────────────────────
function signedPost(bodyObj) {
  const raw = JSON.stringify(bodyObj);
  const sig = "sha256=" + crypto.createHmac("sha256", APP_SECRET).update(raw).digest("hex");
  return fetch(`${base}/auth/instagram/webhook`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-hub-signature-256": sig },
    body: raw,
  });
}

const msg = { object: "instagram", entry: [{ id: IG_USER_ID, time: 1, messaging: [{ sender: { id: "seguidor" }, message: { text: "oi" } }] }] };
const r1 = await signedPost(msg);
assert.equal(r1.status, 200);
await new Promise((r) => setTimeout(r, 50)); // forward é background
assert.equal(org.events.length, 1, "DM roteada pra org");
assert.equal(org.events[0].provider, "instagram");
assert.equal(org.events[0].body.entry[0].id, IG_USER_ID);
ok("webhook entry.id=user_id → forward pra org");

const outro = { object: "instagram", entry: [{ id: "17841400000009999", time: 1, messaging: [] }] };
await signedPost(outro);
await new Promise((r) => setTimeout(r, 50));
assert.equal(org.events.length, 1, "entry de OUTRA conta não roteia");
ok("entry desconhecido → sem forward");

console.log(`\ninstagram.e2e: ${passed} passos ✓`);
server.close();
mock.close();
orgServer.close();
