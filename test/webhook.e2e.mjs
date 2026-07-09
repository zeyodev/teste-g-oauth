// E2E do webhook receiver (hook instagram_webhook), sem rede externa:
//   (A) GET handshake — verify_token certo devolve hub.challenge (200 texto);
//       token errado → 403; mode != subscribe → 403.
//   (B) POST assinatura — X-Hub-Signature-256 válida (HMAC do body CRU com o
//       app secret) → 200 + audita webhook.recv; assinatura ausente/errada → 403.
//   (C) rawBody — a validação usa os BYTES exatos do corpo (reserializar o
//       req.body quebraria o HMAC): mandamos um JSON com espaçamento incomum e
//       a assinatura ainda bate porque HMAC é sobre o que enviamos.
// Roda com `npm test`.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));

// ── env de teste ANTES de importar config ────────────────────────────────
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zkeys-webhook-e2e-"));
process.env.ZKEYS_MASTER_KEY = crypto.randomBytes(32).toString("hex");
process.env.ZKEYS_AUTH_PEPPER = "pepper-de-teste";
process.env.ZKEYS_SESSION_SECRET = "session-secret-de-teste";
process.env.ZKEYS_INSECURE_COOKIE = "1";
process.env.ZKEYS_DB_PATH = path.join(tmp, "zkeys.db");
process.env.ZKEYS_PROVIDERS_DIR = path.join(tmp, "providers");

const APP_SECRET = "ig-app-secret-de-teste";
const VERIFY_TOKEN = "verify-token-de-teste-123";
process.env.IG_APP_ID = "ig-app-id";
process.env.IG_APP_SECRET = APP_SECRET;
process.env.IG_WEBHOOK_VERIFY_TOKEN = VERIFY_TOKEN;

const { loadConfig } = await import("../config.js");
const { createApp } = await import("../index.js");

// provider instagram-like apontando pras envs de teste (o hook real é o mesmo).
fs.mkdirSync(process.env.ZKEYS_PROVIDERS_DIR, { recursive: true });
fs.writeFileSync(path.join(process.env.ZKEYS_PROVIDERS_DIR, "instagram.json"), JSON.stringify({
  name: "instagram", displayName: "Instagram",
  authorize_url: "http://x/authorize", token_url: "http://x/token",
  api_base_url: "http://x", auth_injection: { kind: "query", param: "access_token" },
  pkce: false,
  client_id_env: "IG_APP_ID", client_secret_env: "IG_APP_SECRET",
  webhook_verify_token_env: "IG_WEBHOOK_VERIFY_TOKEN",
  packs: { manage: { label: "Manage", scopes: ["instagram_business_basic"] } },
  extensions: ["graph_webhook"],
}));

const config = loadConfig();
config.publicBaseUrl = "http://localhost:0";
const { app, store } = createApp(config);
const server = app.listen(0);
await new Promise((r) => server.on("listening", r));
const base = `http://localhost:${server.address().port}`;

let passed = 0;
const ok = (name) => { passed++; console.log(`  ✓ ${name}`); };

console.log("webhook.e2e:");

// ═══ (A) GET handshake ════════════════════════════════════════════════════
{
  const q = new URLSearchParams({
    "hub.mode": "subscribe", "hub.verify_token": VERIFY_TOKEN, "hub.challenge": "1234567890",
  });
  const r = await fetch(`${base}/auth/instagram/webhook?${q}`);
  assert.equal(r.status, 200);
  assert.equal((await r.text()), "1234567890");
  ok("GET verify_token correto → 200 + echo do hub.challenge");
}
{
  const q = new URLSearchParams({
    "hub.mode": "subscribe", "hub.verify_token": "errado", "hub.challenge": "x",
  });
  const r = await fetch(`${base}/auth/instagram/webhook?${q}`);
  assert.equal(r.status, 403);
  ok("GET verify_token errado → 403");
}
{
  const q = new URLSearchParams({
    "hub.mode": "unsubscribe", "hub.verify_token": VERIFY_TOKEN, "hub.challenge": "x",
  });
  const r = await fetch(`${base}/auth/instagram/webhook?${q}`);
  assert.equal(r.status, 403);
  ok("GET mode != subscribe → 403");
}

// ═══ (B)/(C) POST assinatura ══════════════════════════════════════════════
function sign(raw) {
  return "sha256=" + crypto.createHmac("sha256", APP_SECRET).update(raw).digest("hex");
}
{
  // JSON com espaçamento incomum: HMAC é sobre ESTES bytes, não sobre um
  // re-serialize do parse — prova que rawBody é o que vale.
  const raw = '{"object":"instagram",  "entry":[{"id":"1"},{"id":"2"}]}';
  const r = await fetch(`${base}/auth/instagram/webhook`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-hub-signature-256": sign(raw) },
    body: raw,
  });
  assert.equal(r.status, 200);
  ok("POST assinatura válida (body cru c/ espaçamento incomum) → 200");
}
{
  const raw = '{"object":"instagram","entry":[]}';
  const r = await fetch(`${base}/auth/instagram/webhook`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-hub-signature-256": "sha256=deadbeef" },
    body: raw,
  });
  assert.equal(r.status, 403);
  ok("POST assinatura errada → 403");
}
{
  const raw = '{"object":"instagram","entry":[]}';
  const r = await fetch(`${base}/auth/instagram/webhook`, {
    method: "POST", headers: { "content-type": "application/json" }, body: raw,
  });
  assert.equal(r.status, 403);
  ok("POST sem header de assinatura → 403");
}

// audit: um webhook.recv (a válida) e dois webhook.reject foram gravados.
{
  const rows = store.db.prepare(
    "SELECT action, COUNT(*) n FROM audit_log WHERE action LIKE 'webhook.%' GROUP BY action"
  ).all();
  const byAction = Object.fromEntries(rows.map((r) => [r.action, r.n]));
  assert.equal(byAction["webhook.recv"], 1);
  assert.equal(byAction["webhook.reject"], 2);
  ok("audit: 1 webhook.recv + 2 webhook.reject");
}

server.close();
console.log(`\nwebhook.e2e: ${passed} asserções OK`);
