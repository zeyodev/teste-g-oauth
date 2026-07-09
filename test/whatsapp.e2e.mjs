// E2E do WhatsApp Embedded Signup / coexistence (sem rede externa):
//   (A) authorize URL do pack `coexistence` carrega config_id + extras com
//       featureType=whatsapp_business_app_onboarding; o pack `cloud` carrega
//       extras com feature=whatsapp_embedded_signup (número novo).
//   (B) callback → descoberta Graph: debug_token → waba_id → /{waba}/phone_numbers
//       → phone_number_id, com appsecret_proof correto no phone_numbers. A
//       conexão dedup por waba_id (account_key) e grava metadata (número).
// Roda com `npm test`. Provider aponta pra um mock Graph local.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { mkCsrf } from "./helpers.mjs";

// ── env de teste ANTES de importar config ────────────────────────────────
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zkeys-wa-e2e-"));
process.env.ZKEYS_MASTER_KEY = crypto.randomBytes(32).toString("hex");
process.env.ZKEYS_AUTH_PEPPER = "pepper-de-teste";
process.env.ZKEYS_SESSION_SECRET = "session-secret-de-teste";
process.env.ZKEYS_INSECURE_COOKIE = "1";
process.env.ZKEYS_DB_PATH = path.join(tmp, "zkeys.db");
process.env.ZKEYS_PROVIDERS_DIR = path.join(tmp, "providers");

const APP_ID = "wa-app-id";
const APP_SECRET = "wa-app-secret";
const CONFIG_ID = "wa-config-123";
process.env.WHATSAPP_APP_ID = APP_ID;
process.env.WHATSAPP_APP_SECRET = APP_SECRET;
process.env.WHATSAPP_APP_CONFIG = CONFIG_ID;
process.env.WHATSAPP_WEBHOOK_VERIFY_TOKEN = "verify-de-teste";

const WABA_ID = "WABA_123";
const PHONE_ID = "PHONE_456";
const USER_TOKEN = "wa-user-token";

// ── mock Graph ─────────────────────────────────────────────────────────────
const seen = { proofOnPhones: null, debugAppToken: null };
const mock = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  const json = (o) => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify(o)); };

  if (req.method === "POST" && url.pathname === "/token") {
    let body = ""; req.on("data", (c) => (body += c));
    req.on("end", () => json({ access_token: USER_TOKEN, token_type: "bearer" }));
    return;
  }
  if (req.method === "GET" && url.pathname === "/me") {
    return json({ id: "fb-user-id", name: "FB User" });
  }
  if (req.method === "GET" && url.pathname === "/debug_token") {
    seen.debugAppToken = url.searchParams.get("access_token");
    return json({ data: { granular_scopes: [
      { scope: "whatsapp_business_messaging", target_ids: [WABA_ID] },
      { scope: "whatsapp_business_management", target_ids: [WABA_ID] },
    ] } });
  }
  if (req.method === "GET" && url.pathname === `/${WABA_ID}/phone_numbers`) {
    seen.proofOnPhones = url.searchParams.get("appsecret_proof");
    return json({ data: [
      { id: PHONE_ID, display_phone_number: "+55 11 99999-0000", verified_name: "Minha Empresa" },
    ] });
  }
  res.statusCode = 404; res.end();
});
await new Promise((r) => mock.listen(0, r));
const mockBase = `http://localhost:${mock.address().port}`;

// provider whatsapp-like apontando pro mock (mesma forma do providers/whatsapp.json).
fs.mkdirSync(process.env.ZKEYS_PROVIDERS_DIR, { recursive: true });
fs.writeFileSync(path.join(process.env.ZKEYS_PROVIDERS_DIR, "whatsapp.json"), JSON.stringify({
  name: "whatsapp", displayName: "WhatsApp (Cloud API)",
  authorize_url: `${mockBase}/authorize`, token_url: `${mockBase}/token`,
  profile_url: `${mockBase}/me`, profile_url_params: { fields: "id,name" },
  profile_map: { externalId: "id", name: "name" },
  api_base_url: mockBase,
  auth_injection: { kind: "bearer" }, sign: "appsecret_proof",
  pkce: false, auth_token_in_header: false,
  client_id_env: "WHATSAPP_APP_ID", client_secret_env: "WHATSAPP_APP_SECRET",
  webhook_verify_token_env: "WHATSAPP_WEBHOOK_VERIFY_TOKEN",
  authorize_extra_env: { config_id: "WHATSAPP_APP_CONFIG" },
  account_discovery: { kind: "whatsapp", scope: "whatsapp_business_management" },
  packs: {
    cloud: {
      label: "novo", scopes: ["whatsapp_business_messaging"],
      authorize_extra: { extras: JSON.stringify({ feature: "whatsapp_embedded_signup", sessionInfoVersion: "3" }) },
    },
    coexistence: {
      label: "existente", scopes: ["whatsapp_business_messaging"],
      authorize_extra: { extras: JSON.stringify({ featureType: "whatsapp_business_app_onboarding", sessionInfoVersion: "3" }) },
    },
  },
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
const csrf = await mkCsrf(base, cookie);

// ── (A) authorize URL por modo ─────────────────────────────────────────────
async function authorizeUrlFor(pack) {
  const r = await fetch(`${base}/auth/whatsapp/start?pack=${pack}`, { headers: { cookie }, redirect: "manual" });
  assert.equal(r.status, 302);
  return new URL(r.headers.get("location"));
}

const coex = await authorizeUrlFor("coexistence");
assert.equal(coex.searchParams.get("config_id"), CONFIG_ID, "config_id no authorize");
const coexExtras = JSON.parse(coex.searchParams.get("extras"));
assert.equal(coexExtras.featureType, "whatsapp_business_app_onboarding", "coexistence → featureType");
ok("start coexistence → config_id + extras.featureType");

const cloud = await authorizeUrlFor("cloud");
const cloudExtras = JSON.parse(cloud.searchParams.get("extras"));
assert.equal(cloudExtras.feature, "whatsapp_embedded_signup", "cloud → feature (número novo)");
assert.equal(cloudExtras.featureType, undefined, "cloud NÃO manda featureType");
ok("start cloud → extras.feature (número novo)");

// ── (B) callback → descoberta Graph ────────────────────────────────────────
const startCoex = await fetch(`${base}/auth/whatsapp/start?pack=coexistence`, { headers: { cookie }, redirect: "manual" });
const state = new URL(startCoex.headers.get("location")).searchParams.get("state");
const cb = await fetch(`${base}/auth/whatsapp/callback?code=abc&state=${state}`, { headers: { cookie } });
assert.equal(cb.status, 200);
assert.match(await cb.text(), /Conectado/);
ok("callback coexistence → 200");

// appsecret_proof correto no /phone_numbers (HMAC do user token com o app secret)
const expectedProof = crypto.createHmac("sha256", APP_SECRET).update(USER_TOKEN).digest("hex");
assert.equal(seen.proofOnPhones, expectedProof, "appsecret_proof correto no phone_numbers");
assert.equal(seen.debugAppToken, `${APP_ID}|${APP_SECRET}`, "debug_token usa o app access token");
ok("descoberta usa app token + appsecret_proof");

// conexão: account_key = waba_id, metadata com phone_number_id
const conns = await (await fetch(`${base}/connections`, { headers: { cookie } })).json();
assert.equal(conns.length, 1);
const conn = conns[0];
assert.equal(conn.account_key, WABA_ID, "dedup por waba_id");
assert.equal(conn.display_name, "Minha Empresa", "display_name = verified_name");
assert.equal(conn.metadata.phone_number_id, PHONE_ID, "metadata.phone_number_id");
assert.equal(conn.metadata.waba_id, WABA_ID, "metadata.waba_id");
assert.ok(!JSON.stringify(conns).includes(USER_TOKEN), "token NÃO vaza na listagem");
ok("conexão dedup por waba_id + metadata com phone_number_id");

console.log(`\nwhatsapp.e2e: ${passed} passos ✓`);
server.close();
mock.close();
