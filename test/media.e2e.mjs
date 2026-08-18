// E2E do download de mídia do Meta (F-extra, ver proxy/media.js), sem rede
// externa: um mock Graph devolve {url, mime_type} pra GET /{media_id} e o
// binário no /lookaside/* — que só responde com o token REAL da conexão no
// header Authorization (o mesmo gate do lookaside.fbsbx.com de verdade). O
// workspace chama com um zwt_ e recebe os BYTES de volta; o zwt_ nunca chega
// no upstream e o token real nunca volta na resposta.
//
// Roda com `npm test`.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { mkCsrf } from "./helpers.mjs";

// ── env de teste ANTES de importar config ────────────────────────────────
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zkeys-media-e2e-"));
process.env.ZKEYS_MASTER_KEY = crypto.randomBytes(32).toString("hex");
process.env.ZKEYS_AUTH_PEPPER = "pepper-de-teste";
process.env.ZKEYS_SESSION_SECRET = "session-secret-de-teste";
process.env.ZKEYS_INSECURE_COOKIE = "1";
process.env.ZKEYS_DB_PATH = path.join(tmp, "zkeys.db");
process.env.ZKEYS_PROVIDERS_DIR = path.join(tmp, "providers");
process.env.MOCKMEDIA_CLIENT_ID = "mockmedia-client-id";
process.env.MOCKMEDIA_CLIENT_SECRET = "mockmedia-client-secret";

const { loadConfig } = await import("../config.js");
const { createApp } = await import("../index.js");
const { createPasswords } = await import("../lib/passwords.js");
const { createCrypto } = await import("../lib/crypto.js");

// ── mock Graph (token + metadata + lookaside gateado por Bearer) ─────────
let codeExchanges = 0;
const seen = { metadata: [], lookaside: [] };
const MEDIA_ID = "1816883622629273";
const BIN = Buffer.from("ID3\x04OGGS\x00fake-ogg-bytes", "utf8"); // bytes de teste

const graph = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  const p = url.pathname.replace(/^\/v\d+\.\d+/, ""); // base versionada (como o Graph real)
  const json = (o) => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify(o)); };

  if (req.method === "POST" && p === "/token") {
    let body = ""; req.on("data", (c) => (body += c));
    req.on("end", () => {
      const form = new URLSearchParams(body);
      codeExchanges++;
      res.end(JSON.stringify({
        access_token: `at-real-${codeExchanges}`,
        refresh_token: `rt-${codeExchanges}`,
        expires_in: 3600,
      }));
    });
    return;
  }
  if (req.method === "GET" && p === "/me") {
    return json({ id: "fb-user", name: "FB" });
  }
  // passo 1 — metadata: só responde se o Bearer REAL + appsecret_proof vierem.
  if (req.method === "GET" && p === `/${MEDIA_ID}`) {
    seen.metadata.push({ auth: req.headers.authorization, proof: url.searchParams.get("appsecret_proof") });
    if (req.headers.authorization !== "Bearer at-real-1") {
      res.statusCode = 401;
      return json({ error: "token inválido" });
    }
    const expectedProof = crypto.createHmac("sha256", process.env.MOCKMEDIA_CLIENT_SECRET)
      .update("at-real-1").digest("hex");
    assert.equal(url.searchParams.get("appsecret_proof"), expectedProof, "appsecret_proof correto");
    return json({ url: `http://localhost:${graph.address().port}/lookaside/${MEDIA_ID}`, mime_type: "audio/ogg", file_size: BIN.length });
  }
  // passo 2 — lookaside: gate igual ao de produção (exige o token da Meta).
  if (req.method === "GET" && p === `/lookaside/${MEDIA_ID}`) {
    seen.lookaside.push({ auth: req.headers.authorization });
    if (req.headers.authorization !== "Bearer at-real-1") {
      res.statusCode = 401;
      return json({ error: "no token" });
    }
    res.setHeader("content-type", "audio/ogg; codecs=opus");
    return res.end(BIN);
  }
  res.statusCode = 404; res.end();
});
await new Promise((r) => graph.listen(0, r));

// ── provider media-like (Strategy em dados: media_download:true) ─────────
fs.mkdirSync(process.env.ZKEYS_PROVIDERS_DIR, { recursive: true });
const base = `http://localhost:${graph.address().port}`;
fs.writeFileSync(path.join(process.env.ZKEYS_PROVIDERS_DIR, "mockmedia.json"), JSON.stringify({
  name: "mockmedia", displayName: "Mock Media",
  authorize_url: `${base}/authorize`, token_url: `${base}/token`,
  profile_url: `${base}/me`, profile_map: { externalId: "id", name: "name" },
  api_base_url: `${base}/v23.0`,
  auth_injection: { kind: "bearer" }, sign: "appsecret_proof",
  media_download: true, pkce: false, auth_token_in_header: false,
  client_id_env: "MOCKMEDIA_CLIENT_ID", client_secret_env: "MOCKMEDIA_CLIENT_SECRET",
  packs: { basico: { label: "Básico", scopes: ["whatsapp_business_messaging"] } },
}));

const config = loadConfig();
config.publicBaseUrl = "http://localhost:0";
const { app, store } = createApp(config);
const server = app.listen(0);
await new Promise((r) => server.on("listening", r));
const appBase = `http://localhost:${server.address().port}`;

const passwords = createPasswords(config.pepper);
const cryptoBox = createCrypto(config.masterKey);
store.users.create({
  email: "admin@test.dev",
  passwordHash: await passwords.hash("senha-forte-123"),
  role: "admin",
});

const login = await fetch(`${appBase}/auth/login`, {
  method: "POST", headers: { "content-type": "application/json" },
  body: JSON.stringify({ email: "admin@test.dev", password: "senha-forte-123" }),
});
const cookie = login.headers.get("set-cookie").split(";")[0];
const csrf = await mkCsrf(appBase, cookie);

const start = await fetch(`${appBase}/auth/mockmedia/start?pack=basico`, {
  headers: { cookie }, redirect: "manual",
});
const state = new URL(start.headers.get("location")).searchParams.get("state");
assert.equal(
  (await fetch(`${appBase}/auth/mockmedia/callback?code=abc&state=${state}`, { headers: { cookie } })).status,
  200
);

const issue = await fetch(`${appBase}/auth/workspace-tokens`, {
  method: "POST", headers: csrf.headers(),
  body: JSON.stringify({ name: "ws media", scopes: ["mockmedia"] }),
});
assert.equal(issue.status, 201);
const { token: zwt } = await issue.json();

let passed = 0;
const ok = (name) => { passed++; console.log(`  ✓ ${name}`); };

// ── download: zwt_ → pipeline → binário de volta ─────────────────────────
const dl = await fetch(`${appBase}/p/mockmedia/media/${MEDIA_ID}/download`, {
  headers: { authorization: `Bearer ${zwt}` },
});
if (dl.status !== 200) {
  const txt = await dl.text();
  console.log("DEBUG dl:", dl.status, txt.slice(0, 300));
  console.log("DEBUG connections:", JSON.stringify(
    (await (await fetch(`${appBase}/connections`, { headers: { cookie } })).json()).map(c => ({ p: c.provider, d: c.display_name, account_key: c.account_key }))
  ));
}
assert.equal(dl.status, 200);
assert.equal(dl.headers.get("content-type"), "audio/ogg; codecs=opus");
assert.equal(dl.headers.get("x-meta-mime-type"), "audio/ogg");
assert.equal(dl.headers.get("x-meta-file-size"), String(BIN.length));
const body = Buffer.from(await dl.arrayBuffer());
assert.ok(body.equals(BIN), "binário chega byte a byte");
ok("GET /p/mockmedia/media/{id}/download → 200, mime real, binário íntegro");

// o upstream viu o token REAL (Bearer at-real-1), nunca o zwt_
assert.equal(seen.metadata[0].auth, "Bearer at-real-1", "metadata com token real");
assert.equal(seen.lookaside[0].auth, "Bearer at-real-1", "lookaside com token real");
const tudo = JSON.stringify(seen);
assert.ok(!tudo.includes(zwt), "zwt_ nunca chega no upstream");
assert.ok(!dl.headers.get("x-real-token"), "token real não volta no response");
ok("token real injetado nos 2 hops; zwt_ nunca vaza; token real não vaza na resposta");

// ── gates: sem auth / provider sem media_download / escopo errado ────────
assert.equal((await fetch(`${appBase}/p/mockmedia/media/${MEDIA_ID}/download`)).status, 401);
ok("sem zwt_ → 401");

fs.writeFileSync(path.join(process.env.ZKEYS_PROVIDERS_DIR, "mockplain.json"), JSON.stringify({
  name: "mockplain", displayName: "Sem media",
  authorize_url: `${base}/authorize`, token_url: `${base}/token`,
  profile_url: `${base}/me`, profile_map: { externalId: "id", name: "name" },
  api_base_url: `${base}/v23.0`,
  auth_injection: { kind: "bearer" }, pkce: false, auth_token_in_header: false,
  client_id_env: "MOCKMEDIA_CLIENT_ID", client_secret_env: "MOCKMEDIA_CLIENT_SECRET",
  packs: { basico: { label: "Básico", scopes: ["x"] } },
}));
const issueAll = await fetch(`${appBase}/auth/workspace-tokens`, {
  method: "POST", headers: csrf.headers(),
  body: JSON.stringify({ name: "ws total", scopes: ["*"] }),
});
const { token: zwtAll } = await issueAll.json();
assert.equal(
  (await fetch(`${appBase}/p/mockplain/media/${MEDIA_ID}/download`, { headers: { authorization: `Bearer ${zwtAll}` } })).status,
  404,
  "provider sem media_download → 404"
);
ok("provider sem media_download → 404");

console.log(`\nmedia.e2e: ${passed} passos ✓`);
server.close();
graph.close();
fs.rmSync(tmp, { recursive: true, force: true });
process.exit(0);
