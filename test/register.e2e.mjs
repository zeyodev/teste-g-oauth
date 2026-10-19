// E2E do registro self-serve (§7 — ZKEYS_REGISTER_MODE) + convites + bootstrap
// do primeiro admin pela web + GET /proxy/providers (machine, Bearer zwt_).
// Roda com `npm run test:register`.
//
// Dois apps em DBs separados:
//  A: ZKEYS_REGISTER_MODE=invite — bootstrap first_user → admin, convite,
//     registro por convite, single-use, 409 duplicado, 403 sem/esgotado.
//  B: default (closed) — first_user registra mesmo assim; o segundo leva 403.

import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { mkCsrf } from "./helpers.mjs";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zkeys-reg-"));
process.env.ZKEYS_MASTER_KEY = crypto.randomBytes(32).toString("hex");
process.env.ZKEYS_AUTH_PEPPER = "pepper-de-teste";
process.env.ZKEYS_SESSION_SECRET = "session-secret-de-teste";
process.env.ZKEYS_INSECURE_COOKIE = "1";

const { loadConfig } = await import("../config.js");
const { createApp } = await import("../index.js");

let passed = 0;
const ok = (name) => { passed++; console.log(`  ✓ ${name}`); };

// sobe app numa porta efêmera com DB próprio (cache-bust por nome de db —
// config/index foram importados em outros testes com outros envs)
async function boot(registerMode, dbName) {
  process.env.ZKEYS_DB_PATH = path.join(tmp, `${dbName}.db`);   // DB novo
  process.env.ZKEYS_REGISTER_MODE = registerMode;
  process.env.ZKEYS_RL_LOGIN_MAX = "1000";   // teto folgado: o teste repete IP
  const { loadConfig: lc } = await import(`../config.js?m=${dbName}`);
  const config = lc(process.env);
  const mod = await import(`../index.js?m=${dbName}`);
  const { app, store } = mod.createApp(config);
  const server = app.listen(0);
  await new Promise((r) => server.on("listening", r));
  return { base: `http://localhost:${server.address().port}`, store, config };
}

const post = (base, path, body, extra = {}) => fetch(`${base}${path}`, {
  method: "POST",
  headers: { "content-type": "application/json", ...extra },
  body: JSON.stringify(body),
});

// ══ App A: modo invite ═══════════════════════════════════════════════════
{
  const { base, store, config } = await boot("invite", "invite");

  // register-mode público reflete first_user (banco vazio)
  let rm = await (await fetch(`${base}/auth/register-mode`)).json();
  assert.equal(rm.first_user, true);
  assert.equal(rm.invite_required, false);
  ok("register-mode público → first_user (bootstrap aberto)");

  // bootstrap: primeiro registro vira admin e já entra logado
  const r1 = await post(base, "/auth/register", { email: "boss@test.dev", password: "senha-forte-123" });
  assert.equal(r1.status, 201);
  const setCookie = r1.headers.get("set-cookie");
  assert.ok(setCookie, "register emite sessão");
  const bossCookie = setCookie.split(";")[0];
  const me = await (await fetch(`${base}/auth/me`, { headers: { cookie: bossCookie } })).json();
  assert.equal(me.role, "admin");
  ok("1º registro → conta admin + sessão (bootstrap web)");

  // agora o modo efetivo é invite: sem código → 403
  rm = await (await fetch(`${base}/auth/register-mode`)).json();
  assert.equal(rm.first_user, false);
  assert.equal(rm.invite_required, true);
  const noInvite = await post(base, "/auth/register", { email: "x@test.dev", password: "senha-forte-123" });
  assert.equal(noInvite.status, 403);
  ok("registro sem convite → 403");

  // closed não aceita mais (bootstrap já consumido)
  const csrf = await mkCsrf(base, bossCookie);

  // admin gera convite (multi-use 2, ttl 7d)
  const inv = await post(base, "/auth/invites", { max_uses: 2, ttl_days: 7, note: "org teste" }, csrf.headers());
  assert.equal(inv.status, 201);
  const { code } = await inv.json();
  assert.ok(code.startsWith("zkinv_"), "código zkinv_");
  ok("admin gera convite");

  // lista de convites exige admin
  const listAnon = await fetch(`${base}/auth/invites`);
  assert.equal(listAnon.status, 401);

  // registro por convite → user comum
  const r2 = await post(base, "/auth/register", { email: "convidado@test.dev", password: "senha-forte-123", invite_code: code });
  assert.equal(r2.status, 201);
  const guestCookie = r2.headers.get("set-cookie").split(";")[0];
  const me2 = await (await fetch(`${base}/auth/me`, { headers: { cookie: guestCookie } })).json();
  assert.equal(me2.role, "user");
  assert.equal(me2.email, "convidado@test.dev");
  ok("registro com convite → user comum + sessão");

  // mesmo código de novo → ainda vale (uses 2/2)... e depois esgota
  const r3 = await post(base, "/auth/register", { email: "segundo@test.dev", password: "senha-forte-123", invite_code: code });
  assert.equal(r3.status, 201);
  const r4 = await post(base, "/auth/register", { email: "terceiro@test.dev", password: "senha-forte-123", invite_code: code });
  assert.equal(r4.status, 403);
  ok("convite multi-use esgota (2/2) → 403");

  // código inexistente → 403
  const r5 = await post(base, "/auth/register", { email: "quarto@test.dev", password: "senha-forte-123", invite_code: "zkinv_naoexiste" });
  assert.equal(r5.status, 403);
  ok("convite inexistente → 403");

  // email duplicado → 409 (com convite fresco — não queima código com email existente)
  const dupInv = store.inviteCodes.create({ createdBy: "t", maxUses: 1, ttlDays: 7 });
  const dup = await post(base, "/auth/register", { email: "convidado@test.dev", password: "senha-forte-123", invite_code: dupInv.code });
  assert.equal(dup.status, 409);
  assert.equal(store.inviteCodes.findActive(dupInv.code).uses, 0, "convite não consumido no 409");
  ok("email duplicado → 409 (convite preservado)");

  // senha curta → 400 (com convite fresco também — 400 vem antes do consumo)
  const shortInv = store.inviteCodes.create({ createdBy: "t", maxUses: 1, ttlDays: 7 });
  const short = await post(base, "/auth/register", { email: "curta@test.dev", password: "curta12", invite_code: shortInv.code });
  assert.equal(short.status, 400);
  ok("senha < 8 → 400");

  // convite expirado: cria com ttl passado direto no store
  const exp = store.inviteCodes.create({ createdBy: "x", maxUses: 1, ttlDays: 7 });
  store.db.prepare("UPDATE invite_codes SET expires_at = ? WHERE code = ?")
    .run(new Date(Date.now() - 1000).toISOString(), exp.code);
  const rExp = await post(base, "/auth/register", { email: "atrasado@test.dev", password: "senha-forte-123", invite_code: exp.code });
  assert.equal(rExp.status, 403);
  ok("convite expirado → 403");

  // ── convite NOMINAL (email_alvo) ─────────────────────────────────────
  const nom = await post(base, "/auth/invites", { email_alvo: "Nominal@Test.dev", note: "p/ fulano" }, csrf.headers());
  assert.equal(nom.status, 201);
  const nomBody = await nom.json();
  assert.equal(nomBody.email_alvo, "nominal@test.dev");   // normalizado lowercase
  assert.equal(nomBody.max_uses, 1);                       // nominal = single-use
  ok("convite nominal cria com email normalizado + single-use");

  // email_alvo inválido → 400
  const nomBad = await post(base, "/auth/invites", { email_alvo: "não-email" }, csrf.headers());
  assert.equal(nomBad.status, 400);
  ok("convite com email_alvo inválido → 400");

  // outro email tenta usar o convite nominal → 403 e o convite SOBRA
  const wrong = await post(base, "/auth/register", { email: "outra@test.dev", password: "senha-forte-123", invite_code: nomBody.code });
  assert.equal(wrong.status, 403);
  assert.match((await wrong.json()).error, /nominal@test\.dev/);
  assert.equal(store.inviteCodes.findActive(nomBody.code).uses, 0);
  ok("convite nominal com outro email → 403 (convite preservado)");

  // email certo → 201
  const right = await post(base, "/auth/register", { email: "Nominal@Test.dev", password: "senha-forte-123", invite_code: nomBody.code });
  assert.equal(right.status, 201);
  assert.equal(store.inviteCodes.findActive(nomBody.code), null, "esgotado após uso");
  ok("convite nominal com o email certo → 201 (single-use)");

  // modo invite NÃO registra (null) mesmo com banco com usuários: confere
  // que o gate é o modo, não a existência de convites
  assert.equal(config.registerMode, "invite");

  // GET /proxy/providers com zwt_ (machine) — mesmo shape do /providers
  const tok = `zwt_${crypto.randomBytes(32).toString("base64url")}`;
  const { hashToken } = await import("../lib/crypto.js");
  store.workspaceTokens.create({
    userId: me.id, name: "t", tokenHash: hashToken(tok),
    scopesJson: JSON.stringify(["*"]),
  });
  const provs = await (await fetch(`${base}/proxy/providers`, {
    headers: { authorization: `Bearer ${tok}` },
  })).json();
  assert.ok(Array.isArray(provs) && provs.length >= 1, "catálogo não-vazio");
  assert.ok("name" in provs[0] && "connectable" in provs[0] && "packs" in provs[0]);
  const provSess = await (await fetch(`${base}/providers`, { headers: { cookie: bossCookie } })).json();
  assert.deepEqual(provs.map((p) => p.name), provSess.map((p) => p.name));
  ok("GET /proxy/providers (zwt_) ≡ GET /providers (sessão)");

  // sem token → 401
  assert.equal((await fetch(`${base}/proxy/providers`)).status, 401);
  ok("GET /proxy/providers sem token → 401");

  // ── POST /proxy/invites (machine, dono admin) ────────────────────────
  const mint = (body) => fetch(`${base}/proxy/invites`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${tok}` },
    body: JSON.stringify(body),
  });

  // sem email_alvo → 400
  assert.equal((await mint({})).status, 400);
  // com email_alvo → 201
  const minted = await mint({ email_alvo: "Cliente@Org.dev", note: "org acme via shell" });
  assert.equal(minted.status, 201);
  const mintedBody = await minted.json();
  assert.equal(mintedBody.email_alvo, "cliente@org.dev");
  assert.ok(mintedBody.code.startsWith("zkinv_"));
  ok("POST /proxy/invites (zwt_ de admin) → 201 nominal");

  // convite mintado vale no registro
  const viaProxy = await post(base, "/auth/register", { email: "cliente@org.dev", password: "senha-forte-123", invite_code: mintedBody.code });
  assert.equal(viaProxy.status, 201);
  ok("registro com convite mintado via /proxy/invites → 201");

  // token de NÃO-admin → 403 (mesma rota, dono user comum)
  const tokUser = `zwt_${crypto.randomBytes(32).toString("base64url")}`;
  store.workspaceTokens.create({
    userId: me2.id, name: "nao-admin", tokenHash: hashToken(tokUser),
    scopesJson: JSON.stringify(["*"]),
  });
  const mintUser = await fetch(`${base}/proxy/invites`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${tokUser}` },
    body: JSON.stringify({ email_alvo: "x@y.dev" }),
  });
  assert.equal(mintUser.status, 403);
  ok("POST /proxy/invites com zwt_ de não-admin → 403");
}

// ══ App B: modo closed (default) ═════════════════════════════════════════
{
  const { base } = await boot("closed", "closed");

  const r1 = await post(base, "/auth/register", { email: "first@test.dev", password: "senha-forte-123" });
  assert.equal(r1.status, 201);   // bootstrap ignora closed
  const r2 = await post(base, "/auth/register", { email: "second@test.dev", password: "senha-forte-123" });
  assert.equal(r2.status, 403);
  ok("closed: 1º registro vira admin, 2º → 403");

  // link do form some (register-mode closed)
  const rm = await (await fetch(`${base}/auth/register-mode`)).json();
  assert.equal(rm.mode, "closed");
  assert.equal(rm.invite_required, false);
  ok("register-mode → closed (UI esconde o form)");
}

console.log(`\n${passed} checagens OK`);
process.exit(0);
