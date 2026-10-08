// Regressão do incidente 2026-10-08: a org gravou o LITERAL
// «secret:CLOUDFLARE_BUCKET» como webhook_forward_url (eco da redação de
// exibição do harness da org) e todo evento do WABA passou a falhar com
// "Failed to parse URL" — best-effort, sem retry, descarte silencioso.
// O store agora RECUSA URL imparsável/protocolo não-http na gravação.

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createStore } from "../lib/store.js";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "zkeys-fwdurl-"));
const store = createStore(path.join(tmp, "zkeys.db"));

const user = store.users.create({ email: "org@teste", passwordHash: "x" });
const conn = store.connections.upsert({
  userId: user.id,
  provider: "whatsapp",
  accountKey: "WABA_TESTE",
  scopesJson: "[]",
  accessTokenEnc: Buffer.from("token-cifrado"),
});

// Placeholder de redação (o caso real do incidente) — imparsável, recusa.
assert.throws(
  () => store.connections.setWebhookForwardUrl(conn.id, "https://«secret:CLOUDFLARE_BUCKET».metaorg.app/api/webhooks/whatsapp-mensagem"),
  /webhook_forward_url inválida/
);
// Lixo genérico também recusa.
assert.throws(
  () => store.connections.setWebhookForwardUrl(conn.id, "não-é-url"),
  /webhook_forward_url inválida/
);
// Protocolo não-http recusa.
assert.throws(
  () => store.connections.setWebhookForwardUrl(conn.id, "ftp://duoacademy.metaorg.app/hook"),
  /protocolo/
);
// Nada foi gravado — findByWabaId não roteia pra URL quebrada.
assert.deepEqual(store.connections.findByWabaId("WABA_TESTE"), []);

// URL válida grava e roteia.
store.connections.setWebhookForwardUrl(conn.id, "https://duoacademy.metaorg.app/api/webhooks/whatsapp-mensagem");
const routed = store.connections.findByWabaId("WABA_TESTE");
assert.equal(routed.length, 1);
assert.equal(routed[0].webhook_forward_url, "https://duoacademy.metaorg.app/api/webhooks/whatsapp-mensagem");

// http também é aceito (rede interna de teste).
store.connections.setWebhookForwardUrl(conn.id, "http://192.168.3.60:8003/api/webhooks/whatsapp-mensagem");
assert.equal(store.connections.findByWabaId("WABA_TESTE")[0].webhook_forward_url, "http://192.168.3.60:8003/api/webhooks/whatsapp-mensagem");

fs.rmSync(tmp, { recursive: true, force: true });
console.log("forward-url.test.mjs: OK");
