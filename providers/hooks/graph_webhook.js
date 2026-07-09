// Receptor de webhook do Meta Graph — compartilhado por Instagram e WhatsApp
// (Cloud API). O protocolo é idêntico nos dois:
//   https://developers.facebook.com/docs/graph-api/webhooks
//
// Hook por-provider (DESIGN-zkeys §6): instalado via config.extensions. É
// INBOUND (Meta → zkeys), ao contrário do proxy /p/* que é outbound. Adiciona:
//   GET  /auth/<provider>/webhook → handshake: devolve hub.challenge se
//        hub.verify_token bate com o token configurado (a Meta faz esse GET ao
//        salvar o webhook no painel do app).
//   POST /auth/<provider>/webhook → eventos. Valida X-Hub-Signature-256 (HMAC do
//        corpo CRU com o app secret) e audita. Por ora SÓ valida+loga; o
//        roteamento do evento pro workspace da org vem depois.
//
// Corpo CRU: a assinatura da Meta é sobre os BYTES exatos do corpo, então
// dependemos de req.rawBody (stashed pelo `verify` do express.json em index.js).
// O req.body parseado NÃO serve — reserializar muda os bytes e o HMAC não bate.

import crypto from "crypto";

// Comparação em tempo constante tolerante a tamanhos diferentes (timingSafeEqual
// exige buffers do mesmo tamanho — daí o guard de length antes).
function safeEqual(a, b) {
  const ba = Buffer.from(String(a), "utf8");
  const bb = Buffer.from(String(b), "utf8");
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// X-Hub-Signature-256: "sha256=<hex>", hex = HMAC-SHA256(appSecret, rawBody).
function validSignature(appSecret, rawBody, header) {
  if (!appSecret || !rawBody || !rawBody.length || !header) return false;
  const [algo, sig] = String(header).split("=", 2);
  if (algo !== "sha256" || !sig) return false;
  const expected = crypto.createHmac("sha256", appSecret).update(rawBody).digest("hex");
  return safeEqual(sig, expected);
}

export default function install(app, provider, { store } = {}) {
  const route = `/auth/${provider.name}/webhook`;
  const verifyToken = provider.webhookVerifyToken;

  app.get(route, (req, res) => {
    if (!verifyToken) {
      console.error(`[zkeys/${provider.name}] webhook GET sem ${provider.name.toUpperCase()}_WEBHOOK_VERIFY_TOKEN configurado`);
      return res.sendStatus(500);
    }
    const mode = req.query["hub.mode"];
    const token = req.query["hub.verify_token"];
    const challenge = req.query["hub.challenge"];
    if (mode === "subscribe" && token && safeEqual(token, verifyToken)) {
      return res.status(200).type("text/plain").send(String(challenge ?? ""));
    }
    return res.sendStatus(403);
  });

  app.post(route, (req, res) => {
    if (!validSignature(provider.clientSecret, req.rawBody, req.get("x-hub-signature-256"))) {
      store?.audit("webhook.reject", { provider: provider.name, detail: "assinatura inválida" });
      return res.sendStatus(403);
    }
    const obj = req.body?.object || "?";
    const n = Array.isArray(req.body?.entry) ? req.body.entry.length : 0;
    store?.audit("webhook.recv", { provider: provider.name, detail: `${obj} entries=${n}` });
    console.log(`[zkeys/${provider.name}] webhook ${obj} (${n}):`, JSON.stringify(req.body).slice(0, 500));
    // 200 rápido: a Meta reenvia se não receber 2xx em poucos segundos.
    return res.sendStatus(200);
  });
}
