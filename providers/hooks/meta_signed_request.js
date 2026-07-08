// Meta data-deletion callback (signed_request com HMAC-SHA256).
// https://developers.facebook.com/docs/development/create-an-app/app-dashboard/data-deletion-callback
//
// Hook por-provider (DESIGN-zkeys §6): instalado via config.extensions.
// Não toca o flow normal — só adiciona o endpoint /auth/meta/data-deletion
// e a página de status. Mantemos o comportamento que existia no MetaAuth
// original.

import crypto from "crypto";

function parseSignedRequest(signedRequest, clientSecret) {
  const [encodedSig, payload] = signedRequest.split(".", 2);
  if (!encodedSig || !payload) return null;
  const sig = Buffer.from(encodedSig.replace(/-/g, "+").replace(/_/g, "/"), "base64");
  const expected = crypto.createHmac("sha256", clientSecret).update(payload).digest();
  if (sig.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(sig, expected)) return null;
  const data = JSON.parse(Buffer.from(payload.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
  if ((data.algorithm || "").toUpperCase() !== "HMAC-SHA256") return null;
  return data;
}

export default function install(app, provider) {
  const base = `/auth/${provider.name}`;

  app.post(`${base}/data-deletion`, (req, res) => {
    const signedRequest = req.body?.signed_request;
    if (!signedRequest) {
      return res.status(400).json({ error: "signed_request é obrigatório." });
    }
    const data = parseSignedRequest(signedRequest, provider.clientSecret);
    if (!data) return res.status(403).json({ error: "Assinatura inválida." });
    const confirmationCode = crypto.randomUUID();
    const statusUrl = `${provider.publicBaseUrl}${base}/deletion-status?code=${confirmationCode}`;
    // TODO: persistir confirmationCode pro endpoint de status. Por ora,
    // mantemos a resposta exigida pela Meta.
    res.json({ url: statusUrl, confirmation_code: confirmationCode });
  });

  app.get(`${base}/deletion-status`, (req, res) => {
    const { code } = req.query;
    if (!code) return res.status(400).send("Código de confirmação não informado.");
    res.send(`
      <h1>Status da Exclusão de Dados</h1>
      <p>Código de confirmação: <strong>${String(code).replace(/[^A-Za-z0-9-]/g, "")}</strong></p>
      <p>Seus dados foram marcados para exclusão.</p>
    `);
  });
}
