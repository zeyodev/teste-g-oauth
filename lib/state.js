// JWT state assinado pelo backend (HS256) e validado server-to-server no
// callback. O oauth/ não decodifica — só repassa pro backend. Esta lib só
// existe pra centralizar o segredo compartilhado entre oauth/ e backend
// quando precisarmos validar localmente algum dia.

import crypto from "crypto";

function base64url(buf) {
  return Buffer.from(buf).toString("base64").replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function fromBase64Url(str) {
  const pad = str.length % 4 === 0 ? 0 : 4 - (str.length % 4);
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad);
  return Buffer.from(b64, "base64");
}

export function decodeUnverified(token) {
  try {
    const [, payload] = token.split(".");
    if (!payload) return null;
    return JSON.parse(fromBase64Url(payload).toString("utf8"));
  } catch {
    return null;
  }
}

export function verifyHS256(token, secret) {
  try {
    const [headerB64, payloadB64, sigB64] = token.split(".");
    if (!headerB64 || !payloadB64 || !sigB64) return null;
    const expected = crypto
      .createHmac("sha256", secret)
      .update(`${headerB64}.${payloadB64}`)
      .digest();
    const provided = fromBase64Url(sigB64);
    if (expected.length !== provided.length) return null;
    if (!crypto.timingSafeEqual(expected, provided)) return null;
    const payload = JSON.parse(fromBase64Url(payloadB64).toString("utf8"));
    if (payload.exp && Date.now() / 1000 > payload.exp) return null;
    return payload;
  } catch {
    return null;
  }
}
