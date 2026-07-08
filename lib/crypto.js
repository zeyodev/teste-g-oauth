// Cifra at-rest AES-256-GCM (DESIGN-zkeys §8) + hash de workspace token.
// Formato do BLOB: nonce(12) ‖ ciphertext ‖ tag(16) — espelha
// agente/backend/crypto_credentials.py pra manter a mesma forma nos dois cofres.
//
// KEK direto por ora; envelope encryption (DEK per-connection) é evolução
// prevista em §8 sem mudança de schema (*_enc BLOB continua).

import crypto from "crypto";

export function createCrypto(masterKey) {
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== 32) {
    throw new Error("[zkeys/crypto] masterKey deve ser Buffer de 32 bytes");
  }

  function encrypt(plaintext) {
    if (plaintext == null) return null;
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", masterKey, nonce);
    const ct = Buffer.concat([cipher.update(String(plaintext), "utf8"), cipher.final()]);
    return Buffer.concat([nonce, ct, cipher.getAuthTag()]);
  }

  function decrypt(blob) {
    if (blob == null) return null;
    const buf = Buffer.isBuffer(blob) ? blob : Buffer.from(blob);
    if (buf.length < 28) throw new Error("ciphertext muito curto"); // 12 nonce + 16 tag
    const nonce = buf.subarray(0, 12);
    const tag = buf.subarray(buf.length - 16);
    const ct = buf.subarray(12, buf.length - 16);
    const decipher = crypto.createDecipheriv("aes-256-gcm", masterKey, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
  }

  return { encrypt, decrypt };
}

// sha-256 hex de token opaco (zwt_…). Alta entropia → hash simples basta (§7);
// o banco guarda só isto, o segredo aparece uma vez na emissão.
export function hashToken(token) {
  return crypto.createHash("sha256").update(String(token), "utf8").digest("hex");
}

// Compara dois hashes hex em tempo constante.
export function safeEqualHex(a, b) {
  const ba = Buffer.from(String(a), "hex");
  const bb = Buffer.from(String(b), "hex");
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}
