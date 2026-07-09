// Cifra at-rest AES-256-GCM (DESIGN-zkeys §8) + hash de workspace token.
//
// Dois formatos, com RETROCOMPAT obrigatória (byte de versão):
//  - v1 (legado, KEK direto): nonce(12) ‖ ct ‖ tag(16), SEM byte de versão.
//    Espelha agente/backend/crypto_credentials.py; é o que a F1-F3 gravou.
//  - v2 (envelope): cada connection sorteia um DEK aleatório de 32 bytes; o
//    DEK é *wrapped* (AES-256-GCM) pelo KEK e guardado em connections.dek_wrapped;
//    access/refresh da MESMA linha são cifrados com esse DEK no formato
//    0x02 ‖ nonce(12) ‖ ct ‖ tag(16). Ganho: dump do zkeys.db sem o KEK = lixo,
//    e rotação de KEK = re-wrap dos DEKs (não re-cifra token).
//
// A distinção v1 vs v2 é ancorada na presença de connections.dek_wrapped (por
// linha, inequívoco); o byte 0x02 no blob é a checagem defensiva. openConnection
// PRESERVA o formato da linha (v1 continua v1 até a migração; v2 fica v2) — evita
// blob misto (o refresh preservado pelo COALESCE do store fica com o DEK certo).

import crypto from "crypto";

const V2 = 0x02; // marcador do formato envelope

// GCM sobre Buffers crus: nonce(12) ‖ ct ‖ tag(16).
function gcmEncrypt(key, buf) {
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", key, nonce);
  const ct = Buffer.concat([c.update(buf), c.final()]);
  return Buffer.concat([nonce, ct, c.getAuthTag()]);
}
function gcmDecrypt(key, blob) {
  const buf = Buffer.isBuffer(blob) ? blob : Buffer.from(blob);
  if (buf.length < 28) throw new Error("ciphertext muito curto"); // 12 nonce + 16 tag
  const nonce = buf.subarray(0, 12);
  const tag = buf.subarray(buf.length - 16);
  const ct = buf.subarray(12, buf.length - 16);
  const d = crypto.createDecipheriv("aes-256-gcm", key, nonce);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

export function createCrypto(masterKey) {
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== 32) {
    throw new Error("[zkeys/crypto] masterKey deve ser Buffer de 32 bytes");
  }

  // ── v1 (KEK direto): compat com dados F1-F3 + leitura na migração ──────
  function encrypt(plaintext) {
    if (plaintext == null) return null;
    return gcmEncrypt(masterKey, Buffer.from(String(plaintext), "utf8"));
  }
  function decrypt(blob) {
    if (blob == null) return null;
    return gcmDecrypt(masterKey, blob).toString("utf8");
  }

  // ── Envelope (v2): DEK por connection, wrapped pelo KEK ────────────────
  const generateDek = () => crypto.randomBytes(32);
  const wrapDek = (dek) => gcmEncrypt(masterKey, dek);       // KEK cifra o DEK cru
  const unwrapDek = (wrapped) => gcmDecrypt(masterKey, wrapped);

  // Token cifrado com o DEK da linha, marcado com o byte de versão.
  function encryptWith(dek, plaintext) {
    if (plaintext == null) return null;
    return Buffer.concat([Buffer.from([V2]), gcmEncrypt(dek, Buffer.from(String(plaintext), "utf8"))]);
  }
  function decryptWith(dek, blob) {
    if (blob == null) return null;
    const buf = Buffer.isBuffer(blob) ? blob : Buffer.from(blob);
    if (buf[0] !== V2) throw new Error("[zkeys/crypto] blob não-v2 passado a decryptWith");
    return gcmDecrypt(dek, buf.subarray(1)).toString("utf8");
  }

  // ── Ergonomia por-connection (o que os handlers usam) ──────────────────
  // Connection nova → sorteia DEK v2; devolve o wrapped + cifrador/decifrador.
  function newConnection() {
    const dek = generateDek();
    return {
      dekWrapped: wrapDek(dek),
      encrypt: (pt) => encryptWith(dek, pt),
      decrypt: (blob) => decryptWith(dek, blob),
    };
  }
  // Abre uma connection existente PRESERVANDO seu formato: v2 (tem dek_wrapped)
  // → usa o DEK da linha; v1 (dek_wrapped null, ainda não migrada) → KEK direto.
  // Assim reconexão/refresh não misturam formatos numa mesma linha.
  function openConnection(conn) {
    if (conn && conn.dek_wrapped) {
      const dek = unwrapDek(conn.dek_wrapped);
      return {
        dekWrapped: conn.dek_wrapped,
        encrypt: (pt) => encryptWith(dek, pt),
        decrypt: (blob) => decryptWith(dek, blob),
      };
    }
    return { dekWrapped: null, encrypt, decrypt };  // v1 legado
  }

  return {
    encrypt, decrypt,                                  // v1 (compat + migração)
    generateDek, wrapDek, unwrapDek, encryptWith, decryptWith, // primitivas v2
    newConnection, openConnection,                     // ergonomia por-connection
  };
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
