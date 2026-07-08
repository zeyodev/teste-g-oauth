// ULID (Crockford base32): 10 chars de timestamp + 16 chars aleatórios.
// Ids ordenáveis por criação, mesmo formato usado no resto do metaorg.

import crypto from "crypto";

const B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

export function ulid(now = Date.now()) {
  let ts = "";
  let t = now;
  for (let i = 0; i < 10; i++) {
    ts = B32[t % 32] + ts;
    t = Math.floor(t / 32);
  }
  const rnd = crypto.randomBytes(16);
  let out = ts;
  for (let i = 0; i < 16; i++) out += B32[rnd[i] % 32]; // 256 % 32 === 0 → sem viés
  return out;
}
