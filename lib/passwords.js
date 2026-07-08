// Hashing de senha: Argon2id + pepper — espelha agente/backend/passwords.py.
//
// Pepper ANTES do Argon2: HMAC-SHA256(pepper, senha) → base64 → Argon2id.
// Assim o pepper é chave de tamanho fixo independente dos params do Argon2,
// e um dump do banco sem o env é inútil pra brute-force. Trocar o pepper
// invalida TODOS os hashes (re-cadastro).
//
// Params idênticos aos defaults do argon2-cffi usados no agente:
// Argon2id, time_cost=3, memory=64MiB, parallelism=4.

import crypto from "crypto";
import argon2 from "argon2";

const ARGON2_OPTS = {
  type: argon2.argon2id,
  timeCost: 3,
  memoryCost: 64 * 1024, // KiB → 64 MiB
  parallelism: 4,
};

export function createPasswords(pepper) {
  if (!pepper) throw new Error("[zkeys/passwords] pepper vazio");

  function peppered(password) {
    return crypto
      .createHmac("sha256", Buffer.from(pepper, "utf8"))
      .update(String(password), "utf8")
      .digest("base64");
  }

  async function hash(password) {
    return argon2.hash(peppered(password), ARGON2_OPTS);
  }

  // Não levanta em mismatch/hash inválido — o caller responde genérico
  // (sem revelar user inexistente vs senha errada).
  async function verify(storedHash, password) {
    try {
      return await argon2.verify(storedHash, peppered(password));
    } catch {
      return false;
    }
  }

  return { hash, verify };
}
