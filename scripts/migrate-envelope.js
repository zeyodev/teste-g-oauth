// Migração de dados v1 (KEK direto) → v2 (envelope) — DESIGN-zkeys §8.
// Pra cada connection ainda-v1 (dek_wrapped IS NULL): decifra os tokens com o
// KEK, sorteia um DEK, re-cifra no formato v2 e grava dek_wrapped. O schema
// (*_enc BLOB) não muda; só entra a coluna dek_wrapped (o createStore já a
// adiciona por ALTER idempotente).
//
// Segurança do processo:
//  - BACKUP consistente antes (VACUUM INTO) — a conexão real de dev não pode
//    quebrar (memória project_metaorg_oauth_credentials);
//  - IDEMPOTENTE: linhas já-v2 são puladas; rodar 2x é no-op;
//  - PROVA o plaintext: re-decifra a linha migrada e compara com o original
//    ANTES de commitar; qualquer divergência → rollback e aborta;
//  - NUNCA loga plaintext (só contagem e tamanho de blob).
//
// Uso: node scripts/migrate-envelope.js [--dry-run]

import { loadConfig } from "../config.js";
import { createStore } from "../lib/store.js";
import { createCrypto } from "../lib/crypto.js";

const dryRun = process.argv.includes("--dry-run");

const config = loadConfig();
const store = createStore(config.dbPath);   // abre o banco + ALTER idempotente (dek_wrapped)
const crypto = createCrypto(config.masterKey);
const db = store.db;

// ── Backup consistente (não no --dry-run: nada muda) ─────────────────────
if (!dryRun && config.dbPath !== ":memory:") {
  const bak = `${config.dbPath}.bak-envelope-${new Date().toISOString().replace(/[:.]/g, "")}`;
  db.exec(`VACUUM INTO '${bak.replace(/'/g, "''")}'`);
  console.log(`[migrate-envelope] backup → ${bak}`);
}

const pending = db.prepare("SELECT * FROM connections WHERE dek_wrapped IS NULL").all();
const alreadyV2 = db.prepare("SELECT COUNT(*) c FROM connections WHERE dek_wrapped IS NOT NULL").get().c;
console.log(`[migrate-envelope] v1 pendentes: ${pending.length} · já-v2: ${alreadyV2}${dryRun ? " · DRY-RUN" : ""}`);

let migrated = 0;
db.exec("BEGIN");
try {
  for (const row of pending) {
    // Decifra o que existe (v1, KEK direto). Guarda só pra provar depois.
    const access = crypto.decrypt(row.access_token_enc);
    const refresh = row.refresh_token_enc ? crypto.decrypt(row.refresh_token_enc) : null;

    // Re-cifra com um DEK novo (v2).
    const box = crypto.newConnection();
    const accessEnc = box.encrypt(access);
    const refreshEnc = refresh != null ? box.encrypt(refresh) : null;

    // PROVA o plaintext antes de gravar: re-decifra com o DEK recém-criado.
    if (box.decrypt(accessEnc) !== access || (refresh != null && box.decrypt(refreshEnc) !== refresh)) {
      throw new Error(`[migrate-envelope] verificação falhou na connection ${row.id} — abortando`);
    }

    if (!dryRun) {
      db.prepare(
        "UPDATE connections SET access_token_enc = ?, refresh_token_enc = ?, dek_wrapped = ?, updated_at = ? WHERE id = ?"
      ).run(accessEnc, refreshEnc, box.dekWrapped, new Date().toISOString(), row.id);
    }
    migrated++;
    console.log(`  ✓ ${row.provider}/${row.account_key} (${row.id}) → v2${refresh == null ? " (sem refresh)" : ""}`);
  }

  // Prova FINAL, lendo do banco pós-UPDATE: cada linha migrada abre e decifra.
  if (!dryRun) {
    for (const row of pending) {
      const fresh = store.connections.findById(row.id);
      const box = crypto.openConnection(fresh);
      const access = box.decrypt(fresh.access_token_enc);
      if (!access || access.length === 0) {
        throw new Error(`[migrate-envelope] pós-UPDATE indecifrável na connection ${row.id} — rollback`);
      }
    }
  }

  db.exec(dryRun ? "ROLLBACK" : "COMMIT");
  console.log(`[migrate-envelope] ${dryRun ? "DRY-RUN ok (rollback)" : "OK — commit"}: ${migrated} migrada(s), ${alreadyV2} já-v2 intactas.`);
} catch (e) {
  db.exec("ROLLBACK");
  console.error(String(e.message || e));
  console.error("[migrate-envelope] ROLLBACK — banco intacto (backup preservado).");
  process.exit(1);
}
