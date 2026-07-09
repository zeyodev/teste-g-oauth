// Rotação do KEK (DESIGN-zkeys §8) — o ganho do envelope: trocar o master key
// é RE-WRAP dos DEKs, não re-cifrar todo token. Pra cada connection v2:
// unwrap do DEK com o KEK velho → wrap com o KEK novo → grava dek_wrapped.
// access/refresh (cifrados com o DEK, que não muda) ficam INTACTOS.
//
//  - KEK velho vem de ZKEYS_MASTER_KEY (config); KEK novo de ZKEYS_NEW_MASTER_KEY.
//  - BACKUP antes (VACUUM INTO); transação com prova de re-wrap; rollback em erro.
//  - Linhas ainda-v1 (dek_wrapped NULL) NÃO têm DEK — rode migrate-envelope antes.
//  - Ao terminar, troque ZKEYS_MASTER_KEY pelo valor novo no ambiente/secret.
//
// Uso: ZKEYS_NEW_MASTER_KEY=<hex64> node scripts/rotate-kek.js

import { loadConfig } from "../config.js";
import { createStore } from "../lib/store.js";
import { createCrypto } from "../lib/crypto.js";

const config = loadConfig();
const store = createStore(config.dbPath);
const db = store.db;

const newHex = process.env.ZKEYS_NEW_MASTER_KEY;
if (!/^[0-9a-fA-F]{64}$/.test(newHex || "")) {
  console.error("[rotate-kek] defina ZKEYS_NEW_MASTER_KEY = 32 bytes hex (openssl rand -hex 32)");
  process.exit(1);
}
const oldCrypto = createCrypto(config.masterKey);
const newCrypto = createCrypto(Buffer.from(newHex, "hex"));

const v1 = db.prepare("SELECT COUNT(*) c FROM connections WHERE dek_wrapped IS NULL").get().c;
if (v1 > 0) {
  console.error(`[rotate-kek] ${v1} connection(s) ainda-v1 (sem DEK) — rode migrate-envelope.js antes. Abortando.`);
  process.exit(1);
}

const rows = db.prepare("SELECT id, dek_wrapped FROM connections").all();
const bak = `${config.dbPath}.bak-rotate-${new Date().toISOString().replace(/[:.]/g, "")}`;
if (config.dbPath !== ":memory:") {
  db.exec(`VACUUM INTO '${bak.replace(/'/g, "''")}'`);
  console.log(`[rotate-kek] backup → ${bak}`);
}

let rotated = 0;
db.exec("BEGIN");
try {
  for (const row of rows) {
    const dek = oldCrypto.unwrapDek(row.dek_wrapped);   // abre com o KEK velho
    const rewrapped = newCrypto.wrapDek(dek);           // fecha com o KEK novo
    // Prova: o DEK re-wrapped abre igual com o KEK novo.
    if (!newCrypto.unwrapDek(rewrapped).equals(dek)) {
      throw new Error(`[rotate-kek] re-wrap inconsistente na connection ${row.id} — abortando`);
    }
    db.prepare("UPDATE connections SET dek_wrapped = ? WHERE id = ?").run(rewrapped, row.id);
    rotated++;
  }
  db.exec("COMMIT");
  console.log(`[rotate-kek] OK: ${rotated} DEK(s) re-wrapped. Agora troque ZKEYS_MASTER_KEY pelo novo valor.`);
} catch (e) {
  db.exec("ROLLBACK");
  console.error(String(e.message || e));
  console.error("[rotate-kek] ROLLBACK — banco intacto (backup preservado).");
  process.exit(1);
}
