// Repository (DESIGN-zkeys §3/§5): esconde o SQLite atrás de métodos de
// domínio. Handlers dependem desta interface, não do driver — testável com
// fake e trocável sem tocar rota. Driver: node:sqlite (stdlib, sem dep nativa).
//
// Invariantes do cofre:
//  - token cru só existe cifrado (colunas *_enc BLOB) — quem cifra é o caller;
//  - workspace_tokens guarda só sha-256 do segredo;
//  - oauth_states é single-use (consume = DELETE ... RETURNING) com TTL.

import { DatabaseSync } from "node:sqlite";
import fs from "fs";
import path from "path";
import { ulid } from "./ulid.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'user',
  created_at    TEXT NOT NULL,
  disabled_at   TEXT
);

CREATE TABLE IF NOT EXISTS connections (
  id                 TEXT PRIMARY KEY,
  user_id            TEXT NOT NULL REFERENCES users(id),
  provider           TEXT NOT NULL,
  account_key        TEXT NOT NULL,
  alias              TEXT,
  email              TEXT,
  scopes_json        TEXT NOT NULL,
  access_token_enc   BLOB NOT NULL,
  refresh_token_enc  BLOB,
  dek_wrapped        BLOB,             -- envelope (§8): DEK da linha wrapped pelo KEK; NULL = v1 (KEK direto)
  expires_at         TEXT,
  is_default         INTEGER NOT NULL DEFAULT 0,
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL,
  UNIQUE(user_id, provider, account_key)
);
CREATE INDEX IF NOT EXISTS idx_connections_user ON connections(user_id, provider);

CREATE TABLE IF NOT EXISTS workspace_tokens (
  id           TEXT PRIMARY KEY,
  user_id      TEXT NOT NULL REFERENCES users(id),
  name         TEXT NOT NULL,
  token_hash   TEXT NOT NULL UNIQUE,
  scopes_json  TEXT NOT NULL,
  created_at   TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at   TEXT
);

CREATE TABLE IF NOT EXISTS oauth_states (
  state         TEXT PRIMARY KEY,
  user_id       TEXT NOT NULL REFERENCES users(id),
  provider      TEXT NOT NULL,
  pack          TEXT,
  code_verifier TEXT,
  created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id       TEXT PRIMARY KEY,
  user_id  TEXT,
  action   TEXT NOT NULL,
  provider TEXT,
  detail   TEXT,
  at       TEXT NOT NULL
);
`;

const now = () => new Date().toISOString();

// Migração de schema idempotente (§8): CREATE TABLE IF NOT EXISTS não altera
// tabela já existente, então colunas novas entram por ADD COLUMN guardado.
// dek_wrapped nasce NULL nas linhas antigas (= v1, KEK direto); a migração de
// DADOS (re-cifra p/ envelope) é separada — scripts/migrate-envelope.js.
function migrateSchema(db) {
  const cols = db.prepare("PRAGMA table_info(connections)").all().map((c) => c.name);
  if (!cols.includes("dek_wrapped")) {
    db.exec("ALTER TABLE connections ADD COLUMN dek_wrapped BLOB");
  }
  // display_name (rótulo do provider: username/nome do perfil) — a UI mostra
  // isso no lugar do account_key cru. Linhas antigas nascem NULL e caem no
  // fallback email/account_key até a próxima reconexão preencher.
  if (!cols.includes("display_name")) {
    db.exec("ALTER TABLE connections ADD COLUMN display_name TEXT");
  }
  // metadata_json: bag de dados não-secretos descobertos no connect que a org
  // precisa pra USAR a conexão mas que não são credencial. Hoje: WhatsApp ES
  // grava { waba_id, phone_number_id, display_phone_number } (o número de onde
  // enviar). NULL nas linhas antigas / providers sem descoberta.
  if (!cols.includes("metadata_json")) {
    db.exec("ALTER TABLE connections ADD COLUMN metadata_json TEXT");
  }
  // webhook_forward_url: pra onde o zkeys manda eventos recebidos do Meta
  // (webhook inbound). A URL é da org (ex: https://protest1.metaorg.app/api/webhooks/whatsapp).
  // NULL = sem roteamento (eventos são auditados mas não encaminhados).
  if (!cols.includes("webhook_forward_url")) {
    db.exec("ALTER TABLE connections ADD COLUMN webhook_forward_url TEXT");
  }
}

export function createStore(dbPath) {
  if (dbPath !== ":memory:") fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA journal_mode=WAL;");
  db.exec("PRAGMA foreign_keys=ON;");
  db.exec("PRAGMA busy_timeout=5000;");   // WAL + escritas concorrentes (refresh, migração)
  db.exec(SCHEMA);
  migrateSchema(db);

  function transaction(fn) {
    db.exec("BEGIN");
    try {
      const out = fn();
      db.exec("COMMIT");
      return out;
    } catch (e) {
      db.exec("ROLLBACK");
      throw e;
    }
  }

  const users = {
    create({ email, passwordHash, role = "user" }) {
      const id = ulid();
      db.prepare(
        "INSERT INTO users (id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)"
      ).run(id, String(email).toLowerCase(), passwordHash, role, now());
      return { id, email: String(email).toLowerCase(), role };
    },
    findByEmail(email) {
      return (
        db.prepare("SELECT * FROM users WHERE email = ? AND disabled_at IS NULL")
          .get(String(email).toLowerCase()) ?? null
      );
    },
    findById(id) {
      return db.prepare("SELECT * FROM users WHERE id = ?").get(id) ?? null;
    },
    count() {
      return db.prepare("SELECT COUNT(*) AS c FROM users").get().c;
    },
  };

  const oauthStates = {
    create({ state, userId, provider, pack = null, codeVerifier = null }) {
      db.prepare(
        "INSERT INTO oauth_states (state, user_id, provider, pack, code_verifier, created_at) VALUES (?, ?, ?, ?, ?, ?)"
      ).run(state, userId, provider, pack, codeVerifier, now());
    },
    // Single-use: apaga ao ler. Expirado conta como inexistente.
    consume(state, ttlSeconds) {
      const row = db.prepare("DELETE FROM oauth_states WHERE state = ? RETURNING *").get(state);
      if (!row) return null;
      if (Date.now() - Date.parse(row.created_at) > ttlSeconds * 1000) return null;
      return row;
    },
    purgeExpired(ttlSeconds) {
      const cutoff = new Date(Date.now() - ttlSeconds * 1000).toISOString();
      db.prepare("DELETE FROM oauth_states WHERE created_at < ?").run(cutoff);
    },
  };

  const connections = {
    // Upsert por (user, provider, account_key): reconectar a mesma conta
    // atualiza tokens/scopes; refresh_token novo só sobrescreve se veio
    // (Google só devolve no primeiro consent). Primeira conexão do provider
    // vira default.
    upsert({ userId, provider, accountKey, alias = null, email = null, displayName = null,
             metadataJson = null, scopesJson,
             accessTokenEnc, refreshTokenEnc = null, dekWrapped = null, expiresAt = null }) {
      return transaction(() => {
        const ts = now();
        // Reconexão da MESMA conta reusa o DEK da linha (o caller passa o
        // dek_wrapped existente): o refresh_token_enc antigo preservado pelo
        // COALESCE continua cifrado com esse DEK. Trocar o DEK aqui sem re-cifrar
        // o refresh antigo o tornaria indecifrável (§8) — por isso dek_wrapped
        // só entra via excluded (mesmo valor no reconnect).
        const row = db.prepare(`
          INSERT INTO connections
            (id, user_id, provider, account_key, alias, email, display_name, metadata_json, scopes_json,
             access_token_enc, refresh_token_enc, dek_wrapped, expires_at, is_default, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
          ON CONFLICT(user_id, provider, account_key) DO UPDATE SET
            email             = excluded.email,
            display_name      = COALESCE(excluded.display_name, connections.display_name),
            metadata_json     = COALESCE(excluded.metadata_json, connections.metadata_json),
            scopes_json       = excluded.scopes_json,
            access_token_enc  = excluded.access_token_enc,
            refresh_token_enc = COALESCE(excluded.refresh_token_enc, connections.refresh_token_enc),
            dek_wrapped       = excluded.dek_wrapped,
            expires_at        = excluded.expires_at,
            updated_at        = excluded.updated_at
          RETURNING id
        `).get(ulid(), userId, provider, accountKey, alias, email, displayName, metadataJson, scopesJson,
               accessTokenEnc, refreshTokenEnc, dekWrapped, expiresAt, ts, ts);
        db.prepare(`
          UPDATE connections SET is_default = 1
          WHERE id = ? AND NOT EXISTS (
            SELECT 1 FROM connections WHERE user_id = ? AND provider = ? AND is_default = 1
          )
        `).run(row.id, userId, provider);
        return this.findById(row.id);
      });
    },
    findById(id) {
      return db.prepare("SELECT * FROM connections WHERE id = ?").get(id) ?? null;
    },
    // Lookup pela chave de dedup — o callback usa pra reusar o DEK no reconnect
    // (a linha inteira, com dek_wrapped, antes de re-cifrar os tokens).
    findByAccount(userId, provider, accountKey) {
      return (
        db.prepare(
          "SELECT * FROM connections WHERE user_id = ? AND provider = ? AND account_key = ?"
        ).get(userId, provider, accountKey) ?? null
      );
    },
    findDefault(userId, provider) {
      return (
        db.prepare(
          "SELECT * FROM connections WHERE user_id = ? AND provider = ? ORDER BY is_default DESC, created_at ASC LIMIT 1"
        ).get(userId, provider) ?? null
      );
    },
    findByAlias(userId, provider, alias) {
      return (
        db.prepare(
          "SELECT * FROM connections WHERE user_id = ? AND provider = ? AND alias = ?"
        ).get(userId, provider, alias) ?? null
      );
    },
    // Metadata only — nunca expõe *_enc (decisão B: token não sai do cofre).
    listByUser(userId) {
      return db.prepare(`
        SELECT id, provider, account_key, alias, email, display_name, metadata_json, scopes_json,
               expires_at, is_default, created_at, updated_at
        FROM connections WHERE user_id = ? ORDER BY provider, created_at
      `).all(userId);
    },
    setDefault(userId, id) {
      return transaction(() => {
        const conn = this.findById(id);
        if (!conn || conn.user_id !== userId) return false;
        db.prepare("UPDATE connections SET is_default = 0 WHERE user_id = ? AND provider = ?")
          .run(userId, conn.provider);
        db.prepare("UPDATE connections SET is_default = 1 WHERE id = ?").run(id);
        return true;
      });
    },
    updateAlias(userId, id, alias) {
      const conn = this.findById(id);
      if (!conn || conn.user_id !== userId) return false;
      db.prepare("UPDATE connections SET alias = ?, updated_at = ? WHERE id = ?")
        .run(alias, now(), id);
      return true;
    },
    // Pós-refresh (F2): regrava tokens preservando refresh antigo se não veio novo.
    // dekWrapped opcional (§8): quando o refresh de uma linha ainda-v1 sobe pra
    // envelope, o caller passa o dek_wrapped novo junto (self-heal v1→v2). Sem
    // ele, o DEK da linha não muda e o refresh preservado pelo COALESCE segue
    // decifrável — por isso só sobrescreve quando veio.
    updateTokens(id, { accessTokenEnc, refreshTokenEnc = null, dekWrapped = null, expiresAt = null }) {
      db.prepare(`
        UPDATE connections SET
          access_token_enc  = ?,
          refresh_token_enc = COALESCE(?, refresh_token_enc),
          dek_wrapped       = COALESCE(?, dek_wrapped),
          expires_at        = ?,
          updated_at        = ?
        WHERE id = ?
      `).run(accessTokenEnc, refreshTokenEnc, dekWrapped, expiresAt, now(), id);
    },
    remove(id) {
      db.prepare("DELETE FROM connections WHERE id = ?").run(id);
    },
    // Guarda a URL de forward pra onde o zkeys manda eventos webhook do Meta.
    // A org chama setup-webhook passando sua URL (ex: https://protest1.metaorg.app/api/webhooks/whatsapp).
    // Valida ANTES de gravar: URL imparsável aqui viraria forward quebrado em
    // silêncio lá na frente (incidente 2026-10-08 — a org gravou o literal
    // «secret:CLOUDFLARE_BUCKET» na URL e todo evento do WABA foi descartado
    // com "Failed to parse URL", best-effort sem retry).
    setWebhookForwardUrl(id, url) {
      const s = String(url ?? "").trim();
      let parsed;
      try {
        parsed = new URL(s);
      } catch {
        throw new Error(
          `webhook_forward_url inválida: "${s.slice(0, 120)}" não é uma URL válida — ` +
          "informe a URL http(s) completa do webhook da org (ex.: https://<org>.metaorg.app/api/webhooks/whatsapp-mensagem)"
        );
      }
      if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
        throw new Error(
          `webhook_forward_url inválida: protocolo "${parsed.protocol}" não suportado — use http(s)://`
        );
      }
      db.prepare("UPDATE connections SET webhook_forward_url = ?, updated_at = ? WHERE id = ?")
        .run(s, now(), id);
    },
    // Encontra TODAS as connections de um dado WABA (webhook routing).
    // Retorna as linhas com webhook_forward_url não-nula (só as que têm org inscrita).
    findByWabaId(wabaId) {
      return db.prepare(
        "SELECT * FROM connections WHERE provider = 'whatsapp' AND account_key = ? AND webhook_forward_url IS NOT NULL"
      ).all(String(wabaId));
    },
  };

  const workspaceTokens = {
    // F3 usa; schema já nasce completo. Guarda só o hash do zwt_….
    create({ userId, name, tokenHash, scopesJson }) {
      const id = ulid();
      db.prepare(
        "INSERT INTO workspace_tokens (id, user_id, name, token_hash, scopes_json, created_at) VALUES (?, ?, ?, ?, ?, ?)"
      ).run(id, userId, name, tokenHash, scopesJson, now());
      return { id, name };
    },
    findActiveByHash(tokenHash) {
      const row = db.prepare(
        "SELECT * FROM workspace_tokens WHERE token_hash = ? AND revoked_at IS NULL"
      ).get(tokenHash);
      if (row) {
        db.prepare("UPDATE workspace_tokens SET last_used_at = ? WHERE id = ?").run(now(), row.id);
      }
      return row ?? null;
    },
    listByUser(userId) {
      return db.prepare(
        "SELECT id, name, scopes_json, created_at, last_used_at, revoked_at FROM workspace_tokens WHERE user_id = ?"
      ).all(userId);
    },
    revoke(userId, id) {
      const r = db.prepare(
        "UPDATE workspace_tokens SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL"
      ).run(now(), id, userId);
      return r.changes > 0;
    },
  };

  // Trilha de auditoria (§9): connect / revoke / token-issue / login.fail / proxy-deny.
  // Token nunca em log.
  function audit(action, { userId = null, provider = null, detail = null } = {}) {
    db.prepare(
      "INSERT INTO audit_log (id, user_id, action, provider, detail, at) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(ulid(), userId, action, provider, detail, now());
  }

  // Leitura da trilha (F4, §9): só do próprio usuário (isolamento) e nunca
  // devolve token (o audit já não loga segredo). Paginação por id (ULID é
  // monotônico → ordenação estável): before = último id da página anterior.
  const auditLog = {
    listByUser(userId, { limit = 50, before = null } = {}) {
      const cap = Math.min(Math.max(Number(limit) || 50, 1), 200);
      const rows = before
        ? db.prepare(
            "SELECT id, action, provider, detail, at FROM audit_log WHERE user_id = ? AND id < ? ORDER BY id DESC LIMIT ?"
          ).all(userId, String(before), cap)
        : db.prepare(
            "SELECT id, action, provider, detail, at FROM audit_log WHERE user_id = ? ORDER BY id DESC LIMIT ?"
          ).all(userId, cap);
      return rows;
    },
  };

  return { db, users, oauthStates, connections, workspaceTokens, audit, auditLog };
}
