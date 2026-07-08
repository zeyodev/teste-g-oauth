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

export function createStore(dbPath) {
  if (dbPath !== ":memory:") fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA journal_mode=WAL;");
  db.exec("PRAGMA foreign_keys=ON;");
  db.exec(SCHEMA);

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
    upsert({ userId, provider, accountKey, alias = null, email = null, scopesJson,
             accessTokenEnc, refreshTokenEnc = null, expiresAt = null }) {
      return transaction(() => {
        const ts = now();
        const row = db.prepare(`
          INSERT INTO connections
            (id, user_id, provider, account_key, alias, email, scopes_json,
             access_token_enc, refresh_token_enc, expires_at, is_default, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
          ON CONFLICT(user_id, provider, account_key) DO UPDATE SET
            email             = excluded.email,
            scopes_json       = excluded.scopes_json,
            access_token_enc  = excluded.access_token_enc,
            refresh_token_enc = COALESCE(excluded.refresh_token_enc, connections.refresh_token_enc),
            expires_at        = excluded.expires_at,
            updated_at        = excluded.updated_at
          RETURNING id
        `).get(ulid(), userId, provider, accountKey, alias, email, scopesJson,
               accessTokenEnc, refreshTokenEnc, expiresAt, ts, ts);
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
        SELECT id, provider, account_key, alias, email, scopes_json,
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
    updateTokens(id, { accessTokenEnc, refreshTokenEnc = null, expiresAt = null }) {
      db.prepare(`
        UPDATE connections SET
          access_token_enc  = ?,
          refresh_token_enc = COALESCE(?, refresh_token_enc),
          expires_at        = ?,
          updated_at        = ?
        WHERE id = ?
      `).run(accessTokenEnc, refreshTokenEnc, expiresAt, now(), id);
    },
    remove(id) {
      db.prepare("DELETE FROM connections WHERE id = ?").run(id);
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

  return { db, users, oauthStates, connections, workspaceTokens, audit };
}
