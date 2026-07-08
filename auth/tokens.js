// Workspace tokens (DESIGN-zkeys §7): zwt_… é a API key que o WORKSPACE usa
// no proxy — segredo de alta entropia, aparece UMA vez, o banco guarda só o
// sha-256. Factory (§5): a política do token (formato, entropia, escopo)
// vive aqui, num lugar só.
//
// F2 trouxe só a emissão mínima (o proxy precisa de um token pra autenticar);
// F3 completa o ciclo: lista (sem o segredo) + revogação. UI em web/.

import crypto from "crypto";
import express from "express";
import { hashToken } from "../lib/crypto.js";

export function createWorkspaceTokenRoutes({ store, sessions }) {
  const router = express.Router();

  // Lista os tokens do usuário: nome/escopos/criado/último uso/revogado.
  // O store nunca devolve o token_hash (§7) — o segredo só existiu na emissão.
  router.get("/auth/workspace-tokens", sessions.requireSession, (req, res) => {
    const rows = store.workspaceTokens.listByUser(req.user.id).map((t) => ({
      id: t.id,
      name: t.name,
      scopes: JSON.parse(t.scopes_json || "[]"),
      created_at: t.created_at,
      last_used_at: t.last_used_at,
      revoked_at: t.revoked_at,
    }));
    res.json(rows);
  });

  // Revoga (seta revoked_at) sem tocar nas conexões. 404 se não for do usuário
  // ou já revogado — o proxy passa a devolver 401 pra esse zwt_ na hora seguinte.
  router.delete("/auth/workspace-tokens/:id", sessions.requireSession, (req, res) => {
    if (!store.workspaceTokens.revoke(req.user.id, req.params.id)) {
      return res.status(404).json({ error: "token não encontrado ou já revogado" });
    }
    store.audit("token.revoke", { userId: req.user.id, detail: req.params.id });
    res.json({ ok: true });
  });

  router.post("/auth/workspace-tokens", sessions.requireSession, (req, res) => {
    const { name, scopes } = req.body || {};
    if (!name || typeof name !== "string" || !name.trim()) {
      return res.status(400).json({ error: "name é obrigatório" });
    }
    if (
      !Array.isArray(scopes) || scopes.length === 0 ||
      !scopes.every((s) => typeof s === "string" && s.trim())
    ) {
      return res.status(400).json({ error: 'scopes: lista de providers, ex ["google"] ou ["*"]' });
    }
    const token = `zwt_${crypto.randomBytes(32).toString("base64url")}`;
    const { id } = store.workspaceTokens.create({
      userId: req.user.id,
      name: name.trim(),
      tokenHash: hashToken(token),
      scopesJson: JSON.stringify(scopes),
    });
    store.audit("token.issue", {
      userId: req.user.id,
      detail: `${name.trim()} [${scopes.join(",")}]`,
    });
    // O segredo sai SÓ nesta resposta — depois só existe o hash.
    res.status(201).json({ id, name: name.trim(), scopes, token });
  });

  return router;
}
