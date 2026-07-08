// Workspace tokens (DESIGN-zkeys §7): zwt_… é a API key que o WORKSPACE usa
// no proxy — segredo de alta entropia, aparece UMA vez, o banco guarda só o
// sha-256. Factory (§5): a política do token (formato, entropia, escopo)
// vive aqui, num lugar só.
//
// F2 traz só a emissão mínima (o proxy precisa de um token pra autenticar);
// lista/revogação/UI completam na F3.

import crypto from "crypto";
import express from "express";
import { hashToken } from "../lib/crypto.js";

export function createWorkspaceTokenRoutes({ store, sessions }) {
  const router = express.Router();

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
