// Auditoria exposta (DESIGN-zkeys §9): a trilha já é ESCRITA pelo store; aqui
// ela vira legível pra pessoa dona da conta — sem curl. Isolamento: cada
// usuário só vê os próprios eventos (listByUser filtra por user_id). Token
// nunca aparece (o audit já não loga segredo).
//
// DIP: recebe store/sessions injetados; nada de env ou SQLite direto aqui.

import express from "express";

export function createAuditRoutes({ store, sessions }) {
  const router = express.Router();

  // Últimos N eventos do usuário: connect/revoke, token.issue/revoke,
  // login.fail/ratelimited, proxy.deny/ratelimited, user.create.
  // ?limit=N (1..200, default 50) e ?before=<id> pra paginar.
  router.get("/audit", sessions.requireSession, (req, res) => {
    const rows = store.auditLog.listByUser(req.user.id, {
      limit: req.query.limit,
      before: req.query.before || null,
    });
    res.json(rows);
  });

  return router;
}
