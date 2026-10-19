// Rota curinga do proxy (DESIGN-zkeys §6): ALL /p/:provider/*path → pipeline
// authN → authZ → resolve → fresh → forward.
//
// Gotchas embutidos:
//  - Express 5 exige wildcard nomeado ("*path"; "*" sozinho não compila);
//  - o body chega CRU (express.raw local, qualquer content-type) porque este
//    router monta ANTES dos body parsers globais no index.js — express.json()
//    consumiria o stream e o upstream receberia body vazio. Buffer cru também
//    é o que permite reenviar no retry-on-401.

import express from "express";
import { createProxyPipeline } from "./middleware.js";
import { createForward } from "./forward.js";
import { createMediaDownload } from "./media.js";

export function createProxyRouter({ store, cryptoBox, registry, rateLimit }) {
  const router = express.Router();
  const { ipLimit, tokenLimit, authN, authZ, resolve, fresh, refreshConnection } =
    createProxyPipeline({ store, cryptoBox, registry, rateLimit });
  const forward = createForward({ cryptoBox, refreshConnection });
  const mediaDownload = createMediaDownload({ cryptoBox });

  // GET /proxy/providers — machine-to-machine: catálogo de providers com o
  // MESMO shape do /providers (sessão), mas autenticado por Bearer zwt_. Fecha
  // o gap pra UIs do workspace (ex: página zkeys do shell do agente) montarem
  // "disponíveis pra conectar" sem hardcode — provider novo no registry
  // aparece sozinho (OCP). Sem fluxo OAuth aqui: conectar segue no console.
  router.get(
    "/proxy/providers",
    ipLimit,
    authN,
    tokenLimit,
    (_req, res) => {
      res.json(
        [...registry.values()].map((p) => ({
          name: p.name,
          displayName: p.config.displayName || p.name,
          connectable: p.config.connectable !== false,
          packs: Object.entries(p.packs).map(([id, pk]) => ({
            id, label: pk.label, description: pk.description,
          })),
        }))
      );
    }
  );

  // POST /proxy/invites — machine-to-machine: gera convite de registro NOMINAL
  // (atado a um email, single-use, 7d). authN = mesmo Bearer zwt_ do proxy;
  // authZ EXTRA = o DONO do token ter role=admin no zkeys (§7: só admin convida).
  // Uso: backend do agente expõe "gerar convite" pro admin da org sem entregar
  // sessão humana do zkeys. Dica de least-privilege: crie o zwt_ do operador
  // com escopo ["__invite_only"] — nome que nunca bate com provider, então o
  // token NÃO consegue chamar /p/* (só minta convites).
  router.post(
    "/proxy/invites",
    ipLimit,
    authN,
    tokenLimit,
    express.json(),   // router roda ANTES dos body parsers globais (§6)
    (req, res) => {
      const owner = store.users.findById(req.zkeys.userId);
      if (!owner || owner.role !== "admin") {
        store.audit("invite.deny", {
          userId: req.zkeys.userId,
          detail: `token ${req.zkeys.token.id}: dono não é admin`,
        });
        return res.status(403).json({ error: "só admin do zkeys gera convites" });
      }
      const { email_alvo, note = null } = req.body || {};
      const alvo = email_alvo ? String(email_alvo).trim().toLowerCase() : null;
      if (!alvo || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(alvo)) {
        return res.status(400).json({ error: "email_alvo é obrigatório (convite nominal)" });
      }
      const invite = store.inviteCodes.create({
        createdBy: owner.id,
        note: note ? String(note).slice(0, 200) : null,
        emailAlvo: alvo,
        maxUses: 1,
        ttlDays: 7,
      });
      store.audit("invite.create", {
        userId: owner.id,
        detail: `${invite.code.slice(0, 10)}… p/ ${alvo} (via /proxy/invites)`,
      });
      res.status(201).json({
        code: invite.code,
        email_alvo: invite.email_alvo,
        expires_at: invite.expires_at,
      });
    }
  );

  // GET /proxy/connections — machine-to-machine: lista conexões do usuário
  // autenticado via Bearer zwt_ (mesmo authN do proxy). Metadata only, sem
  // tokens. Fecha o gap DESIGN-zkeys §11 ("agente descobre via GET /connections").
  router.get(
    "/proxy/connections",
    ipLimit,
    authN,
    tokenLimit,
    (req, res) => {
      const connections = store.connections.listByUser(req.zkeys.userId);
      res.json(connections.map((c) => ({
        ...c,
        scopes: JSON.parse(c.scopes_json || "[]"),
        scopes_json: undefined,
        metadata: c.metadata_json ? JSON.parse(c.metadata_json) : null,
        metadata_json: undefined,
      })));
    }
  );

  // Download de mídia (Meta Cloud API): o binário do lookaside exige o token
  // da Meta no header e o workspace só tem o zwt_ — este handler baixa com o
  // token real e strema (token nunca sai do zkeys). Mesmo pipeline do forward;
  // montado ANTES do catch-all pra rota específica vencer.
  router.get(
    "/p/:provider/media/:mediaId/download",
    ipLimit,
    authN,
    tokenLimit,
    authZ,
    resolve,
    fresh,
    mediaDownload
  );

  router.all(
    ["/p/:provider", "/p/:provider/*path"],
    ipLimit,                                   // §9: teto por IP ANTES de bufferizar o body
    express.raw({ type: () => true, limit: "25mb" }),
    authN,
    tokenLimit,                                // §9: teto por token id (pós-authN, alvo real)
    authZ,
    resolve,
    fresh,
    forward
  );

  return router;
}
