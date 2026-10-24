// Instagram webhook setup + status (espelho do whatsapp-setup.js).
//
// Assina os campos de webhook no nível do APP Meta (object=instagram,
// idempotente) e grava a webhook_forward_url da org na connection — o
// graph_webhook.js roteia os eventos por entry.id → account_key.
//
// Diferença do WhatsApp: no Instagram Login (Business Login for Instagram) NÃO
// há passo per-conta (subscribed_apps é conceito de Page/WABA) — a entrega
// segue da autorização do usuário (permissões do config_id) + assinatura
// app-level. Por isso aqui não se usa o token do usuário.
//
// Auth: Bearer zwt_ (machine-to-machine, mesmo padrão do proxy).
//
// POST /auth/instagram/setup-webhook
//   Body: { account_key?, forward_url?, fields? }
//   account_key: user_id/IGSID da conta IG (account_key da connection). Omitido
//     = usa a ÚNICA connection instagram do usuário (409 se houver mais de uma).
// GET /auth/instagram/webhook-status
//   Assinatura app-level + connections instagram do usuário (metadata only).

import crypto from "crypto";
import express from "express";
import { hashToken } from "../lib/crypto.js";

// Campos padrão do webhook Instagram (DM, postbacks de fluxo, reações e comentários).
const DEFAULT_FIELDS = [
  "messages",
  "messaging_postbacks",
  "message_reactions",
  "comments",
  "live_comments",
  "mentions",
].join(",");

export function createInstagramSetupRoutes({ store, registry }) {
  const router = express.Router();
  const instagram = registry.get("instagram");

  // Extrai user_id do Bearer zwt_ (mesmo authN do whatsapp-setup).
  function authZwt(req, res, next) {
    const m = /^Bearer\s+(zwt_[A-Za-z0-9_-]+)$/i.exec(req.headers.authorization || "");
    const token = m ? store.workspaceTokens.findActiveByHash(hashToken(m[1])) : null;
    if (!token) {
      return res.status(401).json({ error: "workspace token ausente, inválido ou revogado" });
    }
    req.zkeysUserId = token.user_id;
    next();
  }

  // Connection alvo: account_key explícito, ou a única connection instagram.
  function findConnection(req, accountKey) {
    if (accountKey) {
      return store.connections.findByAccount(req.zkeysUserId, "instagram", String(accountKey)) || null;
    }
    const all = store.connections
      .listByUser(req.zkeysUserId)
      .filter((c) => c.provider === "instagram");
    if (all.length === 1) return all[0];
    return {
      error: all.length === 0
        ? { status: 404, message: "nenhuma connection instagram — conecte a conta no zkeys primeiro" }
        : { status: 409, message: `usuário tem ${all.length} connections instagram — informe account_key` },
    };
  }

  // GET /auth/instagram/webhook-status — estado da assinatura app-level + connections.
  router.get("/auth/instagram/webhook-status", authZwt, async (req, res) => {
    if (!instagram) return res.status(500).json({ error: "provider instagram não carregado" });
    const appId = instagram.clientId;
    const appToken = `${appId}|${instagram.clientSecret}`;

    const result = { app_subscribed: false, verify_token_configured: Boolean(instagram.webhookVerifyToken), details: {} };
    try {
      const subResp = await fetch(
        `${instagram.config.api_base_url || "https://graph.facebook.com/v23.0"}/${appId}/subscriptions?access_token=${encodeURIComponent(appToken)}`
      );
      const subData = await subResp.json();
      result.details.app_subscriptions = subData;
      const igSub = (subData.data || []).find((s) => s.object === "instagram");
      result.app_subscribed = Boolean(igSub);
      result.fields = igSub?.fields?.map((f) => f.name) || [];
      result.callback_url = igSub?.callback_url || null;
    } catch (e) {
      result.details.app_error = e.message;
    }

    // Connections instagram do usuário (metadata only — nada cifrado sai).
    // findById pra incluir webhook_forward_url (listByUser projeta sem ela).
    result.connections = store.connections
      .listByUser(req.zkeysUserId)
      .filter((c) => c.provider === "instagram")
      .map((c) => store.connections.findById(c.id))
      .filter(Boolean)
      .map((c) => ({
        id: c.id,
        account_key: c.account_key,
        display_name: c.display_name,
        email: c.email,
        forward_url: c.webhook_forward_url || null,
      }));

    res.json(result);
  });

  // POST /auth/instagram/setup-webhook — configura tudo (idempotente).
  router.post("/auth/instagram/setup-webhook", authZwt, async (req, res) => {
    if (!instagram) return res.status(500).json({ error: "provider instagram não carregado" });

    const { account_key, forward_url, fields } = req.body || {};
    const conn = findConnection(req, account_key);
    if (!conn) {
      return res.status(404).json({ error: "conexão instagram não encontrada — conecte a conta no zkeys primeiro" });
    }
    if (conn.error) {
      return res.status(conn.error.status).json({ error: conn.error.message });
    }

    const appId = instagram.clientId;
    const appToken = `${appId}|${instagram.clientSecret}`;
    const verifyToken = instagram.webhookVerifyToken;
    const callbackUrl = `${instagram.publicBaseUrl}/auth/instagram/webhook`;
    const fieldList = fields || DEFAULT_FIELDS;

    const result = { steps: {}, account_key: conn.account_key };

    // Passo 1: App-level subscription (object=instagram; idempotente no Meta).
    if (!verifyToken) {
      result.steps.app_subscription = {
        ok: false,
        error: "INSTAGRAM_WEBHOOK_VERIFY_TOKEN não configurado no zkeys — handshake do webhook vai falhar",
      };
    } else {
      try {
        const subUrl = new URL(`${instagram.config.api_base_url || "https://graph.facebook.com/v23.0"}/${appId}/subscriptions`);
        subUrl.searchParams.set("object", "instagram");
        subUrl.searchParams.set("callback_url", callbackUrl);
        subUrl.searchParams.set("fields", fieldList);
        subUrl.searchParams.set("verify_token", verifyToken);
        subUrl.searchParams.set("include_values", "true");
        subUrl.searchParams.set("access_token", appToken);

        const subResp = await fetch(subUrl.toString(), { method: "POST" });
        const subData = await subResp.json();
        result.steps.app_subscription = { ok: subResp.ok, status: subResp.status, data: subData };

        store.audit("instagram.setup.app-subscription", {
          userId: req.zkeysUserId,
          provider: "instagram",
          detail: `account=${conn.account_key} HTTP ${subResp.status}: ${JSON.stringify(subData).slice(0, 200)}`,
        });
      } catch (e) {
        result.steps.app_subscription = { ok: false, error: e.message };
      }
    }

    // Passo 2: forward_url da org (roteamento dos eventos, graph_webhook.js).
    if (forward_url) {
      try {
        store.connections.setWebhookForwardUrl(conn.id, String(forward_url));
        result.steps.forward_url = { ok: true, url: forward_url };
      } catch (e) {
        result.steps.forward_url = { ok: false, error: e.message };
      }
    } else {
      result.steps.forward_url = { ok: false, info: "forward_url não fornecida — eventos recebidos serão auditados mas não roteados" };
    }

    const allOk = Object.values(result.steps).every((s) => s.ok !== false);
    res.status(allOk ? 200 : 207).json(result);
  });

  return router;
}
