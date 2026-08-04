// WhatsApp webhook subscription + phone registration (DESIGN-zkeys §11.5 follow-up).
//
// Usa app credentials (WHATSAPP_APP_ID, WHATSAPP_APP_SECRET) pra subscription
// no nível do app Meta, e o token OAuth do usuário (decifrado do cofre) pra
// inscrição do WABA + registro do número.
//
// Auth: Bearer zwt_ (machine-to-machine, mesmo padrão do proxy).
//
// POST /auth/whatsapp/setup-webhook
//   Body: { waba_id, phone_number_id, pin?, fields? }
//   Usa app credentials pra POST /{app_id}/subscriptions (app-level, idempotente),
//   token do usuário pra POST /{waba_id}/subscribed_apps + POST /{phone_id}/register.
//   Retorna status de cada passo.

import crypto from "crypto";
import express from "express";
import { hashToken } from "../lib/crypto.js";

const GRAPH_BASE = "https://graph.facebook.com/v23.0";

// Campos padrão pra WhatsApp Cloud API webhook.
const DEFAULT_FIELDS = [
  "messages",
  "message_template_status_update",
  "message_template_quality_update",
].join(",");

export function createWhatsAppSetupRoutes({ store, cryptoBox, registry }) {
  const router = express.Router();
  const whatsapp = registry.get("whatsapp");

  // Extrai user_id do Bearer zwt_ (mesmo authN do proxy, sem rate limit).
  function authZwt(req, res, next) {
    const m = /^Bearer\s+(zwt_[A-Za-z0-9_-]+)$/i.exec(req.headers.authorization || "");
    const token = m ? store.workspaceTokens.findActiveByHash(hashToken(m[1])) : null;
    if (!token) {
      return res.status(401).json({ error: "workspace token ausente, inválido ou revogado" });
    }
    req.zkeysUserId = token.user_id;
    next();
  }

  // GET /auth/whatsapp/webhook-status — consulta o estado atual no Meta.
  router.get("/auth/whatsapp/webhook-status", authZwt, async (req, res) => {
    if (!whatsapp) return res.status(500).json({ error: "provider whatsapp não carregado" });
    const appId = whatsapp.clientId;
    const appToken = `${appId}|${whatsapp.clientSecret}`;

    const result = { app_subscribed: false, waba_subscribed: false, phone_registered: false, details: {} };

    // 1. App-level subscriptions (usa app token)
    try {
      const subResp = await fetch(`${GRAPH_BASE}/${appId}/subscriptions?access_token=${encodeURIComponent(appToken)}`);
      const subData = await subResp.json();
      result.details.app_subscriptions = subData;
      const wabaSubs = (subData.data || []).filter(
        (s) => s.object === "whatsapp_business_account"
      );
      result.app_subscribed = wabaSubs.length > 0;
    } catch (e) {
      result.details.app_error = e.message;
    }

    // 2. WABA subscribed_apps (usa token do usuário)
    const { waba_id, phone_number_id } = req.query;
    if (waba_id) {
      try {
        const conn = store.connections.findByAccount(req.zkeysUserId, "whatsapp", String(waba_id));
        if (conn) {
          const box = cryptoBox.openConnection(conn);
          const userToken = box.decrypt(conn.access_token_enc);
          const wabaResp = await fetch(
            `${GRAPH_BASE}/${encodeURIComponent(waba_id)}/subscribed_apps?access_token=${encodeURIComponent(userToken)}`
          );
          const wabaData = await wabaResp.json();
          result.details.waba_subscribed_apps = wabaData;
          result.waba_subscribed = (wabaData.data || []).length > 0;
        } else {
          result.details.waba_error = "conexão whatsapp não encontrada pra este WABA";
        }
      } catch (e) {
        result.details.waba_error = e.message;
      }
    }

    // 3. Phone registration status
    if (phone_number_id) {
      try {
        const conn = store.connections.findByAccount(req.zkeysUserId, "whatsapp", String(waba_id || ""));
        if (conn) {
          const box = cryptoBox.openConnection(conn);
          const userToken = box.decrypt(conn.access_token_enc);
          const phoneResp = await fetch(
            `${GRAPH_BASE}/${encodeURIComponent(phone_number_id)}?fields=code_verification_status,display_phone_number,quality_rating&access_token=${encodeURIComponent(userToken)}`
          );
          const phoneData = await phoneResp.json();
          result.details.phone = phoneData;
          result.phone_registered = phoneData.code_verification_status === "VERIFIED";
        }
      } catch (e) {
        result.details.phone_error = e.message;
      }
    }

    res.json(result);
  });

  // POST /auth/whatsapp/setup-webhook — configura tudo (idempotente).
  router.post("/auth/whatsapp/setup-webhook", authZwt, async (req, res) => {
    if (!whatsapp) return res.status(500).json({ error: "provider whatsapp não carregado" });

    const { waba_id, phone_number_id, pin, fields } = req.body || {};
    if (!waba_id) return res.status(400).json({ error: "waba_id é obrigatório" });

    const conn = store.connections.findByAccount(req.zkeysUserId, "whatsapp", String(waba_id));
    if (!conn) {
      return res.status(404).json({ error: "conexão whatsapp não encontrada pra este WABA — conecte primeiro no zkeys" });
    }

    const appId = whatsapp.clientId;
    const appSecret = whatsapp.clientSecret;
    const appToken = `${appId}|${appSecret}`;
    const verifyToken = whatsapp.webhookVerifyToken;
    const callbackUrl = `${whatsapp.publicBaseUrl}/auth/whatsapp/webhook`;
    const fieldList = fields || DEFAULT_FIELDS;
    const box = cryptoBox.openConnection(conn);

    let userToken;
    try {
      userToken = box.decrypt(conn.access_token_enc);
    } catch (e) {
      return res.status(500).json({ error: `falha ao decifrar token do usuário: ${e.message}` });
    }

    const result = { steps: {} };

    // Passo 1: App-level subscription (idempotente — Meta retorna sucesso se já existe).
    try {
      const subUrl = new URL(`${GRAPH_BASE}/${appId}/subscriptions`);
      subUrl.searchParams.set("object", "whatsapp_business_account");
      subUrl.searchParams.set("callback_url", callbackUrl);
      subUrl.searchParams.set("fields", fieldList);
      subUrl.searchParams.set("verify_token", verifyToken);
      subUrl.searchParams.set("include_values", "true");
      subUrl.searchParams.set("access_token", appToken);

      const subResp = await fetch(subUrl.toString(), { method: "POST" });
      const subData = await subResp.json();
      result.steps.app_subscription = { ok: subResp.ok, status: subResp.status, data: subData };

      if (!subResp.ok && subResp.status !== 400) {
        // 400 pode ser "already subscribed" — não é erro fatal.
        store.audit("whatsapp.setup.app-subscription", {
          userId: req.zkeysUserId,
          provider: "whatsapp",
          detail: `HTTP ${subResp.status}: ${JSON.stringify(subData).slice(0, 200)}`,
        });
      }
    } catch (e) {
      result.steps.app_subscription = { ok: false, error: e.message };
    }

    // Passo 2: WABA subscription ao app (usa user token).
    try {
      const wabaUrl = `${GRAPH_BASE}/${encodeURIComponent(waba_id)}/subscribed_apps`;
      const wabaResp = await fetch(wabaUrl, {
        method: "POST",
        headers: { Authorization: `Bearer ${userToken}` },
      });
      const wabaData = await wabaResp.json();
      result.steps.waba_subscription = { ok: wabaResp.ok, status: wabaResp.status, data: wabaData };

      store.audit("whatsapp.setup.waba-subscription", {
        userId: req.zkeysUserId,
        provider: "whatsapp",
        detail: `waba=${waba_id} HTTP ${wabaResp.status}: ${JSON.stringify(wabaData).slice(0, 200)}`,
      });
    } catch (e) {
      result.steps.waba_subscription = { ok: false, error: e.message };
    }

    // Passo 3: Phone number registration (se pin fornecido).
    if (phone_number_id && pin) {
      try {
        const regUrl = `${GRAPH_BASE}/${encodeURIComponent(phone_number_id)}/register`;
        const regResp = await fetch(regUrl, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${userToken}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ messaging_product: "whatsapp", pin: String(pin) }),
        });
        const regData = await regResp.json();
        result.steps.phone_registration = { ok: regResp.ok, status: regResp.status, data: regData };

        store.audit("whatsapp.setup.phone-register", {
          userId: req.zkeysUserId,
          provider: "whatsapp",
          detail: `phone=${phone_number_id} HTTP ${regResp.status}`,
        });
      } catch (e) {
        result.steps.phone_registration = { ok: false, error: e.message };
      }
    } else if (phone_number_id) {
      result.steps.phone_registration = { ok: false, info: "pin não fornecido — pule este passo ou forneça o PIN de 6 dígitos" };
    }

    // Passo 4: Guarda a forward_url na connection pra roteamento de eventos (stage 3).
    if (req.body.forward_url) {
      try {
        store.connections.setWebhookForwardUrl(conn.id, String(req.body.forward_url));
        result.steps.forward_url = { ok: true, url: req.body.forward_url };
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
