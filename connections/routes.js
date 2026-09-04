// Rotas de conexões (DESIGN-zkeys §4): catálogo, start/callback OAuth e CRUD
// de credenciais. O callback CIFRA E PERSISTE direto no cofre — fim do
// pull-once/_claimStore do broker antigo.
//
// DIP: recebe store/cryptoBox/registry/sessions injetados; nada de env ou
// SQLite direto aqui.

import crypto from "crypto";
import express from "express";
import { pkcePair } from "./OAuth2Provider.js";
import { popupHtml } from "./popup.js";

export function createConnectionRoutes({ store, cryptoBox, registry, sessions, csrf, stateTtlSeconds }) {
  const router = express.Router();
  const { requireSession } = sessions;

  // Catálogo pra UI: providers habilitados + packs de scopes. `connectable:
  // false` (base alias, ex: google-workspace-events) aparece no catálogo mas a
  // UI não oferece o botão Conectar — não há OAuth próprio pra ele.
  router.get("/providers", requireSession, (_req, res) => {
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
  });

  // Início do OAuth: sessão obrigatória. State = 32 bytes aleatórios,
  // persistido atado ao usuário, single-use, TTL curto (§9 anti-CSRF).
  router.get("/auth/:provider/start", requireSession, (req, res) => {
    const provider = registry.get(req.params.provider);
    if (!provider) return res.status(404).send("provider desconhecido");
    // Base alias não tem fluxo OAuth próprio — usa a conexão do provider dono.
    if (provider.config.connectable === false) {
      const owner = provider.config.connection_provider;
      return res.status(400).send(
        `provider ${provider.name} não é conectável — usa a conexão ${owner ?? "de outro provider"}`
      );
    }
    const pack = req.query.pack || Object.keys(provider.packs)[0];
    const packCfg = provider.packs[pack];
    if (!packCfg) return res.status(400).send(`pack desconhecido: ${pack}`);

    const state = crypto.randomBytes(32).toString("base64url");
    let codeVerifier = null;
    let codeChallenge = null;
    if (provider.config.pkce) ({ codeVerifier, codeChallenge } = pkcePair());

    store.oauthStates.purgeExpired(stateTtlSeconds); // higiene oportunista
    store.oauthStates.create({ state, userId: req.user.id, provider: provider.name, pack, codeVerifier });
    // authorize_extra por-pack: Embedded Signup do WhatsApp usa isto pra escolher
    // o modo (número novo vs `featureType: whatsapp_business_app_onboarding` =
    // conectar número existente). Provider-wide authorizeExtra (ex: config_id)
    // continua vindo do JSON; o do pack sobrepõe.
    res.redirect(provider.authorizeUrl({
      state,
      scopes: packCfg.scopes,
      codeChallenge,
      extra: packCfg.authorize_extra || {},
    }));
  });

  // Callback: o state é a autoridade (single-use + TTL) — amarra o code ao
  // usuário que iniciou o flow, sem depender do cookie no redirect.
  router.get("/auth/:provider/callback", async (req, res) => {
    const provider = registry.get(req.params.provider);
    if (!provider) return res.status(404).send("provider desconhecido");
    const { code, state, error, error_description } = req.query;
    if (error) {
      return res.send(popupHtml({ ok: false, message: error_description || error }));
    }
    if (!code || !state) {
      return res.status(400).send(popupHtml({ ok: false, message: "code/state ausente" }));
    }
    const st = store.oauthStates.consume(String(state), stateTtlSeconds);
    if (!st || st.provider !== provider.name) {
      return res.status(400).send(
        popupHtml({ ok: false, message: "state inválido ou expirado — recomece a conexão" })
      );
    }
    try {
      const tokens = await provider.exchangeCodeForTokens({
        code: String(code),
        codeVerifier: st.code_verifier,
      });
      let profile = {};
      try {
        profile = await provider.fetchProfile(tokens.accessToken);
      } catch (e) {
        console.warn(`[zkeys/${provider.name}] profile fetch falhou:`, e.message);
      }
      // Descoberta de conta (WhatsApp ES): resolve waba_id + phone_number_id via
      // Graph, já que sem o SDK não há evento WA_EMBEDDED_SIGNUP. Best-effort —
      // se falhar, cai no profile normal e a conexão ainda é gravada.
      let discovered = null;
      try {
        discovered = await provider.discoverAccount?.(tokens.accessToken);
      } catch (e) {
        console.warn(`[zkeys/${provider.name}] discoverAccount falhou:`, e.message);
      }
      // Dedup por conta: waba_id descoberto > externalId do perfil > email > fixa.
      const accountKey = String(discovered?.externalId ?? profile.externalId ?? profile.email ?? "default");
      const displayName = discovered?.name ?? profile.name ?? null;
      const metadataJson = discovered?.metadata ? JSON.stringify(discovered.metadata) : null;
      const scopes = tokens.scope ?? provider.packs[st.pack]?.scopes ?? [];
      // Envelope (§8): reconexão da MESMA conta reusa o DEK da linha (senão o
      // refresh preservado pelo COALESCE do upsert ficaria com DEK divergente);
      // conta nova sorteia um DEK fresco.
      const existing = store.connections.findByAccount(st.user_id, provider.name, accountKey);
      const box = existing ? cryptoBox.openConnection(existing) : cryptoBox.newConnection();
      const conn = store.connections.upsert({
        userId: st.user_id,
        provider: provider.name,
        accountKey,
        email: profile.email ?? null,
        // Rótulo humano do provider (username/nome/número) — a UI mostra no lugar
        // do account_key cru. Ex: "agentemetaorg" ou o display_phone_number do WA.
        displayName,
        // Metadata não-secreta descoberta no connect (WhatsApp: waba_id +
        // phone_number_id + display_phone_number). NULL pros demais providers.
        metadataJson,
        scopesJson: JSON.stringify(scopes),
        accessTokenEnc: box.encrypt(tokens.accessToken),
        refreshTokenEnc: tokens.refreshToken ? box.encrypt(tokens.refreshToken) : null,
        dekWrapped: box.dekWrapped,
        expiresAt: tokens.expiresIn
          ? new Date(Date.now() + tokens.expiresIn * 1000).toISOString()
          : null,
      });
      store.audit("connection.connect", {
        userId: st.user_id,
        provider: provider.name,
        detail: conn.email || accountKey,
      });
      const asWho = profile.email || discovered?.name;
      res.send(popupHtml({
        ok: true,
        message: `Conectado${asWho ? ` como ${asWho}` : ""} — pode fechar esta janela`,
      }));
    } catch (e) {
      console.error(`[zkeys/${provider.name}] callback erro:`, e);
      res.status(500).send(popupHtml({ ok: false, message: e.message }));
    }
  });

  // Cofre: metadata only — colunas *_enc nunca saem (decisão B, §2).
  router.get("/connections", requireSession, (req, res) => {
    res.json(store.connections.listByUser(req.user.id).map((c) => ({
      ...c,
      scopes: JSON.parse(c.scopes_json || "[]"),
      scopes_json: undefined,
      // metadata não-secreta (WhatsApp: waba_id/phone_number_id). Só o dono vê.
      metadata: c.metadata_json ? JSON.parse(c.metadata_json) : null,
      metadata_json: undefined,
    })));
  });

  router.post("/connections/:id/default", requireSession, csrf.require, (req, res) => {
    if (!store.connections.setDefault(req.user.id, req.params.id)) {
      return res.status(404).json({ error: "conexão não encontrada" });
    }
    res.json({ ok: true });
  });

  router.patch("/connections/:id", requireSession, csrf.require, (req, res) => {
    const alias = req.body?.alias;
    if (typeof alias !== "string") return res.status(400).json({ error: "alias é obrigatório" });
    if (!store.connections.updateAlias(req.user.id, req.params.id, alias.trim() || null)) {
      return res.status(404).json({ error: "conexão não encontrada" });
    }
    res.json({ ok: true });
  });

  // Revoke real no provider (best-effort, §9) + remoção do cofre.
  router.delete("/connections/:id", requireSession, csrf.require, async (req, res) => {
    const conn = store.connections.findById(req.params.id);
    if (!conn || conn.user_id !== req.user.id) {
      return res.status(404).json({ error: "conexão não encontrada" });
    }
    const provider = registry.get(conn.provider);
    if (provider) {
      try {
        const box = cryptoBox.openConnection(conn);   // decifra com o DEK da linha (v1 ou v2)
        await provider.revokeTokens({
          accessToken: box.decrypt(conn.access_token_enc),
          refreshToken: box.decrypt(conn.refresh_token_enc),
        });
      } catch (e) {
        console.warn(`[zkeys/${conn.provider}] revoke no provider falhou (removendo mesmo assim):`, e.message);
      }
    }
    store.connections.remove(conn.id);
    store.audit("connection.revoke", {
      userId: req.user.id,
      provider: conn.provider,
      detail: conn.email || conn.account_key,
    });
    res.json({ ok: true });
  });

  return router;
}
