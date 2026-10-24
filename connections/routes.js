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
      const scopes = tokens.scope ?? provider.packs[st.pack]?.scopes ?? [];
      const userRefreshToken = tokens.refreshToken || tokens.accessToken; // User Token = seed de refresh

      // Descoberta plural (pack-aware): Instagram retorna array de contas;
      // WhatsApp cai de volta via discoverAccount singular. Unified Login:
      // falha na descoberta é FATAL (configuração errada) — popup com diagnóstico
      // em vez de gravar connection quebrada com account_key "default".
      let discoveredList = null;   // null = sem descoberta; [] = sem contas; [...] = conexões
      try {
        discoveredList = await provider.discoverAccounts?.(tokens.accessToken, st.pack) ?? null;
      } catch (e) {
        console.warn(`[zkeys/${provider.name}] discoverAccounts falhou:`, e.message);
        if (provider.discoveryKind?.(st.pack) === "unified_instagram") {
          return res.send(popupHtml({ ok: false, message: e.message }));
        }
      }

      // Helper: persiste UMA conexão cifrada e retorna a row.
      const upsertOne = ({ externalId, name = null, metadata = null,
                           accessToken = tokens.accessToken,
                           refreshToken = userRefreshToken,
                           email = profile.email ?? null }) => {
        const accountKey = String(externalId ?? profile.externalId ?? email ?? "default");
        const displayName = name ?? profile.name ?? null;
        const metadataJson = metadata ? JSON.stringify(metadata) : null;
        const existing = store.connections.findByAccount(st.user_id, provider.name, accountKey);
        const box = existing ? cryptoBox.openConnection(existing) : cryptoBox.newConnection();
        const conn = store.connections.upsert({
          userId: st.user_id,
          provider: provider.name,
          accountKey,
          email,
          displayName,
          metadataJson,
          scopesJson: JSON.stringify(scopes),
          accessTokenEnc: box.encrypt(accessToken),
          refreshTokenEnc: refreshToken ? box.encrypt(refreshToken) : null,
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
        return conn;
      };

      if (Array.isArray(discoveredList)) {
        // Descoberta plural: N conexões (uma por conta descoberta).
        if (discoveredList.length === 0) {
          const msg = provider.discoveryKind?.(st.pack) === "unified_instagram"
            ? "Login concluído, mas nenhuma conta Instagram foi compartilhada. "
              + "Confira: (1) a conta é profissional (Business ou Creator)? (2) no login, "
              + "você selecionou o business portfolio E a conta Instagram (não pule/escolha 'continuar sem compartilhar')?"
            : "Nenhuma página com conta Instagram de negócio encontrada. "
              + "Confira se a página está vinculada a um Instagram Business Account.";
          return res.send(popupHtml({ ok: false, message: msg }));
        }
        for (const d of discoveredList) {
          const isPageToken = d.accessToken != null;
          upsertOne({
            externalId: d.externalId,
            name: d.name,
            metadata: d.metadata,
            accessToken: d.accessToken ?? tokens.accessToken,
            // Page Token = accessToken; User Token = refreshToken (seed do _refreshPageToken)
            refreshToken: isPageToken ? userRefreshToken : null,
          });
        }
        const names = discoveredList.map((d) => d.name).filter(Boolean);
        res.send(popupHtml({
          ok: true,
          message: `Conectado${names.length ? `: ${names.slice(0, 4).join(", ")}` + (names.length > 4 ? ` e mais ${names.length - 4}` : "") : ""} — pode fechar esta janela`,
        }));
      } else {
        // Caminho legado (WhatsApp e providers sem account_discovery).
        let discovered = null;
        try {
          discovered = await provider.discoverAccount?.(tokens.accessToken);
        } catch (e) {
          console.warn(`[zkeys/${provider.name}] discoverAccount falhou:`, e.message);
        }
        upsertOne({
          externalId: discovered?.externalId ?? profile.externalId ?? profile.email ?? "default",
          name: discovered?.name ?? profile.name ?? null,
          metadata: discovered?.metadata ?? null,
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          email: profile.email ?? null,
        });
        const asWho = profile.email || discovered?.name;
        res.send(popupHtml({
          ok: true,
          message: `Conectado${asWho ? ` como ${asWho}` : ""} — pode fechar esta janela`,
        }));
      }
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
          connection: conn,
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
