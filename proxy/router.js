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

export function createProxyRouter({ store, cryptoBox, registry, rateLimit }) {
  const router = express.Router();
  const { ipLimit, tokenLimit, authN, authZ, resolve, fresh, refreshConnection } =
    createProxyPipeline({ store, cryptoBox, registry, rateLimit });
  const forward = createForward({ cryptoBox, refreshConnection });

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
