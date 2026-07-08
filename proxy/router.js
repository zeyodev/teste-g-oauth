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

export function createProxyRouter({ store, cryptoBox, registry }) {
  const router = express.Router();
  const { authN, authZ, resolve, fresh, refreshConnection } =
    createProxyPipeline({ store, cryptoBox, registry });
  const forward = createForward({ cryptoBox, refreshConnection });

  router.all(
    ["/p/:provider", "/p/:provider/*path"],
    express.raw({ type: () => true, limit: "25mb" }),
    authN,
    authZ,
    resolve,
    fresh,
    forward
  );

  return router;
}
