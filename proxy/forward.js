// Forward do proxy (DESIGN-zkeys §6, passos 5-6): monta a URL upstream com o
// resto do path + query, injeta a credencial conforme auth_injection do
// provider (Strategy em dados — provider novo não muda este código) e STREAMA
// a resposta crua: status + headers + body, sem bufferizar nem normalizar.
//
// Retry-on-401: refresh 1x (single-flight, injetado) e repete; persistindo
// 401, repassa cru — a conexão precisa de re-OAuth. Token nunca em log.

import { Readable } from "node:stream";
import { appsecretProof } from "../providers/hooks/meta_signed_request.js";

// Headers que NUNCA atravessam pro upstream: hop-by-hop (RFC 9110 §7.6.1),
// o que o fetch recalcula, e os internos do zkeys.
const DROP_REQ = new Set([
  "host", "connection", "keep-alive", "transfer-encoding", "upgrade",
  "te", "trailer", "proxy-authorization", "proxy-connection",
  "content-length",  // fetch recalcula do Buffer
  "accept-encoding", // undici negocia e descomprime sozinho
  "authorization",   // o zwt_ NUNCA vai pro upstream — injeta-se o Bearer real
  "cookie",          // sessão zkeys não vaza pra fora
  "x-zkeys-account", // seleção de conta é assunto interno (resolve)
]);

// Headers da resposta que não atravessam de volta: hop-by-hop + os de
// codificação (o fetch já descomprimiu; o stream sai re-chunkado).
const DROP_RES = new Set([
  "connection", "keep-alive", "transfer-encoding", "upgrade", "trailer",
  "proxy-authenticate", "content-encoding", "content-length",
]);

// Recorta o resto CRU do originalUrl (path + query como chegaram no fio).
// Express 5 decodifica req.params do wildcard "*path"; reconstruir a partir
// deles re-encodaria errado — daqui sai byte a byte o que o cliente mandou.
function splitProxyUrl(originalUrl) {
  const m = /^\/p\/[^/?]+([^?]*)(?:\?(.*))?$/.exec(originalUrl);
  return { restPath: m?.[1] || "/", rawQuery: m?.[2] || "" };
}

// Remove um param da query preservando o resto intacto quando ele não existe
// (só re-serializa se precisar mexer).
function stripQueryParam(rawQuery, name) {
  if (!rawQuery) return rawQuery;
  const sp = new URLSearchParams(rawQuery);
  if (!sp.has(name)) return rawQuery;
  sp.delete(name);
  return sp.toString();
}

// Estratégias de injeção de auth (§6): a variação vive em providers/*.json
// (auth_injection), não em if(provider===...) aqui.
const INJECTIONS = {
  bearer({ headers, token }) {
    headers.set("authorization", `Bearer ${token}`);
    return null;
  },
  query({ token, injection }) {
    const param = injection.param || "access_token";
    return `${encodeURIComponent(param)}=${encodeURIComponent(token)}`;
  },
};

// Assinaturas por-provider (§6, OCP): provider.config.sign nomeia qual — a
// exceção do Meta vive aqui num hook fino, não em if(provider===...). Cada
// signer devolve params extras de query e recebe o token EFETIVO da tentativa,
// então é recomputado a cada attempt (o retry-on-401 refaz com o token novo).
const SIGNERS = {
  appsecret_proof({ token, secret }) {
    return `appsecret_proof=${appsecretProof(secret, token)}`;
  },
};

export function createForward({ cryptoBox, refreshConnection }) {
  return async function forward(req, res) {
    const { provider, connection } = req.zkeys;
    const cfg = provider.config;
    if (!cfg.api_base_url) {
      return res.status(502).json({ error: `provider ${provider.name} sem api_base_url` });
    }
    const injection = cfg.auth_injection || { kind: "bearer" };
    const inject = INJECTIONS[injection.kind];
    if (!inject) {
      return res.status(502).json({ error: `auth_injection desconhecida: ${injection.kind}` });
    }
    // Sign hook opcional (§6): validado aqui, aplicado dentro do attempt.
    const sign = cfg.sign ? SIGNERS[cfg.sign] : null;
    if (cfg.sign && !sign) {
      return res.status(502).json({ error: `sign desconhecido: ${cfg.sign}` });
    }

    const { restPath, rawQuery } = splitProxyUrl(req.originalUrl);
    const baseQuery = stripQueryParam(rawQuery, "account");
    // Body chega como Buffer do express.raw (router monta antes dos parsers)
    // — replayável no retry-on-401. GET/HEAD nunca levam body (fetch rejeita).
    const body =
      !["GET", "HEAD"].includes(req.method) && Buffer.isBuffer(req.body) && req.body.length
        ? req.body
        : undefined;

    const attempt = (conn) => {
      const token = cryptoBox.decrypt(conn.access_token_enc);
      const headers = new Headers();
      for (const [k, v] of Object.entries(req.headers)) {
        if (DROP_REQ.has(k)) continue;
        headers.set(k, Array.isArray(v) ? v.join(", ") : String(v));
      }
      const extraQuery = inject({ headers, token, injection });
      let query = extraQuery
        ? (baseQuery ? `${baseQuery}&${extraQuery}` : extraQuery)
        : baseQuery;
      // Sign DEPOIS da injeção (§6): o proof é sobre o token EFETIVO desta
      // tentativa — no retry pós-refresh, `token` já é o novo e o proof muda.
      if (sign) {
        const signQuery = sign({ token, secret: provider.clientSecret });
        query = query ? `${query}&${signQuery}` : signQuery;
      }
      const url =
        cfg.api_base_url.replace(/\/+$/, "") + restPath + (query ? `?${query}` : "");
      // redirect manual: 3xx do upstream atravessa cru (proxy transparente).
      return fetch(url, { method: req.method, headers, body, redirect: "manual" });
    };

    try {
      let upstream = await attempt(req.zkeys.connection);

      // Passo 6 — retry-on-401: refresh 1x e repete. Se o refresh falhar,
      // o 401 original atravessa cru (workspace sabe que precisa re-OAuth).
      if (upstream.status === 401 && req.zkeys.connection.refresh_token_enc) {
        try {
          const freshConn = await refreshConnection(req.zkeys.connection, provider);
          await upstream.body?.cancel();
          upstream = await attempt(freshConn);
        } catch (e) {
          console.warn(`[zkeys/proxy] retry-refresh ${provider.name} falhou: ${e.message}`);
        }
      }

      res.status(upstream.status);
      for (const [k, v] of upstream.headers) {
        if (!DROP_RES.has(k) && k !== "set-cookie") res.setHeader(k, v);
      }
      const setCookies = upstream.headers.getSetCookie();
      if (setCookies.length) res.setHeader("set-cookie", setCookies);
      if (!upstream.body) return res.end();
      const stream = Readable.fromWeb(upstream.body);
      stream.on("error", () => res.destroy());
      stream.pipe(res);
    } catch (e) {
      console.error(`[zkeys/proxy] forward ${provider.name} falhou:`, e.message);
      if (!res.headersSent) {
        res.status(502).json({ error: "falha ao contatar o upstream" });
      } else {
        res.destroy();
      }
    }
  };
}
