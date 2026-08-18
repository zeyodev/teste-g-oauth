// Download de mídia do Meta Graph (WhatsApp/Instagram Cloud API) com o token
// real do cofre — DESIGNS §6: o binário do lookaside.fbsbx.com exige o access
// token da Meta no header `Authorization`, e o workspace só tem um zwt_ (que o
// lookaside rejeita). Este handler roda no MESMO pipeline do proxy (authN →
// authZ → resolve → fresh), busca a URL do binário via {media_id} com o token
// real e STREMA o arquivo de volta. O token cru nunca sai do zkeys (§3, B).
//
// Habilitado por provider via `"media_download": true` no providers/*.json
// (Strategy em dados — o núcleo do proxy não conhece "Meta").

import { Readable } from "node:stream";
import { appsecretProof } from "../providers/hooks/meta_signed_request.js";

export function createMediaDownload({ cryptoBox }) {
  return async function mediaDownload(req, res) {
    const { provider, connection } = req.zkeys;
    const cfg = provider.config;
    const mediaId = req.params.mediaId;
    if (!mediaId) return res.status(400).json({ error: "media_id ausente" });
    if (!cfg.media_download) return res.status(404).json({ error: "download de mídia indisponível para este provider" });
    if (!cfg.api_base_url) return res.status(502).json({ error: `provider ${provider.name} sem api_base_url` });

    const token = cryptoBox.openConnection(connection).decrypt(connection.access_token_enc);
    const base = cfg.api_base_url.replace(/\/+$/, "");
    const proof = appsecretProof(provider.clientSecret, token);

    try {
      // Passo 1 — metadata: GET {media_id} → {url, mime_type, file_size}.
      // O Graph exige appsecret_proof do Meta junto do Bearer real.
      const metaResp = await fetch(
        `${base}/${encodeURIComponent(mediaId)}?appsecret_proof=${proof}`,
        { headers: { authorization: `Bearer ${token}` }, redirect: "manual" },
      );
      if (!metaResp.ok) {
        const body = await metaResp.text().catch(() => "");
        return res.status(metaResp.status).json({ error: `Graph ${metaResp.status}`, detail: body.slice(0, 200) });
      }
      const meta = await metaResp.json();
      if (!meta?.url) {
        return res.status(502).json({ error: "Graph não devolveu url de mídia", detail: JSON.stringify(meta).slice(0, 200) });
      }

      // Passo 2 — binário: a URL do lookaside só responde com o token da Meta
      // no header. Streama cru (status/headers/body), como o forward genérico.
      const binResp = await fetch(meta.url, { headers: { authorization: `Bearer ${token}` } });
      if (!binResp.ok) {
        const body = await binResp.text().catch(() => "");
        return res.status(binResp.status).json({ error: `download ${binResp.status}`, detail: body.slice(0, 200) });
      }

      res.status(200);
      res.setHeader(
        "content-type",
        binResp.headers.get("content-type") || meta.mime_type || "application/octet-stream",
      );
      res.setHeader("x-meta-mime-type", meta.mime_type || "");
      res.setHeader("x-meta-file-size", String(meta.file_size ?? ""));
      if (!binResp.body) return res.end();
      const stream = Readable.fromWeb(binResp.body);
      stream.on("error", () => res.destroy());
      stream.pipe(res);
    } catch (e) {
      console.error(`[zkeys/media] download ${provider.name}/${mediaId} falhou:`, e.message);
      if (!res.headersSent) {
        res.status(502).json({ error: "falha ao baixar a mídia" });
      } else {
        res.destroy();
      }
    }
  };
}
