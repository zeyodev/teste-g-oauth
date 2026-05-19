// Cliente server-to-server pro metaorg/backend. Envia POST com x-oauth-token
// (segredo compartilhado, similar ao AGENT_SHARED_TOKEN). O backend valida o
// header e o `state` JWT antes de aplicar mutações.

export function backendBaseUrl() {
  const url = process.env.METAORG_BACKEND_URL || process.env.METAORG_API;
  if (!url) throw new Error("METAORG_BACKEND_URL/METAORG_API não configurado");
  return url.replace(/\/$/, "");
}

function backendToken() {
  const tok = process.env.OAUTH_BACKEND_TOKEN;
  if (!tok) throw new Error("OAUTH_BACKEND_TOKEN não configurado");
  return tok;
}

export async function backendPost(path, body) {
  const resp = await fetch(`${backendBaseUrl()}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "accept": "application/json",
      "x-oauth-token": backendToken(),
    },
    body: JSON.stringify(body),
  });
  const text = await resp.text();
  let parsed;
  try { parsed = text ? JSON.parse(text) : null; } catch { parsed = text; }
  if (!resp.ok) {
    const detail = typeof parsed === "string" ? parsed : JSON.stringify(parsed);
    const err = new Error(`backend ${path} HTTP ${resp.status}: ${detail.slice(0, 300)}`);
    err.status = resp.status;
    err.body = parsed;
    throw err;
  }
  return parsed;
}
