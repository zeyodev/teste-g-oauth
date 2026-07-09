// Helpers compartilhados dos e2e (F4): CSRF double-submit nas mutações via
// cookie. Como o proxy (Bearer) é imune, isto só vale pras rotas web.

// Busca o token CSRF (GET /auth/csrf seta o cookie zkeys_csrf e ecoa o valor)
// e devolve um construtor de headers pra mutações: manda o cookie de sessão +
// o cookie csrf e o header X-CSRF-Token casando (o servidor confere um contra
// o outro).
export async function mkCsrf(base, sessionCookie) {
  const r = await fetch(`${base}/auth/csrf`, { headers: { cookie: sessionCookie } });
  const setCookie = r.headers.get("set-cookie") || "";
  const csrfCookie = setCookie.split(";")[0];                       // zkeys_csrf=VALUE
  const token = decodeURIComponent(csrfCookie.split("=").slice(1).join("="));
  const cookie = `${sessionCookie}; ${csrfCookie}`;
  return {
    token,
    cookie,
    // headers p/ POST/PATCH/DELETE via cookie: sessão+csrf + header + json.
    headers: (extra = {}) => ({
      cookie,
      "x-csrf-token": token,
      "content-type": "application/json",
      ...extra,
    }),
  };
}
