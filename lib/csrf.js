// CSRF (DESIGN-zkeys §9): double-submit cookie pras rotas WEB que mutam via
// cookie de sessão. O cookie zkeys_csrf é LEGÍVEL por JS (não httpOnly) — a
// proteção é que um site cross-origin não consegue LER o valor pra ecoar no
// header X-CSRF-Token (same-origin policy). O proxy /p/* usa Bearer, não
// cookie → é imune e NÃO passa por aqui (exigir CSRF lá quebraria o workspace).
//
// Factory (§5): política do token num lugar só; DIP — recebe { secure }
// injetado, sem ler env. Stdlib (node:crypto), sem dependência de CSRF.

import crypto from "crypto";

export const CSRF_COOKIE = "zkeys_csrf";
const CSRF_HEADER = "x-csrf-token";

function readCookie(req, name) {
  for (const part of String(req.headers.cookie || "").split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return decodeURIComponent(rest.join("="));
  }
  return null;
}

// Compara dois segredos em tempo constante sem vazar tamanho como oráculo.
function safeEqual(a, b) {
  const ba = Buffer.from(String(a || ""), "utf8");
  const bb = Buffer.from(String(b || ""), "utf8");
  if (ba.length !== bb.length || ba.length === 0) return false;
  return crypto.timingSafeEqual(ba, bb);
}

export function createCsrf({ secure }) {
  function cookieAttrs(value) {
    // Sem HttpOnly de propósito: o cliente precisa LER pra mandar no header.
    const attrs = [`${CSRF_COOKIE}=${encodeURIComponent(value)}`, "Path=/", "SameSite=Lax"];
    if (secure) attrs.push("Secure");
    return attrs.join("; ");
  }

  // Garante um token CSRF pra requisição: reusa o cookie se veio, senão sorteia
  // e o seta na resposta. Devolve o valor (pro handler /auth/csrf ecoar).
  // Memoiza em req: numa mesma request (issue + handler /auth/csrf), evita
  // gerar/Set-Cookie duas vezes (o que corromperia o cabeçalho set-cookie).
  function ensure(req, res) {
    if (req._csrfToken) return req._csrfToken;
    let token = readCookie(req, CSRF_COOKIE);
    if (!token) {
      token = crypto.randomBytes(32).toString("base64url");
      res.append("Set-Cookie", cookieAttrs(token));
    }
    req._csrfToken = token;
    return token;
  }

  // Emite o cookie CSRF em requisições seguras (GET/HEAD/OPTIONS) se ainda não
  // existe — assim o cliente sempre tem um token pra ecoar antes de mutar.
  function issue(req, res, next) {
    if (["GET", "HEAD", "OPTIONS"].includes(req.method)) ensure(req, res);
    next();
  }

  // GET /auth/csrf → { csrfToken }: o cliente lê e manda no header X-CSRF-Token
  // (o cookie zkeys_csrf também é legível via document.cookie; este endpoint é
  // a via explícita, usada pelos testes).
  function token(req, res) {
    res.json({ csrfToken: ensure(req, res) });
  }

  // Exige que o header X-CSRF-Token case com o cookie zkeys_csrf. Aplicado
  // SÓ nas rotas web que mutam via sessão (ver §9); 403 se ausente/divergente.
  function require(req, res, next) {
    const cookie = readCookie(req, CSRF_COOKIE);
    const header = req.headers[CSRF_HEADER];
    if (!cookie || !safeEqual(cookie, header)) {
      return res.status(403).json({ error: "CSRF token ausente ou inválido" });
    }
    next();
  }

  return { issue, require, token };
}
