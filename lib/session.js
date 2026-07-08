// Sessão web (DESIGN-zkeys §7): JWT HS256 compacto em cookie httpOnly.
// Implementado com node:crypto (sem dep) — mesmo shape do verify que existia
// no antigo lib/state.js, agora com sign. Factory pattern: a política de
// token (TTL, secret, flags de cookie) vive num lugar só.

import crypto from "crypto";

export const SESSION_COOKIE = "zkeys_session";

const b64url = (buf) => Buffer.from(buf).toString("base64url");

export function createSessions({ secret, ttlSeconds, secure }) {
  if (!secret) throw new Error("[zkeys/session] secret vazio");

  function sign(claims) {
    const header = b64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
    const now = Math.floor(Date.now() / 1000);
    const payload = b64url(
      JSON.stringify({ ...claims, typ: "session", iat: now, exp: now + ttlSeconds })
    );
    const sig = crypto.createHmac("sha256", secret).update(`${header}.${payload}`).digest();
    return `${header}.${payload}.${b64url(sig)}`;
  }

  function verify(token) {
    try {
      const [h, p, s] = String(token || "").split(".");
      if (!h || !p || !s) return null;
      const expected = crypto.createHmac("sha256", secret).update(`${h}.${p}`).digest();
      const got = Buffer.from(s, "base64url");
      if (expected.length !== got.length || !crypto.timingSafeEqual(expected, got)) return null;
      const claims = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
      if (claims.typ !== "session") return null;
      if (!claims.exp || Date.now() / 1000 > claims.exp) return null;
      return claims;
    } catch {
      return null;
    }
  }

  function readCookie(req) {
    for (const part of String(req.headers.cookie || "").split(";")) {
      const [k, ...rest] = part.trim().split("=");
      if (k === SESSION_COOKIE) return decodeURIComponent(rest.join("="));
    }
    return null;
  }

  function cookieAttrs(value, maxAge) {
    const attrs = [
      `${SESSION_COOKIE}=${encodeURIComponent(value)}`,
      "HttpOnly",
      "Path=/",
      "SameSite=Lax",
      `Max-Age=${maxAge}`,
    ];
    if (secure) attrs.push("Secure");
    return attrs.join("; ");
  }

  const setCookie = (res, token) => res.append("Set-Cookie", cookieAttrs(token, ttlSeconds));
  const clearCookie = (res) => res.append("Set-Cookie", cookieAttrs("", 0));

  // Middlewares (Chain of Responsibility do pipeline HTTP)
  function requireSession(req, res, next) {
    const claims = verify(readCookie(req));
    if (!claims) return res.status(401).json({ error: "não autenticado" });
    req.user = { id: claims.sub, email: claims.email, role: claims.role };
    next();
  }

  function requireAdmin(req, res, next) {
    requireSession(req, res, () => {
      if (req.user.role !== "admin") return res.status(403).json({ error: "requer admin" });
      next();
    });
  }

  return { sign, verify, setCookie, clearCookie, requireSession, requireAdmin };
}
