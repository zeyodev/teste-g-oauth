// Auth da plataforma (DESIGN-zkeys §7): sessão web pra humanos.
// Plataforma FECHADA por default: admin cria usuários (POST /auth/users); o
// primeiro admin nasce via scripts/create-user.js OU pelo bootstrap web (§7 —
// banco sem usuários aceita o primeiro POST /auth/register como admin).
// ZKEYS_REGISTER_MODE=invite|open libera o self-serve (com convite / aberto).

import express from "express";

// rateLimit = limiter do login (§9): teto por IP e por email. csrf protege as
// rotas web que mutam (POST /auth/users, /auth/invites); login/register ficam
// de fora (não há sessão ainda; são gateados por rate limit + credenciais).
export function createAuthRoutes({ store, passwords, sessions, rateLimit, csrf, registerMode = "closed" }) {
  const router = express.Router();
  const { requireSession, requireAdmin } = sessions;

  // Hash dummy pré-computado: verify roda mesmo com user inexistente,
  // igualando o timing (sem oráculo de enumeração de email).
  const dummyHashPromise = passwords.hash("dummy-timing-equalizer");

  // 429 + Retry-After sem vazar se o email existe (mesmo shape pra IP e email).
  function tooMany(res, r) {
    res.set("Retry-After", String(r.retryAfterSeconds));
    return res.status(429).json({ error: "muitas tentativas — tente mais tarde" });
  }

  router.post("/auth/login", async (req, res) => {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "email e password são obrigatórios" });
    }
    // Teto por IP ANTES de verificar a senha (barato, corta o brute-force cedo).
    const ipHit = rateLimit.check(`ip:${req.ip}`);
    if (ipHit.limited) {
      store.audit("login.ratelimited", { detail: `ip:${req.ip}` });
      return tooMany(res, ipHit);
    }
    const user = store.users.findByEmail(email);
    const hash = user ? user.password_hash : await dummyHashPromise;
    const ok = (await passwords.verify(hash, password)) && Boolean(user);
    if (!ok) {
      // Conta a falha no teto por email (só falhas contam; sucesso libera).
      const emailHit = rateLimit.check(`email:${String(email).toLowerCase()}`);
      store.audit("login.fail", { detail: String(email).toLowerCase() });
      if (emailHit.limited) {
        store.audit("login.ratelimited", { detail: `email:${String(email).toLowerCase()}` });
        return tooMany(res, emailHit);
      }
      return res.status(401).json({ error: "credenciais inválidas" });
    }
    // Login bom zera o contador do email (não pune o dono da conta).
    rateLimit.reset(`email:${String(email).toLowerCase()}`);
    sessions.setCookie(res, sessions.sign({ sub: user.id, email: user.email, role: user.role }));
    res.json({ ok: true, user: { id: user.id, email: user.email, role: user.role } });
  });

  router.post("/auth/logout", (_req, res) => {
    sessions.clearCookie(res);
    res.json({ ok: true });
  });

  // ── Registro self-serve (§7) ────────────────────────────────────────────
  // Modo efetivo: closed | invite | open — MAS banco sem nenhum usuário
  // registra o primeiro como admin em qualquer modo (bootstrap web).
  const effectiveMode = () => (store.users.count() === 0 ? "first_user" : registerMode);

  // Público: a tela de login consulta pra decidir se mostra o form "criar
  // conta" (e o campo de código de convite). first_user = bootstrap aberto.
  router.get("/auth/register-mode", (_req, res) => {
    const mode = effectiveMode();
    res.json({ mode, invite_required: mode === "invite", first_user: mode === "first_user" });
  });

  router.post("/auth/register", async (req, res) => {
    const { email, password, invite_code } = req.body || {};
    const mode = effectiveMode();
    if (mode === "closed") {
      return res.status(403).json({ error: "registro desabilitado — admin cria usuários (POST /auth/users)" });
    }
    if (!email || !password) {
      return res.status(400).json({ error: "email e password são obrigatórios" });
    }
    const normEmail = String(email).trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(normEmail)) {
      return res.status(400).json({ error: "email inválido" });
    }
    if (String(password).length < 8) {
      return res.status(400).json({ error: "password: mínimo 8 caracteres" });
    }
    // Teto por IP compartilhando a política do login (mesma máquina de falhas:
    // só registro FALHO conta — sucesso libera).
    const ipHit = rateLimit.check(`ip:${req.ip}`);
    if (ipHit.limited) {
      store.audit("register.ratelimited", { detail: `ip:${req.ip}` });
      return tooMany(res, ipHit);
    }
    // invite: valida SEM consumir (não queima código se o email já existe);
    // o consumo atômico (esgotado/expirado/corrida) acontece no fim.
    if (mode === "invite") {
      if (!invite_code || !store.inviteCodes.findActive(invite_code)) {
        rateLimit.check(`email:${normEmail}`);
        store.audit("register.fail", { detail: `convite inválido (${normEmail})` });
        return res.status(403).json({ error: "código de convite inválido, esgotado ou expirado" });
      }
    }
    if (store.users.findByEmail(normEmail)) {
      store.audit("register.fail", { detail: `email duplicado (${normEmail})` });
      return res.status(409).json({ error: "email já cadastrado — faça login" });
    }
    if (mode === "invite" && !store.inviteCodes.consume(invite_code)) {
      store.audit("register.fail", { detail: `convite esgotado na corrida (${normEmail})` });
      return res.status(403).json({ error: "código de convite inválido, esgotado ou expirado" });
    }
    // Bootstrap (§7): primeiro usuário do banco vira admin, independente do modo.
    const role = mode === "first_user" ? "admin" : "user";
    const user = store.users.create({ email: normEmail, passwordHash: await passwords.hash(password), role });
    store.audit("user.register", { userId: user.id, detail: `${user.email} (${role})${mode === "first_user" ? " — bootstrap web" : ""}` });
    // Já entra logado (mesma sessão do login) — o form segue direto pro app.
    sessions.setCookie(res, sessions.sign({ sub: user.id, email: user.email, role: user.role }));
    res.status(201).json({ ok: true, user });
  });

  // ── Convites (modo invite; admin) ──────────────────────────────────────
  // Gera código e o devolve UMA vez na resposta (a UI oferece copiar). O
  // audit guarda só o formato/metadados — o código em si fica na resposta.
  router.get("/auth/invites", requireAdmin, (req, res) => {
    res.json(store.inviteCodes.list().map((c) => ({
      code: c.code,
      note: c.note,
      uses: c.uses,
      max_uses: c.max_uses,
      expires_at: c.expires_at,
      created_at: c.created_at,
      active: c.uses < c.max_uses && (!c.expires_at || Date.parse(c.expires_at) > Date.now()),
    })));
  });

  router.post("/auth/invites", requireAdmin, csrf.require, (req, res) => {
    const { note = null, max_uses = 1, ttl_days = 7 } = req.body || {};
    if (max_uses != null && (!Number.isInteger(max_uses) || max_uses < 1 || max_uses > 100)) {
      return res.status(400).json({ error: "max_uses: inteiro 1–100" });
    }
    if (ttl_days != null && (!Number.isInteger(ttl_days) || ttl_days < 1 || ttl_days > 90)) {
      return res.status(400).json({ error: "ttl_days: inteiro 1–90" });
    }
    const invite = store.inviteCodes.create({
      createdBy: req.user.id,
      note: note ? String(note).slice(0, 200) : null,
      maxUses: max_uses,
      ttlDays: ttl_days,
    });
    store.audit("invite.create", {
      userId: req.user.id,
      detail: `${invite.code.slice(0, 10)}… (uses≤${invite.max_uses}, exp ${invite.expires_at ?? "nunca"})`,
    });
    res.status(201).json(invite);
  });

  router.get("/auth/me", requireSession, (req, res) => res.json(req.user));

  router.post("/auth/users", requireAdmin, csrf.require, async (req, res) => {
    const { email, password, role = "user" } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "email e password são obrigatórios" });
    }
    if (!["admin", "user"].includes(role)) {
      return res.status(400).json({ error: "role inválido (admin|user)" });
    }
    if (String(password).length < 8) {
      return res.status(400).json({ error: "password: mínimo 8 caracteres" });
    }
    if (store.users.findByEmail(email)) {
      return res.status(409).json({ error: "email já cadastrado" });
    }
    const user = store.users.create({ email, passwordHash: await passwords.hash(password), role });
    store.audit("user.create", { userId: req.user.id, detail: `${user.email} (${role})` });
    res.status(201).json(user);
  });

  return router;
}
