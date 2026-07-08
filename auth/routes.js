// Auth da plataforma (DESIGN-zkeys §7): sessão web pra humanos.
// Plataforma FECHADA: não há /register público — admin cria usuários
// (POST /auth/users); o primeiro admin nasce via scripts/create-user.js.

import express from "express";

export function createAuthRoutes({ store, passwords, sessions }) {
  const router = express.Router();
  const { requireSession, requireAdmin } = sessions;

  // Hash dummy pré-computado: verify roda mesmo com user inexistente,
  // igualando o timing (sem oráculo de enumeração de email).
  const dummyHashPromise = passwords.hash("dummy-timing-equalizer");

  router.post("/auth/login", async (req, res) => {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: "email e password são obrigatórios" });
    }
    const user = store.users.findByEmail(email);
    const hash = user ? user.password_hash : await dummyHashPromise;
    const ok = (await passwords.verify(hash, password)) && Boolean(user);
    if (!ok) {
      store.audit("login.fail", { detail: String(email).toLowerCase() });
      return res.status(401).json({ error: "credenciais inválidas" });
    }
    sessions.setCookie(res, sessions.sign({ sub: user.id, email: user.email, role: user.role }));
    res.json({ ok: true, user: { id: user.id, email: user.email, role: user.role } });
  });

  router.post("/auth/logout", (_req, res) => {
    sessions.clearCookie(res);
    res.json({ ok: true });
  });

  router.get("/auth/me", requireSession, (req, res) => res.json(req.user));

  router.post("/auth/users", requireAdmin, async (req, res) => {
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
