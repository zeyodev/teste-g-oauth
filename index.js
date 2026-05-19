// oauth.metaorg.app — proxy puro de providers OAuth (config-driven).
// DESIGN-oauth-credentials.md §2.6: cada provider vive em providers/*.json;
// a classe genérica OAuth2Provider gera as rotas (start/callback/refresh/revoke).
// Adicionar provider novo = JSON novo + env vars; zero refactor de código aqui.

import express from "express";
import "dotenv/config";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import OAuth2Provider from "./lib/OAuth2Provider.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 5000;

// Health
app.get("/healthz", (_req, res) => res.json({ ok: true }));

// Carrega todos os providers em providers/*.json
const providersDir = path.join(__dirname, "providers");
const installed = [];
if (fs.existsSync(providersDir)) {
  for (const file of fs.readdirSync(providersDir).sort()) {
    if (!file.endsWith(".json")) continue;
    try {
      const cfg = JSON.parse(fs.readFileSync(path.join(providersDir, file), "utf8"));
      const provider = new OAuth2Provider(cfg);
      provider.install(app);
      installed.push(provider.name);
    } catch (err) {
      console.error(`[oauth] falha ao carregar ${file}:`, err.message);
    }
  }
}

// Listagem dos providers carregados (debug / discovery)
app.get("/providers", (_req, res) => {
  res.json({ installed });
});

app.listen(PORT, () => {
  console.log(`[oauth] Servidor em http://localhost:${PORT} — providers: ${installed.join(", ") || "(nenhum)"}`);
});
