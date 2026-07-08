// Carrega providers/*.json num registry Map(name → OAuth2Provider).
// OCP: provider novo = JSON novo (+ hook opcional em providers/hooks/);
// o resto do app itera o registry sem conhecer providers específicos (LSP).

import fs from "fs";
import path from "path";
import OAuth2Provider from "./OAuth2Provider.js";
import metaSignedRequest from "../providers/hooks/meta_signed_request.js";

// Hooks nomeados que os JSONs podem referenciar em `extensions`.
export const HOOKS = {
  meta_signed_request: metaSignedRequest,
};

export function loadProviders({ providersDir, publicBaseUrl, env = process.env }) {
  const registry = new Map();
  if (!fs.existsSync(providersDir)) return registry;
  for (const file of fs.readdirSync(providersDir).sort()) {
    if (!file.endsWith(".json")) continue;
    try {
      const cfg = JSON.parse(fs.readFileSync(path.join(providersDir, file), "utf8"));
      const provider = new OAuth2Provider(cfg, { publicBaseUrl, env });
      if (!provider.enabled) {
        console.warn(
          `[zkeys/${provider.name}] desabilitado: env ${cfg.client_id_env}/${cfg.client_secret_env} ausentes`
        );
        continue;
      }
      registry.set(provider.name, provider);
    } catch (err) {
      console.error(`[zkeys] falha ao carregar ${file}:`, err.message);
    }
  }
  return registry;
}
