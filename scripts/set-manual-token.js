// Cadastra uma credencial MANUAL (não-OAuth) como connection no cofre.
//
// Pra providers cujo token NÃO vem de OAuth de usuário — ex: WhatsApp Cloud API,
// que autentica com um token PERMANENTE de System User (Business Settings), não
// pelo dialog/oauth. O token é cifrado com envelope (DEK novo por linha, §8) e
// gravado via o mesmo upsert do callback OAuth, então o proxy /p/<provider>/*
// passa a usá-lo igual a qualquer conexão.
//
// Uso:
//   node scripts/set-manual-token.js --provider whatsapp --email admin@x.dev \
//     --account <phone_number_id> --token <SYSTEM_USER_TOKEN> [--alias <label>] [--name <label>]
//
// --account  chave de dedup (use o phone_number_id do WhatsApp).
// --alias    rótulo pra selecionar a conta no proxy (?account=<alias>).
// --name     display_name mostrado na UI (default = --alias ou --account).

import { loadConfig } from "../config.js";
import { createStore } from "../lib/store.js";
import { createCrypto } from "../lib/crypto.js";
import { loadProviders } from "../connections/registry.js";

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : undefined;
}

const providerName = arg("provider");
const email = arg("email");
const account = arg("account");
const token = arg("token");
const alias = arg("alias") || null;
const name = arg("name") || alias || account;

if (!providerName || !email || !account || !token) {
  console.error(
    "uso: node scripts/set-manual-token.js --provider <p> --email <user> " +
    "--account <key> --token <TOKEN> [--alias <label>] [--name <label>]"
  );
  process.exit(1);
}

const config = loadConfig();
const store = createStore(config.dbPath);
const cryptoBox = createCrypto(config.masterKey);
const registry = loadProviders({ providersDir: config.providersDir, publicBaseUrl: config.publicBaseUrl });

const provider = registry.get(providerName);
if (!provider) {
  console.error(`provider desconhecido ou desabilitado: ${providerName} (habilitados: ${[...registry.keys()].join(", ")})`);
  process.exit(1);
}
const user = store.users.findByEmail(email);
if (!user) {
  console.error(`usuário não encontrado: ${email}`);
  process.exit(1);
}

// Scopes = os do primeiro pack do provider (referência; o token permanente já
// carrega as permissões do System User). Sem refresh_token: token não expira.
const scopes = Object.values(provider.packs)[0]?.scopes ?? [];
// Reconexão da mesma conta reusa o DEK da linha; conta nova sorteia um DEK.
const existing = store.connections.findByAccount(user.id, providerName, account);
const box = existing ? cryptoBox.openConnection(existing) : cryptoBox.newConnection();

const conn = store.connections.upsert({
  userId: user.id,
  provider: providerName,
  accountKey: account,
  alias,
  displayName: name,
  scopesJson: JSON.stringify(scopes),
  accessTokenEnc: box.encrypt(token),
  refreshTokenEnc: null,        // token permanente — sem refresh
  dekWrapped: box.dekWrapped,
  expiresAt: null,
});
store.audit("connection.connect", { userId: user.id, provider: providerName, detail: `manual:${account}` });

console.log(`✓ conexão ${providerName} gravada: id=${conn.id} account=${account} alias=${alias ?? "—"} default=${!!conn.is_default}`);
