// Bootstrap de usuário (plataforma fechada, DESIGN-zkeys §7) — espelha o
// create_user.py do agente. O primeiro admin nasce por aqui; os demais podem
// vir de POST /auth/users.
//
// Uso: node scripts/create-user.js --email x@y.z --password 'senha' [--role admin]

import { loadConfig } from "../config.js";
import { createStore } from "../lib/store.js";
import { createPasswords } from "../lib/passwords.js";

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i > -1 ? process.argv[i + 1] : undefined;
}

const email = arg("email");
const password = arg("password");
const role = arg("role") || "user";

if (!email || !password) {
  console.error("uso: node scripts/create-user.js --email x@y.z --password 'senha' [--role admin|user]");
  process.exit(1);
}
if (!["admin", "user"].includes(role)) {
  console.error(`role inválido: ${role} (admin|user)`);
  process.exit(1);
}
if (password.length < 8) {
  console.error("password: mínimo 8 caracteres");
  process.exit(1);
}

const config = loadConfig();
const store = createStore(config.dbPath);
const passwords = createPasswords(config.pepper);

if (store.users.findByEmail(email)) {
  console.error(`email já cadastrado: ${email}`);
  process.exit(1);
}

const user = store.users.create({ email, passwordHash: await passwords.hash(password), role });
store.audit("user.create", { detail: `${user.email} (${role}) via create-user.js` });
console.log(`criado: ${user.email} role=${user.role} id=${user.id}`);
console.log(`db: ${config.dbPath}`);
