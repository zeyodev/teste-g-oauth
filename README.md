# zkeys

Cofre de credenciais multi-tenant + proxy de integrações. A pessoa loga
(Argon2id+pepper), conecta as próprias contas (Google/Meta/Canva/...), e o
zkeys guarda os tokens **cifrados** (AES-256-GCM) e serve de **reverse-proxy**
pras plataformas finais — o workspace só recebe um `zwt_…` escopado/revogável
e **nunca** vê o token cru.

Design completo: [`DESIGN-zkeys.md`](../DESIGN-zkeys.md) (raiz do metaorg).
Este repo era o broker `oauth/` (pull-once, nunca lançado) — evoluído na F1.

## Rodar

```bash
cp .env.example .env    # preencher os 3 segredos (openssl rand -hex 32) + client ids
npm install
npm run create-user -- --email voce@x.dev --password 'senha' --role admin
npm start               # http://localhost:5000
```

Dev em http: adicionar `ZKEYS_INSECURE_COOKIE=1` no `.env` (senão o cookie
Secure não volta).

## Proxy transparente (F2)

O workspace nunca vê o token do provider — só um `zwt_…` escopado/revogável:

```bash
# 1. logado (cookie de sessão), emitir um workspace token — o segredo sai UMA vez
curl -X POST http://localhost:5000/auth/workspace-tokens \
  -H 'content-type: application/json' -b "$COOKIE" \
  -d '{"name":"workspace acme","scopes":["google"]}'
# → { "token": "zwt_…", ... }

# 2. do workspace, falar com o provider ATRAVÉS do proxy
curl http://localhost:5000/p/google/gmail/v1/users/me/messages \
  -H "Authorization: Bearer zwt_…"
```

Pipeline (`proxy/`): authN (`zwt_` → hash → user) → authZ (provider ∈ escopo)
→ resolve (connection default, ou `?account=<alias>` / `X-Zkeys-Account`) →
fresh (refresh se expirando) → forward (injeta auth conforme `auth_injection`
do provider, streama a resposta crua; upstream 401 → refresh 1x → retry).

## Workspace tokens + Meta (F3)

Ciclo completo de `zwt_` (além da emissão da F2):

```bash
curl http://localhost:5000/auth/workspace-tokens -b "$COOKIE"          # lista (sem hash/segredo)
curl -X DELETE http://localhost:5000/auth/workspace-tokens/<id> -b "$COOKIE"  # revoga → proxy passa a dar 401
```

Gestão pela UI em `/` (criar mostra o `zwt_` **uma vez**, listar, revogar).

**`appsecret_proof` do Meta** (chamadas Graph): `providers/meta.json` declara
`"sign": "appsecret_proof"`; o proxy injeta
`appsecret_proof = hex(HMAC-SHA256(app_secret, access_token))` na query, **por
tentativa** (o retry pós-refresh recalcula com o token novo). É um `SIGNER` em
dados (gêmeo do `auth_injection`) — o núcleo do proxy não conhece "Meta".

**Helper no harness** (`agente/harness/tools.py`): `zkeys_request(provider,
path, method, body)` lê `ZKEYS_TOKEN`, monta `<base>/p/<provider>/<path>`,
injeta o Bearer do `zwt_` e ecoa a URL alvo.

## Hardening (F4)

- **Rate limit** (§9, stdlib): login por IP+email e proxy por IP (pré-authN) + token id
  (pós-authN) → `429` + `Retry-After`. Atrás do tunnel, o IP real vem do `X-Forwarded-For`
  via `ZKEYS_TRUST_PROXY` (default 1 hop). Limites em `ZKEYS_RL_*` (ver `.env.example`).
- **Auditoria exposta**: `GET /audit` (sessão) + card "Atividade" na UI — trilha do próprio
  usuário (isolada), sem segredo.
- **CSRF** (double-submit): cookie `zkeys_csrf` legível + header `X-CSRF-Token` nas rotas web
  que mutam. O proxy `/p/*` usa Bearer → **imune** (não exige CSRF).
- **Envelope encryption** (§8): cada connection tem um DEK aleatório *wrapped* pelo KEK
  (`connections.dek_wrapped`); os tokens usam o DEK (formato v2 `0x02‖…`). Dump do `zkeys.db`
  sem o KEK = lixo; rotação de KEK = re-wrap dos DEKs.

Migrar dados existentes (v1 KEK-direto → v2 envelope) e rotacionar o KEK:

```bash
npm run migrate-envelope -- --dry-run   # verifica (rollback), sem tocar o banco
npm run migrate-envelope                # backup (VACUUM INTO) + migra idempotente + prova plaintext
ZKEYS_NEW_MASTER_KEY=$(openssl rand -hex 32) npm run rotate-kek   # re-wrap dos DEKs (troque a env depois)
```

## Testes

```bash
npm test    # F1 (login→connect→cofre→revoke) + F2 (proxy mock) + F3 (tokens + appsecret_proof)
            # + F4 (rate limit + auditoria + envelope + csrf) — 14+12+6+15 checks
```

## Estado (roadmap DESIGN-zkeys §13)

- **F1 ✅** login + conectar + cofre cifrado + CRUD de credenciais + UI mínima
- **F2 ✅** proxy transparente `/p/:provider/*` (refresh-on-401) + emissão mínima de `zwt_`
- **F3 ✅** ciclo completo de workspace tokens (lista/revogação/UI) + hook `appsecret_proof` do Meta + helper `zkeys_request` no harness
- **F4 ✅** UI usável sem curl + auditoria exposta + rate limit + envelope encryption (§8/§9)
- **F5** retirada do fluxo brokered no agente
