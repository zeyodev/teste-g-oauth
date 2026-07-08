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

## Testes

```bash
npm test    # e2e com provider mock: login → connect (PKCE) → cofre → revoke
```

## Estado (roadmap DESIGN-zkeys §13)

- **F1 ✅** login + conectar + cofre cifrado + CRUD de credenciais + UI mínima
- **F2** proxy transparente `/p/:provider/*` (refresh-on-401)
- **F3** workspace tokens (`zwt_…`) + hook `appsecret_proof` do Meta
- **F4** UI completa + rate limit + envelope encryption
- **F5** retirada do fluxo brokered no agente
