# Deploy do zkeys via Dockerfile (Dokku detecta e builda). Node pinado em 24
# porque o store usa `node:sqlite` (DatabaseSync) — stdlib, mas experimental e
# sensível à versão: 24 roda flagless. argon2 é nativo; instalamos o toolchain
# caso o prebuild-install caia pra compilação do source.
FROM node:24-slim

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Cache de deps: só o manifesto primeiro.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

# O DB vive aqui (config.dbPath default = ROOT/data/zkeys.db). Em produção este
# diretório é um volume persistente montado pelo Dokku (storage:mount).
RUN mkdir -p /app/data

ENV NODE_ENV=production
EXPOSE 5000

CMD ["node", "index.js"]
