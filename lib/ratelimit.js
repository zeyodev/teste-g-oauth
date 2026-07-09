// Rate limit in-memory (DESIGN-zkeys §9): anti-brute-force no login e
// anti-abuso no proxy. Stdlib puro — o ethos do repo é stdlib + argon2, então
// nada de dependência de rate-limit; janela fixa por chave basta pro volume
// (login por IP/email, proxy por IP/token id).
//
// DIP (§5): não lê env nem relógio global — recebe { max, windowMs, now }
// injetados pelo composition root; o clock injetável torna a expiração da
// janela testável sem esperar tempo real.
//
// TODO(escala): single-process (1 host, o deploy atual). Escala horizontal
// exigiria um store compartilhado (Redis/SQLite) — fora de escopo aqui.

export function createRateLimiter({ max, windowMs, now = () => Date.now() }) {
  // chave → { count, resetAt }. Janela fixa: reinicia ao cruzar resetAt.
  const hits = new Map();

  // Conta um evento na chave e diz se estourou. retryAfterMs = quanto falta
  // pra janela virar (vira o header Retry-After, em segundos, arredondado ↑).
  function check(key) {
    const t = now();
    let e = hits.get(key);
    if (!e || t >= e.resetAt) {
      e = { count: 0, resetAt: t + windowMs };
      hits.set(key, e);
    }
    e.count++;
    const limited = e.count > max;
    return {
      limited,
      remaining: Math.max(0, max - e.count),
      retryAfterMs: limited ? Math.max(0, e.resetAt - t) : 0,
      retryAfterSeconds: limited ? Math.ceil(Math.max(0, e.resetAt - t) / 1000) : 0,
    };
  }

  // Zera a chave (ex: login bem-sucedido libera o contador do email).
  function reset(key) {
    hits.delete(key);
  }

  // GC oportunista das janelas já expiradas — evita vazar memória sob chaves
  // efêmeras (muitos IPs/emails distintos).
  function sweep() {
    const t = now();
    for (const [k, e] of hits) if (t >= e.resetAt) hits.delete(k);
  }

  return { check, reset, sweep };
}
