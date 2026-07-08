// Página de fechamento do popup OAuth. Fecha sozinha; a página-mãe refetcha
// as conexões no focus. Sem postMessage (mesma decisão do design original §2.5).

const esc = (s) => String(s || "").replace(/[&<>"']/g, (c) => ({
  "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
}[c]));

export function popupHtml({ ok, message }) {
  return `<!doctype html><html><head><meta charset="utf-8"><title>${ok ? "Conectado" : "Erro"}</title></head>
<body style="font-family: 'DM Sans', system-ui, sans-serif; background:#050605; color:#f2f2ef; padding:24px; max-width:480px;">
  <h2 style="color:${ok ? "#c1ff72" : "#ff7272"}">${ok ? "Conectado!" : "Erro na conexão"}</h2>
  <p>${esc(message)}</p>
  <p style="color:#888;font-size:12px;">Esta janela fecha sozinha.</p>
  <script>setTimeout(() => { try { window.close(); } catch (e) {} }, 1500);</script>
</body></html>`;
}
