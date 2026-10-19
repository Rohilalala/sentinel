/* Home: real KPIs from local check history, recent checks, grouped tool list. */
(() => {
const S = Sentinel, esc = S.esc, svg = S.svg;

const ago = ts => {
  const s = Math.round((Date.now() - ts) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + ' min ago';
  if (s < 86400) return Math.floor(s / 3600) + ' h ago';
  return Math.floor(s / 86400) + ' d ago';
};
const VERDICT = { danger: ['b-danger', 'x', 'Issue'], warn: ['b-warn', 'alert', 'Review'], safe: ['b-safe', 'check', 'OK'], info: ['b-mut', 'info', 'Info'] };

S.renderHome = main => {
  const h = S.history(), mods = S.order.map(id => S.modules[id]);
  const issues = h.filter(x => x.cls === 'danger' || x.cls === 'warn').length;
  const used = new Set(h.map(x => x.tool)).size;
  const kpi = (lbl, val, sm) => `<div class="kpi"><div class="lbl">${lbl}</div><div class="val">${val}${sm ? ` <small>${sm}</small>` : ''}</div></div>`;

  const recent = h.slice(0, 6).map(x => {
    const m = S.modules[x.tool], [cls, ic, word] = VERDICT[x.cls] || VERDICT.info;
    return `<tr><td>${m ? `<a href="#/${m.id}">${esc(m.name)}</a>` : esc(x.tool)}</td><td class="mono">${esc(x.input)}</td>
      <td>${S.ui.badge(cls, ic, word)} <span class="mut">${esc(x.title)}</span></td><td class="mut" style="white-space:nowrap">${ago(x.ts)}</td></tr>`;
  }).join('');

  const groups = S.GROUPS.map(g => {
    const items = mods.filter(m => m.group === g);
    if (!items.length) return '';
    return `<div class="list-group">${esc(g)}</div>` + items.map(m =>
      `<a class="list-row" href="#/${m.id}">${svg(m.icon)}<span class="name">${esc(m.name)}</span><span class="desc">${esc(m.tile || '')}</span>${S.tagHtml(S.tagOf(m)) || '<span></span>'}${svg('right')}</a>`).join('');
  }).join('');

  main.innerHTML = `<div class="page">
    <nav class="crumb" aria-label="Breadcrumb"><span aria-current="page">Home</span></nav>
    <div class="headrow"><div><h1 tabindex="-1">Overview</h1>
      <p>Real lookups on live internet data, with every term explained as you go. Start with a guided recon, or pick any tool below.</p></div>
      <a class="btn" href="#/mission">${svg('play')}Run guided recon</a></div>
    <div class="kpis">
      ${kpi('Checks run', h.length)}
      ${kpi('Issues found', issues, issues ? 'need a look' : '')}
      ${kpi('Tools used', used, `of ${mods.length}`)}
      ${kpi('Last check', h[0] ? ago(h[0].ts) : '—')}
    </div>
    <section class="section"><div class="section-head"><h2>Recent checks</h2><p>Stored only in this browser.</p></div>
      ${recent ? `<div class="card" style="padding:4px 8px"><div class="table-wrap"><table>
        <thead><tr><th>Tool</th><th>Target</th><th>Result</th><th>When</th></tr></thead><tbody>${recent}</tbody></table></div></div>`
      : `<div class="card empty"><b>No checks yet</b>Run your first one. Guided recon walks a real domain through five tools in about ten seconds.
         <div><a class="btn" href="#/mission">${svg('play')}Try guided recon</a></div></div>`}
    </section>
    <section class="section"><div class="section-head"><h2>All tools</h2><p>${mods.length} tools. Live tools query public sources; local ones never leave your browser.</p></div>
      <div class="list">${groups}</div></section>
    <div class="note">${svg('info')}<div><b>Ground rule.</b> Reading public records (DNS, WHOIS, routing, certificate logs) is fine for any domain. Scanning or password-testing systems you don't own or have permission to test can be illegal. Practise on your own domains and the built-in examples.</div></div>
  </div>`;
};
})();
