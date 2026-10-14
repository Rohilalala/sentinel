/* Sentinel core: registry, router, shell, API helpers, teaching layer, history.
   Loads in the browser and in Node (tests): no DOM access at load time. */
const Sentinel = (() => {
  const G = globalThis;
  const modules = {}, order = [];
  const $ = (s, r = G.document) => r.querySelector(s);
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  /* ---------- icons (one set: 24 grid, 1.6 stroke) ---------- */
  const I = {
    home: 'M3 11l9-8 9 8M5 10v10h14V10', shield: 'M12 2l8 4v6c0 5-3.5 8-8 10-4.5-2-8-5-8-10V6z',
    route: 'M6 3v12a3 3 0 0 0 3 3h9M15 15l3 3-3 3', dns: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18',
    globe: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18',
    search: 'M21 21l-5-5m2-5a7 7 0 1 1-14 0 7 7 0 0 1 14 0', whois: 'M21 21l-5-5m2-5a7 7 0 1 1-14 0 7 7 0 0 1 14 0',
    cert: 'M12 2l7 4v6c0 4-3 7-7 9-4-2-7-5-7-9V6zM9 12l2 2 4-4', key: 'M15 7a4 4 0 1 1-4 4l-6 6v3h3l1-1h2v-2h2l2-2',
    tool: 'M14 7l3-3 3 3-3 3M3 21l9-9M5 5l5 5M9 3L3 9l3 3 6-6z', play: 'M7 4v16l13-8z', book: 'M4 5a2 2 0 0 1 2-2h12v18H6a2 2 0 0 1-2-2zM18 3v18',
    check: 'M5 12l5 5 9-11', x: 'M6 6l12 12M18 6L6 18', alert: 'M12 3l9 16H3zM12 9v5M12 17h.01',
    info: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18M12 11v6M12 7h.01', chevron: 'M6 9l6 6 6-6', right: 'M9 6l6 6-6 6',
    arrow: 'M5 12h14M13 6l6 6-6 6', sun: 'M12 7a5 5 0 1 0 0 10 5 5 0 0 0 0-10M12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4',
    moon: 'M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z', terminal: 'M4 17l6-6-6-6M12 19h8', menu: 'M4 6h16M4 12h16M4 18h16',
    ban: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18M6 6l12 12', mail: 'M4 6h16v12H4zM4 7l8 6 8-6', file: 'M6 3h9l3 3v15H6zM14 3v4h4',
    target: 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8',
  };
  const addIcons = o => Object.assign(I, o);
  const svg = (n, cls = 'ico') => `<svg class="${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${I[n] || I.info}"/></svg>`;

  /* ---------- glossary (teaching layer) ---------- */
  const GLOSSARY = {};
  const addTerms = o => Object.assign(GLOSSARY, o);
  const t = (term, label) => `<span class="term" tabindex="0" data-term="${esc(term)}">${esc(label || term)}</span>`;

  function wireTips() {
    const tip = $('#tip'); let hideT;
    const show = el => {
      const def = GLOSSARY[el.dataset.term]; if (!def) return;
      tip.innerHTML = `<b>${esc(el.dataset.term)}</b>${esc(def)}`;
      const r = el.getBoundingClientRect();
      tip.style.left = Math.max(8, Math.min(r.left, innerWidth - 316)) + 'px';
      tip.style.top = (r.bottom + 8) + 'px';
      tip.classList.add('on');
      if (r.bottom + 8 + tip.offsetHeight > innerHeight) tip.style.top = (r.top - tip.offsetHeight - 8) + 'px';
    };
    const hide = () => tip.classList.remove('on');
    document.addEventListener('mouseover', e => { const el = e.target.closest('.term'); if (el) { clearTimeout(hideT); show(el); } });
    document.addEventListener('mouseout', e => { if (e.target.closest('.term')) hideT = setTimeout(hide, 120); });
    document.addEventListener('focusin', e => { const el = e.target.closest('.term'); if (el) show(el); });
    document.addEventListener('focusout', e => { if (e.target.closest('.term')) hide(); });
    document.addEventListener('click', e => { const el = e.target.closest('.term'); if (el) { tip.classList.contains('on') ? hide() : show(el); } else hide(); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') hide(); });
    addEventListener('scroll', hide, true);
  }

  /* ---------- feedback ---------- */
  const say = (m, isErr) => {
    const s = $('#status'); if (!s) return;
    const msg = String(m || '').replace(/^\s*⚠\s*/, '');
    s.className = isErr ? 'err' : '';
    s.innerHTML = msg ? (isErr ? svg('alert') : '') + esc(msg) : '';
  };
  let toastT;
  const toast = m => { const el = $('#toast'); el.textContent = m; el.classList.add('on'); clearTimeout(toastT); toastT = setTimeout(() => el.classList.remove('on'), 3200); };

  /* ---------- API helpers (keyless, CORS-clean) ---------- */
  const RIPE = 'https://stat.ripe.net/data';
  async function jget(url, opts) {
    const r = await fetch(url, opts);
    if (!r.ok) throw new Error(`HTTP ${r.status} from ${new URL(url).host}`);
    return r.json();
  }
  const api = {
    jget,
    doh: (name, type = 'A', dnssec = false) => jget(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}${dnssec ? '&do=1' : ''}`, { headers: { accept: 'application/dns-json' } }),
    prefixOverview: ip => jget(`${RIPE}/prefix-overview/data.json?resource=${ip}`).then(d => d.data),
    rpki: (asn, pfx) => jget(`${RIPE}/rpki-validation/data.json?resource=AS${asn}&prefix=${pfx}`).then(d => d.data),
    lookingGlass: pfx => jget(`${RIPE}/looking-glass/data.json?resource=${pfx}`).then(d => d.data),
    asOverview: asn => jget(`${RIPE}/as-overview/data.json?resource=AS${asn}`).then(d => d.data),
    announced: asn => jget(`${RIPE}/announced-prefixes/data.json?resource=AS${asn}`).then(d => d.data),
    geo: ip => fetch(`https://ipwho.is/${ip}`).then(r => r.json()).catch(() => ({ success: false })),
    rdapDomain: d => jget(`https://rdap.org/domain/${d}`),
    rdapIp: ip => jget(`https://rdap.org/ip/${ip}`),
    certspotter: d => jget(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(d)}&include_subdomains=true&expand=dns_names&expand=issuer`),
    hibpRange: p5 => fetch(`https://api.pwnedpasswords.com/range/${p5}`).then(r => r.text()),
    async resolveA(name) {
      const d = await api.doh(name, 'A');
      const a = (d.Answer || []).filter(x => x.type === 1).map(x => x.data);
      if (!a.length) throw new Error('No A record for ' + name);
      return a[a.length - 1];
    },
  };
  const isIP = s => /^(\d{1,3}\.){3}\d{1,3}$/.test(s) && s.split('.').every(o => +o <= 255);
  const isASN = s => /^as?\d+$/i.test(s);
  const cleanHost = s => String(s).trim().replace(/^https?:\/\//i, '').replace(/[/?#].*$/, '').toLowerCase();
  async function sha(algo, str) {
    const b = await crypto.subtle.digest(algo, typeof str === 'string' ? new TextEncoder().encode(str) : str);
    return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, '0')).join('');
  }

  /* ---------- companion (native tools) ---------- */
  const companion = () => G.SENTINEL_COMPANION || null;
  async function native(path, body) {
    const c = companion(); if (!c) throw new Error('Companion not running. Start it with: node companion/server.mjs');
    const r = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json', 'x-sentinel-token': c.token }, body: JSON.stringify(body || {}) });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || `Companion error ${r.status}`);
    return j;
  }

  /* ---------- history (powers KPIs + recent checks) ---------- */
  const HKEY = 'sentinel-history';
  const store = {
    get(k, d) { try { const v = G.localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch (e) { return d; } },
    set(k, v) { try { G.localStorage.setItem(k, JSON.stringify(v)); } catch (e) { /* private mode: history is optional */ } },
  };
  const history = () => store.get(HKEY, []);
  function record(entry) {
    const h = history(); h.unshift({ ts: Date.now(), ...entry });
    store.set(HKEY, h.slice(0, 200));
  }

  /* ---------- registry + groups ---------- */
  const GROUPS = ['Learn', 'Recon', 'Threat intel', 'Web & email', 'Credentials', 'Crypto', 'Forensics', 'Privacy', 'Native', 'Reference'];
  function register(mod) { modules[mod.id] = mod; order.push(mod.id); if (!GROUPS.includes(mod.group)) GROUPS.push(mod.group); }
  const tagOf = m => m.tag !== undefined ? m.tag : (m.group === 'Learn' || m.group === 'Reference') ? '' : 'live';
  const tagHtml = tag => tag ? `<span class="tag ${tag === 'live' ? 'live' : tag === 'native' ? 'native' : ''}">${tag}</span>` : '';
  const badge = (cls, icon, txt) => `<span class="badge ${cls}">${svg(icon, '')}${esc(txt)}</span>`;

  /* ---------- shared tool scaffold ---------- */
  const loading = out => { out.innerHTML = `<div class="card full" aria-busy="true"><div class="skel" style="width:40%"></div><div class="skel"></div><div class="skel" style="width:70%"></div></div>`; };
  function searchTool(mount, cfg) {
    mount.innerHTML = `
      <div class="field">
        <label for="q">${esc(cfg.label || 'Target')}</label>
        <div class="bar"><input id="q" ${cfg.type ? `type="${cfg.type}"` : 'type="text"'} placeholder="${esc(cfg.placeholder)}" autocomplete="off" spellcheck="false" autocapitalize="off">
          <button class="btn secondary" id="go">${esc(cfg.cta || 'Check')}</button></div>
        ${(cfg.examples || []).length ? `<p class="try">Try:${cfg.examples.map(x => `<button type="button">${esc(x)}</button>`).join('')}</p>` : ''}
      </div>
      <div id="status" role="status" aria-live="polite"></div>
      <div id="out" class="grid ${cfg.wide ? '' : 'two'}"></div>`;
    const q = $('#q', mount), out = $('#out', mount), go = $('#go', mount);
    const hd = G.document.getElementById('hdrdemo');
    const run = v => {
      v = (v || '').trim(); if (!v) { q.focus(); return; }
      go.setAttribute('aria-busy', 'true'); if (hd) hd.setAttribute('aria-busy', 'true');
      Promise.resolve().then(() => cfg.run(v, out)).catch(e => say(e.message, true)).finally(() => {
        go.removeAttribute('aria-busy'); if (hd) hd.removeAttribute('aria-busy');
        const vd = out.querySelector('.verdict');
        if (vd && current) record({ tool: current, input: cfg.type === 'password' || cfg.secret ? '••••••' : v,
          cls: ['danger', 'warn', 'safe'].find(c => vd.classList.contains(c)) || 'info',
          title: (vd.querySelector('.big') || vd).textContent.trim().slice(0, 80) });
      });
    };
    go.onclick = () => run(q.value);
    q.addEventListener('keydown', e => { if (e.key === 'Enter') run(q.value); });
    mount.querySelectorAll('.try button').forEach(b => b.onclick = () => { q.value = b.textContent; run(b.textContent); });
    if (hd) {
      if (cfg.demo) { hd.hidden = false; hd.onclick = () => { q.value = cfg.demo.input; if (cfg.demo.narrate) toast(cfg.demo.narrate); run(cfg.demo.input); }; }
      else hd.hidden = true;
    }
    /* deep link: #/<id>?q=<value> opens the tool and runs it on value. While the companion runs, any tool
       may reach it (native tools, Site Files), so deep links only prefill: a link alone must never make
       the companion act on your network. */
    const pre = new URLSearchParams(G.location.hash.split('?')[1] || '').get('q');
    if (pre) { q.value = pre; if (companion() || (current && tagOf(modules[current]) === 'native')) say(`Check the target, then press ${cfg.cta || 'Check'}.`); else run(pre); }
    return { q, out, run };
  }
  /* for tools with custom UIs: show the header Run example button and bind it */
  function demoButton(fn) { const hd = G.document.getElementById('hdrdemo'); if (hd) { hd.hidden = false; hd.onclick = fn; } }

  /* ---------- theme ---------- */
  const THEMES = ['light', 'dark', 'hacker'];
  const theme = {
    get() { const v = store.get('sentinel-theme', null); return THEMES.includes(v) ? v : (G.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'); },
    set(th) { store.set('sentinel-theme', th); theme.apply(th); },
    apply(th) {
      G.document.documentElement.dataset.theme = th;
      G.document.querySelectorAll('.themes button').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.theme === th)));
    },
  };

  /* ---------- shell ---------- */
  let current = null;
  function renderTopbar() {
    const tb = $('#topbar');
    tb.innerHTML = `
      <a class="brand" href="#/home">${svg('shield', '')}<span>Sentinel</span></a>
      <button class="menubtn" id="menubtn" aria-label="Open navigation" aria-expanded="false">${svg('menu')}</button>
      <div class="search" role="search">${svg('search')}
        <input id="topq" type="search" placeholder="Search tools" aria-label="Search tools" autocomplete="off" aria-controls="topres" aria-expanded="false">
        <kbd>/</kbd><div class="results" id="topres" role="listbox"></div></div>
      <div class="themes" role="group" aria-label="Theme">
        ${[['light', 'sun', 'Light'], ['dark', 'moon', 'Dark'], ['hacker', 'terminal', 'Hacker Mode']].map(([id, ic, lbl]) =>
          `<button data-theme="${id}" aria-pressed="false" aria-label="${lbl}" title="${lbl}">${svg(ic)}</button>`).join('')}
      </div>`;
    tb.querySelectorAll('.themes button').forEach(b => b.onclick = () => theme.set(b.dataset.theme));
    theme.apply(theme.get());
    const mb = $('#menubtn', tb), rail = $('#rail');
    mb.onclick = () => { const o = rail.classList.toggle('open'); mb.setAttribute('aria-expanded', String(o)); };
    const q = $('#topq', tb), res = $('#topres', tb); let sel = 0, hits = [];
    const draw = () => {
      const v = q.value.trim().toLowerCase();
      hits = v ? order.map(id => modules[id]).filter(m => (m.name + ' ' + m.blurb + ' ' + m.group).toLowerCase().includes(v)).slice(0, 8) : [];
      res.innerHTML = hits.map((m, i) => `<button role="option" aria-selected="${i === sel}" data-go="${m.id}">${svg(m.icon)}${esc(m.name)}<small>${esc(m.group)}</small></button>`).join('')
        || (v ? `<div class="empty" style="padding:12px">No tool matches “${esc(q.value)}”</div>` : '');
      res.classList.toggle('on', !!v); q.setAttribute('aria-expanded', String(!!v));
    };
    const go = id => { location.hash = '#/' + id; q.value = ''; sel = 0; draw(); q.blur(); };
    q.addEventListener('input', () => { sel = 0; draw(); });
    q.addEventListener('keydown', e => {
      if (e.key === 'ArrowDown') { sel = Math.min(sel + 1, hits.length - 1); draw(); e.preventDefault(); }
      else if (e.key === 'ArrowUp') { sel = Math.max(sel - 1, 0); draw(); e.preventDefault(); }
      else if (e.key === 'Enter' && hits[sel]) go(hits[sel].id);
      else if (e.key === 'Escape') { q.value = ''; draw(); q.blur(); }
    });
    res.addEventListener('mousedown', e => { const b = e.target.closest('[data-go]'); if (b) { e.preventDefault(); go(b.dataset.go); } });
    q.addEventListener('blur', () => setTimeout(() => res.classList.remove('on'), 100));
    document.addEventListener('keydown', e => {
      const typing = /INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName);
      if ((e.key === '/' && !typing) || (e.key.toLowerCase() === 'k' && (e.metaKey || e.ctrlKey))) { e.preventDefault(); q.focus(); }
    });
  }

  function renderRail(active) {
    const rail = $('#rail'), openState = store.get('sentinel-groups', {});
    let html = `<a class="nav-item" href="#/home" ${active === 'home' ? 'aria-current="page"' : ''}>${svg('home')}Home</a>`;
    for (const g of GROUPS) {
      const items = order.map(id => modules[id]).filter(m => m.group === g);
      if (!items.length) continue;
      const open = openState[g] !== false || items.some(m => m.id === active);
      html += `<details class="nav-group" data-group="${esc(g)}" ${open ? 'open' : ''}><summary>${esc(g)}${svg('chevron')}</summary>` +
        items.map(m => `<a class="nav-item" href="#/${m.id}" ${active === m.id ? 'aria-current="page"' : ''}>${svg(m.icon)}${esc(m.name)}${tagHtml(tagOf(m))}</a>`).join('') + `</details>`;
    }
    html += `<p class="rail-note">Real data, no login. Lookups go straight from your browser to public sources. Only test systems you own or are allowed to test.</p>`;
    rail.innerHTML = html;
    rail.querySelectorAll('.nav-group').forEach(d => d.addEventListener('toggle', () => {
      const s = store.get('sentinel-groups', {}); s[d.dataset.group] = d.open; store.set('sentinel-groups', s);
    }));
  }

  function toolShell(mod) {
    const m = $('#main');
    m.innerHTML = `<div class="page">
      <nav class="crumb" aria-label="Breadcrumb"><a href="#/home">Home</a>${svg('right')}<span>${esc(mod.group)}</span>${svg('right')}<span aria-current="page">${esc(mod.name)}</span></nav>
      <div class="headrow"><div><h1 tabindex="-1">${esc(mod.name)}</h1><p>${mod.blurb}</p></div>
        <button class="btn" id="hdrdemo" hidden>${svg('play')}Run example</button></div>
      ${mod.why ? `<details class="about" open><summary>${svg('chevron')}What this is and why it matters</summary><div>${mod.why}</div></details>` : ''}
      <div id="toolbody"></div></div>`;
    return $('#toolbody', m);
  }

  function route() {
    const id = location.hash.replace(/^#\/?/, '').split('?')[0] || 'home';
    const active = modules[id] ? id : 'home';
    current = active === 'home' ? null : active;
    renderRail(active);
    $('#rail').classList.remove('open'); $('#menubtn') && $('#menubtn').setAttribute('aria-expanded', 'false');
    $('#tip').classList.remove('on');
    if (active === 'home') Sentinel.renderHome($('#main'));
    else {
      const body = toolShell(modules[active]);
      try { modules[active].render(body); }
      catch (e) { body.innerHTML = `<div class="note warn">${svg('alert')}<div><b>This tool failed to load.</b> ${esc(e.message)}</div></div>`; }
    }
    G.document.title = (active === 'home' ? 'Sentinel' : modules[active].name + ' · Sentinel');
    scrollTo(0, 0);
    const h1 = $('#main h1'); if (h1) h1.focus({ preventScroll: true });
  }

  function start() {
    theme.apply(theme.get());
    renderTopbar(); wireTips();
    addEventListener('hashchange', route); route();
    if ('serviceWorker' in navigator && location.protocol !== 'file:') navigator.serviceWorker.register('sw.js').catch(() => {});
  }

  const S = {
    register, start, api, isIP, isASN, cleanHost, sha, svg, t, say, toast, esc, record, history, store, native, companion,
    addIcons, addTerms, GLOSSARY, GROUPS, modules, order, tagOf, tagHtml, theme,
    ui: { searchTool, loading, demoButton, badge },
    helpers: { $, badge },
    lib: {},
    renderHome: () => {},
  };
  return S;
})();
globalThis.Sentinel = Sentinel;
