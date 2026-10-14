/* Sentinel tool file: Native tools. They run real commands through the local companion
   (companion/server.mjs); without it each tool explains how to start it. Pure parsers on Sentinel.lib. */
(() => {
const S = Sentinel, api = S.api, esc = S.esc, svg = S.svg, t = S.t;
const { searchTool, loading, badge } = S.ui;

S.addIcons({
  'f-pulse': 'M22 12h-4l-3 9L9 3l-3 9H2',
  'f-hops': 'M3 17a2 2 0 1 0 4 0a2 2 0 1 0-4 0M10 12a2 2 0 1 0 4 0a2 2 0 1 0-4 0M17 7a2 2 0 1 0 4 0a2 2 0 1 0-4 0M6.6 15.8l3.8-2.6M13.6 10.8l3.8-2.6',
  'f-ports': 'M16 16h6v6h-6zM2 16h6v6H2zM9 2h6v6H9zM5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3M12 12V8',
  'f-layers': 'M12 2L2 7l10 5 10-5zM2 17l10 5 10-5M2 12l10 5 10-5',
  'f-link': 'M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7',
});
S.addTerms({
  'companion': 'A small program from the Sentinel folder that runs on your own computer. It lets the browser use real network commands a web page cannot run by itself.',
  'ping': 'A command that sends tiny "are you there?" packets to a host and times the answers.',
  'ICMP': 'Internet Control Message Protocol: the network\'s housekeeping messages, such as ping requests and "time exceeded" errors.',
  'latency': 'How long a packet takes to get somewhere and back, in milliseconds. Lower is closer and faster.',
  'packet loss': 'The share of packets that never got an answer. Some loss means congestion, a bad link, or a firewall dropping them.',
  'traceroute': 'A command that reveals each router between you and a host by sending packets that expire one hop further each time.',
  'hop': 'One router your traffic passes through on its way to a destination.',
  'port': 'A numbered door on a computer (0 to 65535). Each network service listens on one: web on 443, SSH on 22.',
  'port scan': 'Knocking on many ports of a computer to see which ones answer. Only do it to systems you own or have written permission to test.',
  'closed port': 'A port that answered "nothing here" (a TCP reset). The machine is reachable, but no program listens there.',
  'filtered port': 'A port that never answered at all, usually because a firewall silently drops the packets.',
  'TCP handshake': 'The three-step SYN, SYN-ACK, ACK exchange that opens a TCP connection. A connect scan completes it on each port.',
  'recursive resolver': 'The DNS server that answers your lookups by asking other DNS servers on your behalf, then caching the answer.',
  'redirect': 'A server reply (status 301, 302, 303, 307 or 308) that says "go to this other address instead".',
  'URL shortener': 'A service that turns a long link into a short one and redirects you. It hides the real destination until you click.',
  'tracking parameter': 'Extra text added to a link, such as utm_source or WT.mc_id, so the site can tell where your click came from.',
  'server banner': 'Headers such as Server or X-Powered-By that name the software, and sometimes the exact version, a site runs on.',
});

/* ---------- pure parsers (tested in tests/companion.test.mjs) ---------- */
function parsePing(out) {
  const s = String(out || ''), times = [...s.matchAll(/time[=<]\s*([\d.]+)\s*ms/gi)].map(m => +m[1]);
  let m = s.match(/(\d+) packets transmitted, (\d+) (?:packets )?received/) || s.match(/Sent = (\d+), Received = (\d+)/);
  if (!m) return null;
  const sent = +m[1], received = +m[2];
  const rtt = s.match(/= ([\d.]+)\/([\d.]+)\/([\d.]+)/), win = s.match(/Minimum = (\d+)ms, Maximum = (\d+)ms, Average = (\d+)ms/);
  const [min, avg, max] = rtt ? [+rtt[1], +rtt[2], +rtt[3]] : win ? [+win[1], +win[3], +win[2]] : [null, null, null];
  return { sent, received, loss: sent ? Math.round((sent - received) / sent * 100) : 100, min, avg, max, times };
}
function parseTraceroute(out) {
  return String(out || '').split('\n').map(l => l.match(/^\s*(\d+)\s+(.*\S)\s*$/)).filter(Boolean).map(([, n, rest]) => {
    const ms = [...rest.matchAll(/<?([\d.]+)\s*ms/g)].map(x => +x[1]);
    const ip = (rest.match(/[(\[]([\da-f.:]+)[)\]]/i) || rest.match(/((?:\d{1,3}\.){3}\d{1,3}|[\da-f]*:[\da-f:]+)\s*$/i) || [])[1] || null;
    const name = (rest.match(/^([^\s(*]+)\s+\(/) || [])[1];
    return { hop: +n, host: name || ip, ip, ms: ms.length ? Math.min(...ms) : null };
  });
}
function parseDig(out) {
  return String(out || '').split('\n').map(l => l.match(/^(\S+)\s+(\d+)\s+IN\s+([A-Z]+)\s+(.+)$/)).filter(Boolean)
    .map(([, name, ttl, type, data]) => ({ name, ttl: +ttl, type, data: data.trim() }));
}
const normDns = s => String(s).trim().replace(/\s+/g, ' ').replace(/\.(?=\s|$)/g, '').toLowerCase();
function parseWhois(out) {
  let s = String(out || '');
  const i = s.search(/^# whois\./m);
  if (i >= 0) s = s.slice(i);                       // skip the IANA preamble (it describes the TLD, not the domain)
  else if (/% IANA WHOIS server/.test(s)) s = '';   // only the TLD record came back
  const f = re => ((s.match(re) || [])[1] || '').trim() || null;
  return {
    registrar: f(/^\s*Registrar:\s*(.+)$/mi),
    created: f(/^\s*(?:Creation Date|Created(?: On)?|Registered on|Registration Time):\s*(.+)$/mi),
    expires: f(/^\s*(?:Registry Expiry Date|Registrar Registration Expiration Date|Expir\w* (?:Date|On)|paid-till):\s*(.+)$/mi),
    nameservers: [...new Set([...s.matchAll(/^\s*(?:Name Server|nserver):\s*(\S+)/gmi)].map(m => m[1].toLowerCase()))],
    notFound: /No match for|NOT FOUND|No Data Found|Status:\s*free|is available for registration/i.test(s),
  };
}
// [name, category, where, pattern]: where is a header name, 'cookie' or 'body'.
const TECH = [
  ['Cloudflare', 'CDN', 'cf-ray', /./], ['Cloudflare', 'CDN', 'server', /cloudflare/i], ['Amazon CloudFront', 'CDN', 'x-amz-cf-id', /./],
  ['Fastly', 'CDN', 'x-served-by', /cache-/i], ['Akamai', 'CDN', 'server', /akamai/i], ['Vercel', 'Hosting', 'x-vercel-id', /./],
  ['Netlify', 'Hosting', 'x-nf-request-id', /./], ['GitHub', 'Hosting', 'x-github-request-id', /./],
  ['nginx', 'Web server', 'server', /nginx/i], ['Apache', 'Web server', 'server', /apache/i], ['Microsoft IIS', 'Web server', 'server', /microsoft-iis/i],
  ['LiteSpeed', 'Web server', 'server', /litespeed/i], ['Caddy', 'Web server', 'server', /caddy/i],
  ['PHP', 'Language', 'x-powered-by', /php/i], ['PHP', 'Language', 'cookie', /PHPSESSID=/], ['ASP.NET', 'Framework', 'x-powered-by', /asp\.net/i],
  ['ASP.NET', 'Framework', 'cookie', /ASP\.NET_SessionId=/], ['Java', 'Language', 'cookie', /JSESSIONID=/],
  ['Express', 'Framework', 'x-powered-by', /express/i], ['Express', 'Framework', 'cookie', /connect\.sid=/],
  ['Next.js', 'Framework', 'x-powered-by', /next\.js/i], ['Next.js', 'Framework', 'body', /__NEXT_DATA__|\/_next\/static\//],
  ['Nuxt', 'Framework', 'body', /__NUXT__|\/_nuxt\//], ['Laravel', 'Framework', 'cookie', /laravel_session=/],
  ['Django', 'Framework', 'cookie', /csrftoken=/], ['Ruby on Rails', 'Framework', 'cookie', /_[a-z0-9_]+_session=.*--/i], ['Ruby on Rails', 'Framework', 'x-runtime', /^[\d.]+$/],
  ['WordPress', 'CMS', 'body', /\/wp-content\/|\/wp-includes\//], ['WordPress', 'CMS', 'body', /<meta[^>]+generator[^>]+WordPress/i],
  ['Drupal', 'CMS', 'x-generator', /drupal/i], ['Drupal', 'CMS', 'body', /\/sites\/default\/files\/|Drupal\.settings/],
  ['Joomla', 'CMS', 'body', /<meta[^>]+generator[^>]+Joomla/i], ['Shopify', 'E-commerce', 'body', /cdn\.shopify\.com/], ['Shopify', 'E-commerce', 'x-shopid', /./],
  ['React', 'JavaScript library', 'body', /data-reactroot|react(?:-dom)?(?:\.production)?(?:\.min)?\.js/i], ['Vue.js', 'JavaScript library', 'body', /data-v-[0-9a-f]{8}|vue(?:\.min)?\.js/i],
  ['Angular', 'JavaScript framework', 'body', /ng-version=/], ['jQuery', 'JavaScript library', 'body', /jquery[.-][\d.]*(?:min\.)?js/i],
];
function detectTech(res) {
  const h = (res && res.headers) || {}, cookies = [].concat(h['set-cookie'] || []).join('\n'), body = (res && res.bodySample) || '';
  const found = new Map();
  for (const [name, cat, where, re] of TECH) {
    const src = where === 'cookie' ? cookies : where === 'body' ? body : h[where];
    if (!src || !re.test(src) || found.has(name)) continue;
    found.set(name, { name, category: cat, evidence: where === 'body' ? 'page source' : where === 'cookie' ? 'cookie name' : `${where}: ${String(src).slice(0, 80)}` });
  }
  const leaks = ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator'].filter(k => /\d+\.\d+/.test(h[k] || '')).map(k => `${k}: ${h[k]}`);
  return { tech: [...found.values()], leaks };
}
Object.assign(S.lib, { parsePing, parseTraceroute, parseDig, normDns, parseWhois, detectTech });

/* ---------- shared ---------- */
const START = `<pre class="out-pre" style="text-align:left;margin-top:14px">node companion/server.mjs\n# then open http://127.0.0.1:7777</pre>`;
// Renders the "start the companion" empty state and returns true when the tool can't run.
function needCompanion(mount, bin) {
  const c = S.companion();
  if (c && (!bin || (c.tools || {})[bin])) return false;
  mount.innerHTML = c
    ? `<div class="card empty"><b>${esc(bin)} isn't installed</b>The ${t('companion')} is running, but this computer has no <code>${esc(bin)}</code> command. Install it with your package manager, then restart the companion.</div>`
    : `<div class="card empty"><b>Start the companion to use this tool</b>This tool runs a real network command on your computer, which a browser tab can't do. The ${t('companion')} is one small Node file with no dependencies. From the Sentinel folder, run:${START}</div>`;
  return true;
}
const raw = (title, text) => `<div class="card full"><h2>${esc(title)}</h2><pre class="out-pre">${esc(text || '(no output)')}</pre></div>`;
const verdict = (cls, icon, head, sub) => `<div class="card verdict ${cls} full"><h2 class="big">${svg(icon)}${esc(head)}</h2><div class="sub">${sub}</div></div>`;
const bar = (v, max, cls = 'ok') => `<div class="meter" style="margin:0;min-width:80px"><i style="width:${Math.max(2, Math.round(v / max * 100))}%;background:var(--${cls})"></i></div>`;
const host = v => S.cleanHost(v).replace(/:\d+$/, '');
const asUrl = v => /^https?:\/\//i.test(v.trim()) ? v.trim() : 'https://' + v.trim();

/* ---------- Ping ---------- */
S.register({ id: 'ping', name: 'Ping', group: 'Native', icon: 'f-pulse', tag: 'native',
  tile: 'Send four echo requests from your computer and measure round-trip time and packet loss.',
  blurb: 'Check whether a host answers and how long a round trip takes, using your computer\'s own ping command.',
  why: `${t('ping','Ping')} sends small ${t('ICMP')} echo packets and times each reply. ${t('latency','Latency')} tells you how far away a host is in network terms, and ${t('packet loss')} hints at congestion or filtering. Many servers drop ICMP on purpose, so "no reply" doesn't always mean "down".`,
  render(mount) {
    if (needCompanion(mount, 'ping')) return;
    searchTool(mount, { label: 'Host or IP address', placeholder: '1.1.1.1', cta: 'Ping', examples: ['1.1.1.1', 'github.com', '8.8.8.8'],
      demo: { input: '1.1.1.1', narrate: 'Pinging Cloudflare\'s DNS server four times from your own computer.' },
      run: async (v, out) => {
        loading(out); S.say('Pinging (about 4 seconds)…');
        const r = await S.native('/api/run', { tool: 'ping', target: host(v) }), p = parsePing(r.stdout);
        if (!p) { out.innerHTML = verdict('danger', 'x', 'Ping failed', esc((r.stderr || r.stdout || 'No output').trim().split('\n')[0]) + '. Check the spelling, or try an IP address.') + raw('Raw output', r.stdout + r.stderr); S.say(''); return; }
        const cls = p.received === p.sent ? 'safe' : p.received ? 'warn' : 'danger';
        const head = cls === 'safe' ? `Reachable · ${Math.round(p.avg)} ms average` : cls === 'warn' ? `${p.loss}% packet loss` : 'No replies';
        const sub = cls === 'danger' ? 'The host didn\'t answer. It may be offline, or it may block ICMP on purpose; many servers do.'
          : `${p.received} of ${p.sent} replies came back. ${p.avg < 30 ? 'Under 30 ms is close by, often the same city or a nearby data center.' : p.avg < 120 ? 'This is a normal round trip across a country or region.' : 'Over 120 ms usually means another continent or a congested path.'}`;
        const max = Math.max(...p.times, 1);
        out.innerHTML = verdict(cls, cls === 'safe' ? 'check' : cls === 'warn' ? 'alert' : 'x', head, sub) +
          `<div class="card"><h2>Summary</h2><div class="kv">
            <div class="k">Sent / received</div><div class="v">${p.sent} / ${p.received}</div>
            <div class="k">${t('packet loss','Loss')}</div><div class="v">${p.loss}%</div>
            <div class="k">Min / avg / max</div><div class="v">${p.min ?? '—'} / ${p.avg ?? '—'} / ${p.max ?? '—'} ms</div></div></div>
          <div class="card"><h2>Each reply</h2>${p.times.length ? `<div class="table-wrap"><table><tbody>${p.times.map((ms, i) =>
            `<tr><td class="num">#${i + 1}</td><td class="num">${ms} ms</td><td style="width:60%">${bar(ms, max)}</td></tr>`).join('')}</tbody></table></div>` : '<p class="mut">No replies to chart.</p>'}</div>` +
          raw('Raw output', r.stdout);
        S.say('');
      } });
  } });

/* ---------- Traceroute ---------- */
S.register({ id: 'traceroute', name: 'Traceroute', group: 'Native', icon: 'f-hops', tag: 'native',
  tile: 'List every router between your computer and a host, with the delay to each one.',
  blurb: 'Map the path your packets take to a host, one router at a time, with the delay at each step.',
  why: `${t('traceroute','Traceroute')} sends packets whose time-to-live runs out one ${t('hop')} further each time. Each router that drops one replies with an ${t('ICMP')} error, which reveals its address. The path shows which networks carry your traffic, and the delays show where it slows down. A <b>*</b> means that router chose not to reply.`,
  render(mount) {
    if (needCompanion(mount, 'traceroute')) return;
    searchTool(mount, { label: 'Host or IP address', placeholder: '1.1.1.1', cta: 'Trace', wide: true, examples: ['1.1.1.1', 'github.com', 'bbc.co.uk'],
      demo: { input: '1.1.1.1', narrate: 'Tracing the route from your computer to Cloudflare, hop by hop. This takes up to a minute.' },
      run: async (v, out) => {
        loading(out); S.say('Tracing the route (up to a minute)…');
        const r = await S.native('/api/run', { tool: 'traceroute', target: host(v) }), hops = parseTraceroute(r.stdout);
        if (!hops.length) { out.innerHTML = verdict('danger', 'x', 'Trace failed', esc((r.stderr || 'No output').trim().split('\n').pop()) + '. Check the spelling, or try an IP address.') + raw('Raw output', r.stdout + r.stderr); S.say(''); return; }
        const last = hops[hops.length - 1], reached = last.ms != null && hops.length < 20, silent = hops.filter(h => h.ms == null).length;
        const max = Math.max(...hops.map(h => h.ms || 0), 1);
        out.innerHTML = verdict(reached ? 'safe' : 'warn', reached ? 'check' : 'alert', reached ? `Reached in ${hops.length} hops` : `No answer after hop ${hops.length}`,
          reached ? `Your packets crossed ${hops.length - 1} routers to reach ${esc(last.host || host(v))}${silent ? `. ${silent} router${silent > 1 ? 's' : ''} stayed silent, which is normal: many don't answer traceroute` : ''}.`
            : 'The destination never replied. It, or a firewall in front of it, probably drops traceroute packets. The routers before it still show the path.') +
          `<div class="card full"><h2>Path</h2><div class="table-wrap"><table><thead><tr><th>${t('hop','Hop')} and router</th><th class="num">Delay</th><th style="width:30%"></th></tr></thead><tbody>${hops.map(h =>
            `<tr><td class="mono" style="overflow-wrap:anywhere"><span class="mut" style="display:inline-block;min-width:3ch">${h.hop}</span>${h.host ? esc(h.host) + (h.ip && h.ip !== h.host ? ` <span class="mut">${esc(h.ip)}</span>` : '') : '<span class="mut">* no reply</span>'}</td>
             <td class="num">${h.ms != null ? h.ms + ' ms' : '—'}</td><td>${h.ms != null ? bar(h.ms, max) : ''}</td></tr>`).join('')}</tbody></table></div>
            <p class="mut" style="margin-top:10px;font-size:var(--text-sm)">Bars are drawn to scale. Delay can drop at a later hop because routers answer traceroute at low priority.</p></div>` +
          raw('Raw output', r.stdout);
        S.say('');
      } });
  } });

/* ---------- Port Scan ---------- */
const PORT_NOTES = { 21: 'FTP file transfer. Sends passwords in plain text.', 22: 'SSH remote login. Fine when it uses keys and stays patched.',
  23: 'Telnet remote login with no encryption. Should almost never be open.', 25: 'SMTP mail delivery.', 53: 'DNS.', 80: 'Web server (HTTP).',
  110: 'POP3 mail.', 135: 'Windows RPC. Should not face the internet.', 139: 'NetBIOS file sharing. Should not face the internet.', 143: 'IMAP mail.',
  443: 'Web server (HTTPS).', 445: 'Windows file sharing (SMB). Exposed SMB spread the WannaCry worm.', 1433: 'Microsoft SQL Server database.',
  3306: 'MySQL database. Databases should not face the internet.', 3389: 'Windows Remote Desktop. A common ransomware entry point when exposed.',
  5432: 'PostgreSQL database. Databases should not face the internet.', 5900: 'VNC remote desktop, often with weak passwords.',
  8080: 'Alternate web port, often an admin panel or dev server.', 8443: 'Alternate HTTPS port, often an admin panel.' };
const RISKY = [21, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900];
S.register({ id: 'portscan', name: 'Port Scan', group: 'Native', icon: 'f-ports', tag: 'native',
  tile: 'Check the 100 most common ports on a host you own, and learn what each open one means.',
  blurb: 'Find which of the 100 most common ports answer on a host you own or are allowed to test.',
  why: `Every ${t('open port')} is a program accepting connections from the network, and each one is something an attacker can try. A ${t('port scan')} tries a ${t('TCP handshake')} on each port: an answer means open, a reset means ${t('closed port','closed')}, silence means ${t('filtered port','filtered')} by a firewall. Scanning systems without permission can be illegal, so this tool asks first. The Nmap project runs <span class="mono">scanme.nmap.org</span> so learners can practise.`,
  render(mount) {
    if (needCompanion(mount)) return;
    searchTool(mount, { label: 'Host or IP address you are allowed to scan', placeholder: 'scanme.nmap.org', cta: 'Scan', wide: true, examples: ['scanme.nmap.org', '127.0.0.1'],
      demo: { input: 'scanme.nmap.org', narrate: 'Scanning scanme.nmap.org, a host the Nmap project set up so learners can practise legally.' },
      run: async (v, out) => {
        if (!(mount.querySelector('#authz') || {}).checked) throw new Error('Tick the box to confirm you own this target or have written permission to test it.');
        loading(out); S.say('Scanning the top 100 ports (up to two minutes)…');
        const r = await S.native('/api/scan', { target: host(v), profile: 'top100', authorized: true });
        const risky = r.open.filter(o => RISKY.includes(o.port));
        const cls = risky.length ? 'danger' : r.open.length ? 'warn' : 'safe';
        const names = r.open.map(o => o.service || o.port).join(', ');
        out.innerHTML = verdict(cls, cls === 'safe' ? 'check' : cls === 'warn' ? 'alert' : 'x',
          r.open.length ? `${r.open.length} open port${r.open.length > 1 ? 's' : ''}${names ? ': ' + names : ''}` : 'No open ports in the top 100',
          risky.length ? `Port${risky.length > 1 ? 's' : ''} ${risky.map(o => o.port).join(', ')} expose${risky.length > 1 ? '' : 's'} a service that usually shouldn't face the internet. If this is your machine, close it or put it behind a firewall or VPN.`
            : r.open.length ? 'Every open port is a service anyone can talk to. These are common, but confirm each one is meant to be public and kept patched.'
            : 'Nothing answered on the 100 most common ports. The host is either well firewalled or unreachable.') +
          `<div class="card"><h2>Open ports</h2>${r.open.length ? `<div class="table-wrap"><table><thead><tr><th class="num">Port</th><th>Service</th><th>What it is</th></tr></thead><tbody>${r.open.map(o =>
            `<tr><td class="num">${o.port}</td><td class="mono">${esc(o.service || '?')}</td><td>${RISKY.includes(o.port) ? badge('b-danger', 'alert', 'risky') + ' ' : ''}${esc(PORT_NOTES[o.port] || 'No note for this port. Look up what usually listens here.')}</td></tr>`).join('')}</tbody></table></div>` : '<p class="mut">None.</p>'}</div>
          <div class="card"><h2>Scan details</h2><div class="kv">
            <div class="k">Method</div><div class="v">${r.method === 'nmap' ? 'nmap -sT (TCP connect)' : 'Built-in TCP connect scan (nmap not installed)'}</div>
            ${r.ip ? `<div class="k">IP address</div><div class="v">${esc(r.ip)}</div>` : ''}
            ${r.closed != null ? `<div class="k">${t('closed port','Closed')}</div><div class="v">${r.closed}</div><div class="k">${t('filtered port','Filtered')}</div><div class="v">${r.filtered}</div>` : ''}
            <div class="k">Time</div><div class="v">${(r.ms / 1000).toFixed(1)} s</div></div></div>`;
        S.say('');
      } });
    const box = document.createElement('label');
    box.style.cssText = 'display:flex;gap:8px;align-items:flex-start;margin-top:10px;font-size:var(--text-sm);color:var(--fg-2);cursor:pointer';
    box.innerHTML = `<input type="checkbox" id="authz" style="margin-top:3px"> <span>I own this target or have written permission to test it.</span>`;
    mount.querySelector('.field').append(box);
    const hd = document.getElementById('hdrdemo'), demo = hd && hd.onclick;
    if (demo) hd.onclick = () => { box.querySelector('input').checked = true; demo(); };
    mount.insertAdjacentHTML('afterbegin', `<div class="note warn" style="margin-top:0">${svg('alert')}<div><b>Only scan what you're allowed to.</b> Scanning computers you don't own, without written permission, can break the law in many countries. Practise on your own devices or on scanme.nmap.org.</div></div>`);
  } });

/* ---------- DNS (dig) ---------- */
const TYPE_CODE = { A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28 };
S.register({ id: 'dig', name: 'DNS (dig)', group: 'Native', icon: 'dns', tag: 'native',
  tile: 'Ask your own computer\'s DNS resolver with dig and compare the answer to encrypted DNS.',
  blurb: 'Run a real dig lookup through your network\'s resolver and compare it, side by side, with Cloudflare\'s DNS-over-HTTPS answer.',
  why: `Your computer normally asks your network's ${t('recursive resolver')} (often your ISP or router) for DNS answers. Sentinel's other tools use encrypted ${t('DoH')} instead. Comparing the two shows ${t('DNS')} caching at work, and it can reveal a network that rewrites or blocks answers. Big sites often hand out different addresses by location, so a difference isn't automatically bad.`,
  render(mount) {
    if (needCompanion(mount, 'dig')) return;
    searchTool(mount, { label: 'Domain name', placeholder: 'github.com', cta: 'Look up', wide: true, examples: ['github.com', 'wikipedia.org', 'gmail.com'],
      demo: { input: 'github.com', narrate: 'Asking your own resolver and Cloudflare for github.com, then comparing the answers.' },
      run: async (v, out) => {
        const name = host(v), type = (mount.querySelector('#dtype') || {}).value || 'A';
        loading(out); S.say(`Looking up ${type} records two ways…`);
        const [r, d] = await Promise.all([S.native('/api/run', { tool: 'dig', target: name, type }), api.doh(name, type).catch(() => null)]);
        const local = parseDig(r.stdout).filter(x => x.type === type), doh = ((d && d.Answer) || []).filter(x => x.type === TYPE_CODE[type]);
        const a = [...new Set(local.map(x => normDns(x.data)))].sort(), b = [...new Set(doh.map(x => normDns(x.data)))].sort();
        const same = a.join('|') === b.join('|');
        const cls = !a.length && !b.length ? 'warn' : same ? 'safe' : 'warn';
        out.innerHTML = verdict(cls, cls === 'safe' ? 'check' : 'alert', !a.length && !b.length ? `No ${type} records` : same ? 'Both resolvers agree' : 'The answers differ',
          !a.length && !b.length ? `Neither resolver has a ${esc(type)} record for ${esc(name)}. Try another record type.`
            : same ? `Your resolver and Cloudflare returned the same ${esc(type)} records.`
            : 'This is usually normal. Big sites answer by location, and each resolver caches answers for their TTL. If a well-known site points somewhere strange from your network, your resolver may be rewriting answers.') +
          [['Your resolver (dig)', local.map(x => [x.data, x.ttl])], ['Cloudflare DoH', doh.map(x => [x.data, x.TTL])]].map(([title, rows]) =>
            `<div class="card"><h2>${esc(title)}</h2>${rows.length ? `<div class="table-wrap"><table><thead><tr><th>Value</th><th class="num">TTL</th></tr></thead><tbody>${rows.map(([val, ttl]) =>
              `<tr><td class="mono">${esc(val)}</td><td class="num">${esc(ttl)}s</td></tr>`).join('')}</tbody></table></div>` : '<p class="mut">No records.</p>'}</div>`).join('') +
          raw('Raw dig output', r.stdout);
        S.say('');
      } });
    const sel = document.createElement('select');
    sel.id = 'dtype'; sel.setAttribute('aria-label', 'Record type'); sel.style.width = '96px';
    sel.innerHTML = Object.keys(TYPE_CODE).map(k => `<option>${k}</option>`).join('');
    mount.querySelector('.bar').insertBefore(sel, mount.querySelector('#go'));
  } });

/* ---------- WHOIS (CLI) ---------- */
S.register({ id: 'whoiscli', name: 'WHOIS (CLI)', group: 'Native', icon: 'whois', tag: 'native',
  tile: 'Run the classic whois command and compare its free text with structured RDAP data.',
  blurb: 'Run the classic whois command for a domain and compare its free-text answer with the structured RDAP record.',
  why: `${t('WHOIS')} is a 1980s protocol: you connect to port 43 and get back free text, formatted differently by every registry. ${t('RDAP')} is its modern, structured replacement. Seeing both side by side shows why tools moved on, and the raw text often holds details RDAP leaves out.`,
  render(mount) {
    if (needCompanion(mount, 'whois')) return;
    searchTool(mount, { label: 'Domain name', placeholder: 'github.com', cta: 'Look up', examples: ['github.com', 'wikipedia.org', 'example.com'],
      demo: { input: 'github.com', narrate: 'Running the whois command for github.com and comparing it with RDAP.' },
      run: async (v, out) => {
        const name = host(v);
        loading(out); S.say('Running whois…');
        const [r, d] = await Promise.all([S.native('/api/run', { tool: 'whois', target: name }), api.rdapDomain(name).catch(() => null)]);
        const w = parseWhois(r.stdout);
        const ev = Object.fromEntries(((d && d.events) || []).map(e => [e.eventAction, e.eventDate]));
        const reg = ((d && d.entities) || []).find(e => (e.roles || []).includes('registrar'));
        const rdapReg = ((((reg || {}).vcardArray || [])[1] || []).find(x => x[0] === 'fn') || [])[3];
        const cls = w.notFound ? 'warn' : w.registrar || w.created ? 'safe' : 'warn';
        const day = s => s ? String(s).slice(0, 10) : null;
        const row = (k, a, b) => `<tr><td>${k}</td><td class="mono">${esc(a || '—')}</td><td class="mono">${esc(b || '—')}</td><td>${a && b ? (normDns(a) === normDns(b) ? badge('b-safe', 'check', 'match') : badge('b-warn', 'alert', 'differs')) : ''}</td></tr>`;
        out.innerHTML = verdict(cls, cls === 'safe' ? 'check' : 'alert', w.notFound ? 'Not registered' : w.registrar ? `Registered via ${w.registrar}` : 'No structured fields found',
          w.notFound ? `The registry has no record for ${esc(name)}, so it may be available to register.`
            : w.created ? `Registered on ${esc(day(w.created))}${w.expires ? `, paid up until ${esc(day(w.expires))}` : ''}.` : 'This registry formats WHOIS differently. Read the raw text below.') +
          `<div class="card full"><h2>WHOIS text vs RDAP</h2><div class="table-wrap"><table><thead><tr><th>Field</th><th>${t('WHOIS')}</th><th>${t('RDAP')}</th><th></th></tr></thead><tbody>
            ${row('Registrar', w.registrar, rdapReg)}${row('Created', day(w.created), day(ev.registration))}${row('Expires', day(w.expires), day(ev.expiration))}
            ${row('Nameservers', w.nameservers.sort().join(' '), ((d && d.nameservers) || []).map(n => n.ldhName.toLowerCase()).sort().join(' '))}</tbody></table></div>
            ${d ? '' : '<p class="mut" style="margin-top:10px">RDAP had no record for this name, so only the WHOIS column is filled.</p>'}</div>` +
          raw('Raw whois output', r.stdout);
        S.say('');
      } });
  } });

/* ---------- Tech Detector ---------- */
S.register({ id: 'techdetect', name: 'Tech Detector', group: 'Native', icon: 'f-layers', tag: 'native',
  tile: 'Work out which server, framework and CMS a website runs from its headers and page source.',
  blurb: 'Fetch a page from your computer and work out the server, framework and CMS behind it.',
  why: `Sites give away their software in ${t('server banner','server banners')}, cookie names and file paths. Defenders check this to see what they leak; attackers use it to pick exploits, especially when a header names an exact version that has known ${t('CVE','CVEs')}. This is ordinary reading of a public page, nothing more.`,
  render(mount) {
    if (needCompanion(mount)) return;
    searchTool(mount, { label: 'Website address', placeholder: 'https://github.com', cta: 'Detect', examples: ['https://github.com', 'https://wordpress.org', 'https://www.shopify.com'],
      demo: { input: 'https://wordpress.org', narrate: 'Fetching wordpress.org from your computer and reading its headers, cookies and page source.' },
      run: async (v, out) => {
        loading(out); S.say('Fetching the page…');
        const r = await S.native('/api/http', { url: asUrl(v) }), { tech, leaks } = detectTech(r);
        const cls = leaks.length ? 'warn' : '';
        out.innerHTML = verdict(cls, leaks.length ? 'alert' : 'info', tech.length ? `${tech.length} technolog${tech.length > 1 ? 'ies' : 'y'} detected` : 'Nothing recognised',
          leaks.length ? `The site announces exact software versions (${esc(leaks.join('; '))}). Version numbers help attackers look up known vulnerabilities; most servers can hide them.`
            : tech.length ? 'Detected from headers, cookie names and the page source. No exact version numbers were exposed in the headers.' : 'No known signatures matched. The site may hide its stack well, or use software this tool doesn\'t know.') +
          `<div class="card"><h2>Detected</h2>${tech.length ? `<div class="table-wrap"><table><thead><tr><th>Technology</th><th>Kind</th><th>Evidence</th></tr></thead><tbody>${tech.map(x =>
            `<tr><td><b>${esc(x.name)}</b></td><td>${esc(x.category)}</td><td class="mono">${esc(x.evidence)}</td></tr>`).join('')}</tbody></table></div>` : '<p class="mut">None.</p>'}</div>
          <div class="card"><h2>Response</h2><div class="kv">
            <div class="k">Final URL</div><div class="v">${esc(r.finalUrl)}</div><div class="k">Status</div><div class="v">${r.status}</div>
            <div class="k">Server</div><div class="v">${esc(r.headers.server || '—')}</div><div class="k">X-Powered-By</div><div class="v">${esc(r.headers['x-powered-by'] || '—')}</div>
            <div class="k">Time</div><div class="v">${r.ms} ms</div></div></div>`;
        S.say('');
      } });
  } });

/* ---------- Link Unshortener ---------- */
S.register({ id: 'unshorten', name: 'Link Unshortener', group: 'Native', icon: 'f-link', tag: 'native',
  tile: 'Follow a short link\'s redirects from your computer and see where it really ends before you click.',
  blurb: 'Follow every redirect in a short link and see the final destination before you click it.',
  why: `A ${t('URL shortener')} hides where a link really goes, which is exactly why phishing messages use them. This tool follows each ${t('redirect')} from your computer, without opening the page in your browser, and shows every step. Watch for a final domain you didn't expect and for ${t('tracking parameter','tracking parameters')} added along the way.`,
  render(mount) {
    if (needCompanion(mount)) return;
    searchTool(mount, { label: 'Link', placeholder: 'https://aka.ms/vscode', cta: 'Expand', wide: true, examples: ['https://aka.ms/vscode', 'https://youtu.be/dQw4w9WgXcQ', 'http://github.com'],
      demo: { input: 'https://aka.ms/vscode', narrate: 'Following Microsoft\'s aka.ms short link to see where it really goes.' },
      run: async (v, out) => {
        loading(out); S.say('Following redirects…');
        const r = await S.native('/api/http', { url: asUrl(v) });
        const from = new URL(r.chain[0].url), to = new URL(r.finalUrl), hops = r.chain.length - 1;
        const site = h => h.replace(/^www\./, ''), moved = site(from.hostname) !== site(to.hostname);
        const tracking = [...to.searchParams.keys()].filter(k => /^(utm_|fbclid|gclid|mc_|wt\.|ref$|si$|feature$)/i.test(k));
        const cls = !hops ? 'safe' : moved ? 'warn' : 'safe';
        out.innerHTML = verdict(cls, cls === 'safe' ? 'check' : 'alert', !hops ? 'Not a redirect' : `Leads to ${to.hostname}`,
          !hops ? 'This address doesn\'t redirect anywhere; it is the real page.'
            : `${hops} redirect${hops > 1 ? 's' : ''}. ${moved ? 'The link ends on a different site from the one it shows. Make sure you trust that site before you click.' : 'It stays on the same site.'}${tracking.length ? ` The final address carries tracking parameters (${esc(tracking.join(', '))}).` : ''}`) +
          `<div class="card full"><h2>Final destination</h2><p class="mono" style="word-break:break-all">${esc(r.finalUrl)}</p></div>
          <div class="card full"><h2>Every step</h2><div class="table-wrap"><table><thead><tr><th class="num">Step</th><th class="num">Status</th><th>Address</th></tr></thead><tbody>${r.chain.map((c, i) =>
            `<tr><td class="num">${i + 1}</td><td class="num">${badge(c.status < 300 ? 'b-safe' : c.status < 400 ? 'b-info' : 'b-danger', c.status < 300 ? 'check' : c.status < 400 ? 'arrow' : 'x', String(c.status))}</td><td class="mono" style="word-break:break-all">${esc(c.url)}</td></tr>`).join('')}</tbody></table></div></div>`;
        S.say('');
      } });
  } });
})();
