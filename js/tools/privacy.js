/* Sentinel tool file: Privacy (What Sites See, WebRTC Leak Test, Browser Fingerprint).
   Browser-only APIs (navigator, screen, RTCPeerConnection, canvas) are touched inside run functions only, so Node tests can load this file. */
(() => {
const S = Sentinel, api = S.api, esc = S.esc, svg = S.svg, t = S.t, $ = S.helpers.$;
const { loading, demoButton, badge } = S.ui;

S.addIcons({ /* Lucide (ISC) */
  'e-eye': 'M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7zM12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6',
  'e-radio': 'M4.9 19.1C1 15.2 1 8.8 4.9 4.9M7.8 16.2c-2.3-2.3-2.3-6.1 0-8.5M16.2 7.8c2.3 2.3 2.3 6.1 0 8.5M19.1 4.9C23 8.8 23 15.1 19.1 19M12 10a2 2 0 1 0 0 4 2 2 0 0 0 0-4',
  'e-fingerprint': 'M2 12C2 6.5 6.5 2 12 2a10 10 0 0 1 8 4M5 19.5C5.5 18 6 15 6 12c0-.7.12-1.37.34-2M17.29 21.02c.12-.6.43-2.3.5-3.02M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4M8.65 22c.21-.66.45-1.32.57-2M14 13.12c0 2.38 0 6.38-1 8.88M2 16h.01M21.8 16c.2-2 .131-5.354 0-6M9 6.8a6 6 0 0 1 9 5.2c0 .47 0 1.17-.02 2',
});
S.addTerms({
  'user agent': 'A text string your browser sends with every request, naming the browser, its version and your operating system.',
  'ISP': 'Internet service provider: the company that connects you to the internet. Your public IP address belongs to it.',
  'VPN': 'Virtual private network: sends your traffic through someone else\'s server, so sites see that server\'s IP address instead of yours.',
  'Do Not Track': 'An old browser setting asking sites not to track you. Nothing enforces it and most sites ignore it.',
  'Global Privacy Control': 'A newer "don\'t sell or share my data" signal from the browser. Some laws, such as California\'s, require sites to honour it.',
  'WebRTC': 'The browser feature behind video calls. To connect two people directly it discovers your network addresses, which can reveal them to the site.',
  'STUN server': 'A public server that tells your browser what public IP address and port it appears to come from. WebRTC uses one to get through home routers.',
  'ICE candidate': 'One possible network address WebRTC could use for a connection: a local one (host) or your public one as seen by STUN (srflx).',
  'mDNS': 'Multicast DNS. Browsers now hide your local IP behind a random name ending in .local, so sites can\'t read it.',
  'private IP': 'An address used only inside a home or office network (10.x, 172.16-31.x, 192.168.x). It shouldn\'t be visible to websites.',
  'browser fingerprint': 'A profile built from many small facts about your browser and device. Combined, they can recognize you again without cookies.',
  'canvas fingerprinting': 'A site draws hidden text and shapes, then hashes the pixels. Tiny differences in graphics hardware and fonts make the result differ between devices.',
  'identifying bits': 'A way to measure how much a fact narrows down who you are. Each bit halves the crowd you blend into; about 33 bits picks one person out of 8 billion.',
});

/* ---------- pure logic ---------- */
function parseUA(ua) {
  ua = String(ua || '');
  const m = re => (ua.match(re) || [])[1] || '';
  const b = [['Edge', /Edg(?:A|iOS)?\/([\d.]+)/], ['Opera', /OPR\/([\d.]+)/], ['Samsung Internet', /SamsungBrowser\/([\d.]+)/],
    ['Firefox', /(?:Firefox|FxiOS)\/([\d.]+)/], ['Chrome', /(?:Chrome|CriOS)\/([\d.]+)/], ['Safari', /Version\/([\d.]+).*Safari/]].find(([, re]) => re.test(ua));
  const os = /iPhone|iPad|iPod/.test(ua) ? 'iOS ' + m(/OS (\d+(?:_\d+)*)/).replace(/_/g, '.') : /Android/.test(ua) ? 'Android ' + m(/Android ([\d.]+)/)
    : /Windows NT 10/.test(ua) ? 'Windows 10 or 11' : /Windows/.test(ua) ? 'Windows' : /CrOS/.test(ua) ? 'ChromeOS'
    : /Mac OS X/.test(ua) ? 'macOS' : /Linux/.test(ua) ? 'Linux' : 'Unknown';
  return { browser: b ? b[0] : 'Unknown', version: b ? m(b[1]).split('.')[0] : '', os: os.trim() };
}

function ipKind(ip) {
  if (/\.local$/i.test(ip)) return 'mdns';
  if (ip.includes(':')) { const l = ip.toLowerCase(); return l === '::1' ? 'loopback' : /^fe[89ab]/.test(l) ? 'link-local' : /^f[cd]/.test(l) ? 'private' : 'public'; }
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ? 'private' : a === 127 ? 'loopback'
    : a === 169 && b === 254 ? 'link-local' : a === 100 && b >= 64 && b <= 127 ? 'cgnat' : 'public';
}
// "candidate:842163049 1 udp 1677729535 203.0.113.5 54321 typ srflx raddr 0.0.0.0 rport 0 …" → parts
function parseCandidate(str) {
  const p = String(str).replace(/^a=/, '').trim().split(/\s+/), i = p.indexOf('typ'), ip = p[4] || '';
  return { ip, port: p[5] || '', protocol: (p[2] || '').toLowerCase(), type: i > 0 ? p[i + 1] : '?', kind: ipKind(ip) };
}
// Candidate strings + the IPs your normal HTTPS requests came from → verdict.
function webrtcVerdict(list, httpIps) {
  const c = list.map(parseCandidate);
  const local = [...new Set(c.filter(x => x.type === 'host' && ['private', 'cgnat', 'link-local'].includes(x.kind)).map(x => x.ip))];
  const pub = [...new Set(c.filter(x => x.kind === 'public').map(x => x.ip))];
  const extra = pub.filter(ip => !httpIps.includes(ip));
  const v = (cls, title, sub) => ({ cls, title, sub, candidates: c });
  if (!c.length) return v('safe', 'WebRTC revealed nothing', 'No candidates came back, so WebRTC is blocked here (by a setting or an extension). Nothing can leak this way.');
  if (httpIps.length && extra.length) return v('danger', 'Leak: WebRTC shows a different public IP', `WebRTC revealed ${extra.join(', ')}, which your normal web traffic did not show (${httpIps.join(', ')}). If you use a VPN, any site can read your real address this way. Turn on your VPN's WebRTC leak protection or disable WebRTC.`);
  if (local.length) return v('warn', 'Your local network address is exposed', `WebRTC shows ${local.join(', ')} to every site you visit. Current browsers hide it behind a random .local name; this one doesn't. Update the browser or check its WebRTC settings.`);
  if (!pub.length) return v('', 'Inconclusive: the STUN server didn\'t answer', 'Your local address is hidden, but no public address came back (UDP may be blocked on this network), so there was nothing to compare.');
  if (!httpIps.length) return v('', 'Inconclusive: couldn\'t look up your web IP', 'WebRTC returned a public address, but the IP lookup failed (an ad blocker, or no connection), so it couldn\'t be compared. Try again.');
  return v('safe', 'No leak', 'Your local address is masked and WebRTC shows the same public IP your web traffic already shows.');
}

// Limit: fixed rough per-trait estimates; real figures need population data (like AmIUnique's) and shift with who visits.
const FP = [['canvas', 'Canvas drawing', 8], ['webgl', 'Graphics card (WebGL)', 5], ['fonts', 'Installed fonts', 7], ['screen', 'Screen', 5],
  ['timezone', 'Time zone', 3], ['languages', 'Languages', 3], ['cores', 'CPU cores', 2], ['memory', 'Device memory', 1]];
function scoreFingerprint(c) {
  const rows = FP.map(([k, label, bits]) => {
    const v = c[k], blank = v == null || v === '' || (Array.isArray(v) && !v.length) || (k === 'canvas' && v.noisy);
    const value = k === 'canvas' ? (!v ? 'blocked' : v.noisy ? 'randomized on every read' : v.hash.slice(0, 16) + '…')
      : Array.isArray(v) ? (v.length ? `${v.length} found: ${v.join(', ')}` : 'none found') : v == null || v === '' ? 'hidden' : String(v);
    return { k, label, value, bits: blank ? 0 : bits };
  });
  const bits = rows.reduce((a, r) => a + r.bits, 0);
  return { rows, bits, cls: bits >= 25 ? 'warn' : 'safe' };
}
Object.assign(S.lib, { parseUA, parseCandidate, webrtcVerdict, scoreFingerprint });

/* ---------- shared UI ---------- */
// No input: one action button and an empty state; the header Run example does the same thing on this browser.
function panel(mount, cta, intro, narrate, run) {
  mount.innerHTML = `<div class="bar"><button class="btn secondary" id="pgo">${esc(cta)}</button></div>
    <div id="status" role="status" aria-live="polite"></div>
    <div id="out" class="grid two"><div class="card full empty"><b>Nothing measured yet</b>${intro}</div></div>`;
  const out = $('#out', mount), b = $('#pgo', mount), go = async () => {
    b.setAttribute('aria-busy', 'true');
    try { await run(out); S.say(''); } catch (e) { out.innerHTML = ''; S.say(e.message, true); }
    b.removeAttribute('aria-busy');
  };
  b.onclick = go;
  demoButton(() => { S.toast(narrate); go(); });
}
const card = (cls, title, sub) => `<div class="card verdict ${cls} full"><h2 class="big">${svg(cls === 'safe' ? 'check' : cls === 'danger' ? 'x' : cls === 'warn' ? 'alert' : 'info')}${esc(title)}</h2><div class="sub">${sub}</div></div>`;
const kv = rows => `<div class="kv">${rows.map(([k, v]) => `<div class="k">${k}</div><div class="v">${esc(v)}</div>`).join('')}</div>`;

/* ---------- What Sites See ---------- */
async function runSee(out) {
  loading(out); S.say('Asking ipwho.is what your IP address reveals…');
  // https://ipwho.is/ with no IP looks up the caller. Verified 2026-10-14: 200, access-control-allow-origin: *,
  // {ip, success, type:'IPv4'|'IPv6', city, region, country, connection:{asn, org, isp, domain}, timezone:{id, utc}}. api.geo never throws.
  const geo = await api.geo('');
  const n = navigator, ua = parseUA(n.userAgent), tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const off = -new Date().getTimezoneOffset(), p2 = x => String(x).padStart(2, '0');
  const browser = [
    ['Browser', `${ua.browser} ${ua.version}`.trim()], ['Operating system', ua.os],
    ['Languages', (n.languages || [n.language]).join(', ')], ['Time zone', `${tz} (UTC${off < 0 ? '-' : '+'}${p2(Math.floor(Math.abs(off) / 60))}:${p2(Math.abs(off) % 60)})`],
    ['Screen', `${screen.width}×${screen.height}, ${devicePixelRatio}x pixel density, ${screen.colorDepth}-bit color`],
    ['CPU cores', n.hardwareConcurrency || 'hidden'], ['Touch screen', n.maxTouchPoints > 0 ? `yes (${n.maxTouchPoints} touch points)` : 'no'],
    ['Cookies', n.cookieEnabled ? 'enabled' : 'disabled'],
    [t('Do Not Track'), n.doNotTrack === '1' ? 'on' : 'off'], [t('Global Privacy Control'), n.globalPrivacyControl ? 'on' : 'off or not supported'],
  ];
  const ok = geo && geo.success, c = ok ? geo.connection || {} : {}, ipTz = ok && geo.timezone ? geo.timezone.id : '';
  const where = ok ? [geo.city, geo.region, geo.country].filter(Boolean).join(', ') : '';
  const vpnTell = ipTz && ipTz !== tz;
  out.innerHTML = card(vpnTell ? 'warn' : '', ok ? `Sites can place you near ${where}` : `Sites see your IP address and ${browser.length} browser facts`,
      `Every site you open gets all of this without asking: your ${t('IP address')} (which reveals your ${t('ISP')} and rough location) plus ${browser.length} facts your browser volunteers. No permission prompt is involved.
      ${vpnTell ? `<br><b>Your IP's time zone (${esc(ipTz)}) and your clock's (${esc(tz)}) disagree.</b> That is typical of a ${t('VPN')}, and sites can notice it.` : ''}`) +
    (ok ? `<div class="card"><h2>Your network</h2>${kv([['IP address', geo.ip], ['Version', geo.type], ['Provider', c.isp || c.org || 'unknown'], ['Network', c.asn ? 'AS' + c.asn : 'unknown'],
        ['Approximate location', where || 'unknown'], ['IP\'s time zone', ipTz || 'unknown']])}
        <p class="mut" style="margin-top:12px;font-size:var(--text-sm)">IP location is usually right about the city, not the street. A ${t('VPN')} replaces all of this with the VPN server's details.</p></div>`
      : `<div class="note warn">${svg('alert')}<div><b>Couldn't reach ipwho.is.</b> ${esc(geo && geo.message ? geo.message : 'The lookup failed or was blocked')}. Sites still see your IP; this page just couldn't look up what it reveals. Check your connection or ad blocker, then run it again.</div></div>`) +
    `<div class="card"><h2>Your browser</h2>${kv(browser)}</div>
    <div class="card full"><h2>Full ${t('user agent')} string</h2><div class="out-pre mono">${esc(n.userAgent)}</div>
      <p class="mut" style="margin-top:12px;font-size:var(--text-sm)">Browsers now freeze parts of this string (Chrome on a Mac always claims macOS 10.15.7) so it identifies you less. The ${t('browser fingerprint', 'Browser Fingerprint')} tool shows what else can.</p></div>`;
}

/* ---------- WebRTC Leak Test ---------- */
// Verified 2026-10-14 with a raw STUN binding request from Node: stun.l.google.com:19302 answers 0x0101 (binding success).
const STUN = 'stun:stun.l.google.com:19302';
function gather() {
  return new Promise(res => {
    const pc = new RTCPeerConnection({ iceServers: [{ urls: STUN }] }), c = [];
    const done = () => { clearTimeout(tm); try { pc.close(); } catch (e) { /* already closed */ } res(c); };
    const tm = setTimeout(done, 5000);
    pc.onicecandidate = e => { if (!e.candidate) done(); else if (e.candidate.candidate) c.push(e.candidate.candidate); };
    pc.createDataChannel('sentinel');
    pc.createOffer().then(o => pc.setLocalDescription(o)).catch(done);
  });
}
// api.ipify.org → {"ip":"…"} over IPv4 only; api64.ipify.org → same shape, IPv6 when you have it. Both verified 2026-10-14: 200, access-control-allow-origin: *.
const httpIps = () => Promise.all(['https://api.ipify.org?format=json', 'https://api64.ipify.org?format=json']
  .map(u => api.jget(u).then(j => j.ip).catch(() => null))).then(a => [...new Set(a.filter(Boolean))]);
const TYPE = { host: 'your device', srflx: 'public, via STUN', prflx: 'public, via peer', relay: 'relay server' };
async function runRtc(out) {
  if (typeof RTCPeerConnection === 'undefined') {
    out.innerHTML = card('safe', 'WebRTC is turned off', `This browser doesn't offer ${t('WebRTC')} to pages, so it can't leak your addresses. Video-call sites won't work here until you turn it back on.`);
    return;
  }
  loading(out); S.say('Gathering ICE candidates via stun.l.google.com and looking up your web IP…');
  const [cands, ips] = await Promise.all([gather(), httpIps()]);
  const v = webrtcVerdict(cands, ips);
  const tag = x => x.kind === 'mdns' ? badge('b-safe', 'check', 'hidden (mDNS)') : x.kind === 'public'
    ? (ips.includes(x.ip) ? badge('b-safe', 'check', 'same as web IP') : ips.length ? badge('b-danger', 'x', 'differs from web IP') : badge('b-mut', 'info', 'public'))
    : x.type === 'host' && x.kind !== 'loopback' ? badge('b-warn', 'alert', 'local IP exposed') : badge('b-mut', 'info', x.kind);
  out.innerHTML = card(v.cls, v.title, esc(v.sub)) +
    `<div class="card"><h2>${t('ICE candidate', 'ICE candidates')} (${v.candidates.length})</h2>${v.candidates.length ? `<div class="table-wrap"><table><thead><tr><th>Type</th><th>Address</th><th>Protocol</th><th>Meaning</th></tr></thead><tbody>${
      v.candidates.map(x => `<tr><td class="mono">${esc(x.type)}</td><td class="mono" style="word-break:break-all">${esc(x.ip)}</td><td class="mono">${esc(x.protocol)}</td><td>${tag(x)} <span class="mut">${esc(TYPE[x.type] || '')}</span></td></tr>`).join('')}</tbody></table></div>` : '<span class="mut">None.</span>'}</div>
    <div class="card"><h2>Compared against</h2>${kv([['Web IP (IPv4)', ips.find(x => !x.includes(':')) || 'not found'], ['Web IP (IPv6)', ips.find(x => x.includes(':')) || 'none']])}
      <p class="mut" style="margin-top:12px;font-size:var(--text-sm)">Looked up through api.ipify.org: the address every site sees on a normal request. A leak is WebRTC showing an address that isn't on this list.</p></div>`;
}

/* ---------- Browser Fingerprint ---------- */
const FONTS = ['Arial', 'Arial Black', 'Avenir', 'Calibri', 'Cambria', 'Comic Sans MS', 'Consolas', 'Courier New', 'DejaVu Sans', 'Fira Code', 'Futura', 'Georgia', 'Gill Sans', 'Helvetica',
  'Helvetica Neue', 'Impact', 'Lucida Console', 'Menlo', 'Monaco', 'Noto Sans', 'Optima', 'Palatino', 'Roboto', 'Segoe UI', 'Source Code Pro', 'Tahoma', 'Times New Roman', 'Trebuchet MS', 'Ubuntu', 'Verdana'];
async function collectFp() {
  const cv = document.createElement('canvas'), x = cv.getContext('2d');
  // The colors and text below are part of the measurement (an offscreen canvas), not UI.
  const draw = () => { cv.width = 260; cv.height = 60; x.textBaseline = 'top'; x.font = '16px Arial'; x.fillStyle = '#f60'; x.fillRect(110, 4, 90, 30);
    x.fillStyle = '#069'; x.fillText('Cwm fjordbank glyphs vext quiz', 4, 8); x.fillStyle = 'rgba(102,204,0,.7)'; x.font = '18px serif'; x.fillText('Sentinel 1.0', 8, 30); return cv.toDataURL(); };
  let canvas = null;
  try { const a = draw(), b = draw(); canvas = { hash: await S.sha('SHA-256', a), noisy: a !== b }; } catch (e) { /* canvas blocked */ }
  let webgl = null;
  try { const g = document.createElement('canvas').getContext('webgl'), d = g && g.getExtension('WEBGL_debug_renderer_info');
    if (g) webgl = `${g.getParameter(d ? d.UNMASKED_VENDOR_WEBGL : g.VENDOR)} / ${g.getParameter(d ? d.UNMASKED_RENDERER_WEBGL : g.RENDERER)}`; } catch (e) { /* WebGL off */ }
  // A font is installed if text set in it measures differently from all three generic fallbacks.
  const BASE = ['monospace', 'serif', 'sans-serif'], w = f => { x.font = `72px ${f}`; return x.measureText('mmmmmmmmmmlli').width; }, base = x ? BASE.map(w) : [];
  const fonts = x ? FONTS.filter(f => BASE.some((b, i) => w(`"${f}", ${b}`) !== base[i])) : [];
  const n = navigator;
  return { canvas, webgl, fonts, screen: `${screen.width}×${screen.height}, ${screen.colorDepth}-bit, ${devicePixelRatio}x`,
    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone, languages: (n.languages || [n.language]).join(', '),
    cores: n.hardwareConcurrency || null, memory: n.deviceMemory ? n.deviceMemory + ' GB (rounded)' : null };
}
async function runFp(out) {
  loading(out); S.say('Measuring this browser…');
  const comp = await collectFp(), r = scoreFingerprint(comp), id = await S.sha('SHA-256', JSON.stringify(comp));
  const noisy = comp.canvas && comp.canvas.noisy;
  out.innerHTML = card(r.cls, r.cls === 'warn' ? `Easy to recognize: about ${r.bits} identifying bits` : `Harder to recognize: about ${r.bits} identifying bits`,
      `Each of the ${t('identifying bits')} halves the crowd you blend into; about 33 would single out one browser among 8 billion. These traits overlap, so the total is a rough upper estimate, not proof that you are unique.
      ${noisy ? ' Your browser adds random noise to canvas reads, a deliberate anti-fingerprinting defence.' : ''}`) +
    `<div class="card full"><h2>What each trait gives away</h2><div class="table-wrap"><table><thead><tr><th>Trait</th><th>This browser</th><th class="num">≈ bits</th></tr></thead><tbody>${
      r.rows.map(x => `<tr><td>${esc(x.label)}</td><td class="mono" style="word-break:break-word">${esc(x.value)}</td><td class="num">${x.bits}<div class="meter" style="width:64px;margin:4px 0 0 auto"><i style="width:${x.bits / 8 * 100}%;background:var(--info)"></i></div></td></tr>`).join('')}</tbody></table></div>
      <p class="mut" style="margin-top:12px;font-size:var(--text-sm)">Bits are rough estimates of how rare each trait usually is, not measured from real visitors. Sites like EFF's Cover Your Tracks compare you with their actual visitors.</p></div>
    <div class="card full"><h2>Your fingerprint ID</h2><div class="out-pre mono" style="word-break:break-all">${esc(id)}</div>
      <p class="mut" style="margin-top:12px;font-size:var(--text-sm)">A ${t('hash', 'SHA-256 hash')} of everything above. Open this page in a private window: if the ID stays the same, a site can recognize you with no cookies at all. Nothing here left your browser.</p></div>`;
}

/* ---------- registration ---------- */
S.register({ id: 'whatsites', name: 'What Sites See', group: 'Privacy', icon: 'e-eye', tag: 'live',
  tile: 'See your public IP, provider, rough location and the device facts every website reads without asking.',
  blurb: 'Everything a website learns about you the moment you open it, before you click anything or accept any cookies.',
  why: `Every request carries your ${t('IP address')}, which points to your ${t('ISP')} and your rough location, and your browser volunteers its ${t('user agent')}, languages, time zone and screen size. None of it needs permission. Knowing the list is the first step to deciding what to hide, for example with a ${t('VPN')}.`,
  render(mount) {
    panel(mount, 'Show what sites see', 'Your IP is looked up at ipwho.is, a public service; everything else is read from this browser and stays here.',
      'Looking up your own IP at ipwho.is and listing what your browser tells every site.', runSee);
  } });

S.register({ id: 'webrtc', name: 'WebRTC Leak Test', group: 'Privacy', icon: 'e-radio', tag: 'live',
  tile: 'Check whether WebRTC exposes your local IP, or a real IP your VPN is meant to hide.',
  blurb: 'Check whether WebRTC, the browser\'s video-call feature, reveals your local network address or the real IP behind your VPN.',
  why: `To connect calls directly, ${t('WebRTC')} gathers ${t('ICE candidate', 'candidate addresses')}: your device's own address and your public one, which it learns by asking a ${t('STUN server')}. Any web page can trigger this silently. Modern browsers hide your ${t('private IP', 'local address')} behind ${t('mDNS')}, but a misconfigured ${t('VPN')} can still let your real public IP slip out.`,
  render(mount) {
    panel(mount, 'Run the leak test', 'Contacts a public STUN server (stun.l.google.com) and api.ipify.org, then compares the addresses.',
      'Asking a public STUN server for your addresses and comparing them with the IP every site sees.', runRtc);
  } });

S.register({ id: 'fingerprint', name: 'Browser Fingerprint', group: 'Privacy', icon: 'e-fingerprint', tag: 'local',
  tile: 'Estimate how recognizable your browser is from canvas, graphics card, fonts, screen and more.',
  blurb: 'Measure the traits that let sites recognize your browser without cookies, and roughly how much each one gives away. Runs entirely in your browser.',
  why: `Clearing cookies doesn't make you anonymous. A ${t('browser fingerprint')} combines traits like ${t('canvas fingerprinting', 'canvas rendering')}, graphics card, installed fonts and screen size into an ID that often survives private windows. This is an estimate: it shows which traits identify you, not a promise that you are or aren't unique.`,
  render(mount) {
    panel(mount, 'Measure my fingerprint', 'Draws an offscreen canvas, reads your graphics card name and checks 30 common fonts. Nothing is sent anywhere.',
      'Measuring canvas, WebGL, fonts and screen locally, then hashing them into one fingerprint ID.', runFp);
  } });
})();
