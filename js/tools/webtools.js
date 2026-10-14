/* Sentinel tool file: Web & email (CSP Evaluator, Header Analyzer, URL Inspector) and Security Headers (live).
   One grader: gradeCsp feeds gradeHeaders, which feeds both the paste mode and the companion fetch. */
(() => {
const S = Sentinel, esc = S.esc, svg = S.svg, t = S.t, $ = S.helpers.$;
const { searchTool, loading, demoButton, badge } = S.ui;

S.addIcons({ /* Lucide (ISC) */
  'e-code': 'M16 18l6-6-6-6M8 6l-6 6 6 6',
  'e-list': 'M3 6h.01M3 12h.01M3 18h.01M8 6h13M8 12h13M8 18h13',
  'e-server': 'M4 2h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2zM4 14h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2zM6 6h.01M6 18h.01',
  'e-link': 'M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71',
});
S.addTerms({
  'CSP': 'Content-Security-Policy: a response header listing where a page may load scripts, styles and frames from. A strict one stops most cross-site scripting.',
  'XSS (cross-site scripting)': 'An attacker gets their own JavaScript to run on someone else\'s site, where it can read the page and act as the logged-in user.',
  'CSP nonce': 'A random value the server puts in the CSP header and on each script tag it trusts. Injected scripts don\'t know the value, so the browser blocks them.',
  'HSTS': 'Strict-Transport-Security: tells the browser to use only HTTPS for this site from now on, so nobody on the network can downgrade you to plain HTTP.',
  'clickjacking': 'Loading a real site in an invisible frame on top of a decoy page, so your clicks land on buttons you can\'t see.',
  'MIME sniffing': 'When a browser ignores the declared file type and guesses from the content. A guessed "script" can turn an uploaded file into running code.',
  'cookie flags': 'Secure (HTTPS only), HttpOnly (JavaScript can\'t read it) and SameSite (not sent on most cross-site requests). Together they protect session cookies.',
  'response headers': 'Lines a web server sends before the page itself, like name: value. Many of them switch browser security features on or off.',
  'punycode': 'The ASCII form of a non-English domain name, starting with xn--. DNS only understands ASCII, so a name spelled with Cyrillic letters travels as something like xn--80ak6aa92e.com.',
  'IDN': 'Internationalized domain name: a domain written in a non-Latin alphabet or with accents. Browsers show the Unicode form; DNS sees the punycode form.',
  'defang': 'Rewriting a dangerous link so it can\'t be clicked by accident, e.g. hxxps://evil[.]example. Standard practice in security reports and chats.',
  'percent-encoding': 'Writing characters as % plus two hex digits (%2F is /). Normal in URLs, but also used to hide what a link really says.',
});

/* ---------- grading (pure) ---------- */
const PTS = { bad: 25, warn: 10, info: 0, ok: 0 };
const F = (sev, title, fix = '', pts) => ({ sev, title, fix, pts });
function grade(fs) {
  const score = Math.max(0, 100 - fs.reduce((a, f) => a + (f.pts ?? PTS[f.sev]), 0));
  let g = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  if (g < 'C' && fs.some(f => f.sev === 'bad')) g = 'C'; // one failing check caps the grade at C
  return { score, grade: g };
}
const KNOWN = new Set('default-src script-src script-src-elem script-src-attr style-src style-src-elem style-src-attr img-src font-src connect-src media-src object-src frame-src child-src worker-src manifest-src prefetch-src fenced-frame-src base-uri form-action frame-ancestors navigate-to sandbox report-uri report-to upgrade-insecure-requests block-all-mixed-content require-trusted-types-for trusted-types plugin-types'.split(' '));

// Directive name → source list. Only the first policy (before a comma) and the first copy of a directive count, as in browsers.
function parseCsp(raw) {
  const d = Object.create(null);
  for (const part of String(raw).replace(/^\s*content-security-policy(?:-report-only)?\s*:/i, '').split(',')[0].split(';')) {
    const [name, ...src] = part.trim().split(/\s+/);
    if (name && !(name.toLowerCase() in d)) d[name.toLowerCase()] = src;
  }
  return d;
}
function gradeCsp(raw) {
  const d = parseCsp(raw), f = [], policies = String(raw).split(',').filter(p => p.trim()).length;
  const has = (l, k) => (l || []).some(s => s.toLowerCase() === k);
  const from = d['script-src'] ? 'script-src' : 'default-src', script = d[from];
  if (!script) f.push(F('bad', 'No script-src or default-src', 'Scripts may load from anywhere. Add script-src with nonces or hashes, or at least default-src \'self\'.'));
  else {
    const nonce = script.some(s => /^'(nonce|sha256|sha384|sha512)-/i.test(s)), dyn = has(script, "'strict-dynamic'");
    if (has(script, "'unsafe-inline'")) f.push(nonce
      ? F('info', `'unsafe-inline' in ${from} is ignored`, 'Browsers that understand nonces or hashes ignore it. It only remains as a fallback for very old browsers.')
      : F('bad', `'unsafe-inline' in ${from}`, 'Any injected script tag runs, which defeats CSP\'s main job against XSS. Use nonces or hashes instead.'));
    if (has(script, "'unsafe-eval'")) f.push(F('warn', `'unsafe-eval' in ${from}`, 'Lets scripts turn text into code with eval(), a common XSS route. Remove it and refactor code that needs eval.'));
    if (dyn && nonce) f.push(F('ok', `${from} uses 'strict-dynamic' with a nonce or hash`, 'Modern browsers ignore the host and scheme entries and trust only scripts the page itself vouches for.'));
    else {
      if (dyn) f.push(F('warn', "'strict-dynamic' without a nonce or hash", 'Modern browsers will block every script, while old ones fall back to the host list. Add a nonce or hash.'));
      for (const s of script) {
        const l = s.toLowerCase();
        if (l === '*' || l === 'http:' || l === 'https:') f.push(F('bad', `${s} in ${from}`, 'Allows scripts from any website. List specific hosts, or better, use nonces with \'strict-dynamic\'.'));
        else if (l === 'data:') f.push(F('bad', `data: in ${from}`, 'An attacker can inline a whole script as a data: URL. Remove data: from script sources.'));
        else if (l === 'blob:') f.push(F('warn', `blob: in ${from}`, 'Scripts built at runtime as blob: URLs are allowed. Remove it unless the app truly needs it.', 5));
      }
      if (nonce) f.push(F('ok', `${from} uses nonces or hashes`, 'Only scripts carrying the right nonce or hash run; injected ones are blocked.'));
      if (script.some(s => !s.startsWith("'") && !s.endsWith(':') && s !== '*')) f.push(F('info', `${from} relies on a host allowlist`, 'Scripts from these hosts run without a nonce. Allowed hosts often serve something an attacker can reuse (JSONP endpoints, old libraries); nonces with \'strict-dynamic\' avoid that.'));
    }
  }
  const obj = d['object-src'] || d['default-src'];
  f.push(obj && obj.length === 1 && has(obj, "'none'") ? F('ok', "Plugins blocked (object-src 'none')")
    : F('warn', "object-src is not 'none'", 'Plugin content (object and embed tags) can run script. Add object-src \'none\'.'));
  f.push(d['base-uri'] ? F('ok', `base-uri ${d['base-uri'].join(' ')}`)
    : F('warn', 'No base-uri', 'An injected base tag could point every relative script URL at an attacker\'s server. Add base-uri \'none\' or \'self\'.'));
  f.push(d['frame-ancestors'] ? F('ok', `frame-ancestors ${d['frame-ancestors'].join(' ')}`)
    : F('warn', 'No frame-ancestors', 'Any site can frame this page (clickjacking) unless X-Frame-Options covers it. Add frame-ancestors \'none\' or \'self\'.', 5));
  for (const k of Object.keys(d)) if (!KNOWN.has(k)) f.push(F('info', `Unknown directive "${k}"`, 'Browsers ignore directives they don\'t know. Check the spelling.'));
  if (policies > 1) f.push(F('info', `${policies} policies found; graded the first`, 'Browsers enforce every policy at once, so real protection is at least this strong.'));
  return { directives: d, findings: f, ...grade(f) };
}

// Raw header text → { status, headers }. headers matches the companion's /api/http shape:
// lowercase name → string (repeats joined with ", "), except set-cookie → array of strings.
function parseHttpHeaders(raw) {
  let status = null, headers = Object.create(null);
  for (const ln of String(raw).replace(/\r/g, '').split('\n')) {
    const st = ln.match(/^HTTP\/[\d.]+\s+(\d{3})/i);
    if (st) { status = +st[1]; headers = Object.create(null); continue; } // curl -L prints every hop: keep the last response
    const m = ln.match(/^([!#$%&'*+.^_`|~0-9A-Za-z-]+):\s*(.*)$/);
    if (!m) continue;
    const k = m[1].toLowerCase(), v = m[2].trim();
    if (k === 'set-cookie') (headers[k] = headers[k] || []).push(v);
    else headers[k] = k in headers ? headers[k] + ', ' + v : v;
  }
  return { status, headers };
}

const COOKIE_WHY = { Secure: 'Secure keeps it off plain HTTP.', HttpOnly: 'HttpOnly hides it from JavaScript, so an XSS bug can\'t steal it.', SameSite: 'SameSite stops it riding along on cross-site requests (CSRF).' };
const XO = [['Cross-Origin-Opener-Policy', 'COOP same-origin cuts the link to windows that open this page or that it opens, blocking some cross-window attacks.'],
  ['Cross-Origin-Resource-Policy', 'CORP stops other sites embedding this response. Matters most for APIs and private files.'],
  ['Cross-Origin-Embedder-Policy', 'COEP is only needed for cross-origin isolation (features like SharedArrayBuffer). Fine to leave out otherwise.']];
function gradeHeaders(h) {
  const f = [], g = k => typeof h[k] === 'string' ? h[k] : '';
  const hsts = g('strict-transport-security');
  if (!hsts) f.push(F('bad', 'No HSTS (Strict-Transport-Security)', 'The first visit can happen over plain HTTP, where someone on the network can intercept it. Add Strict-Transport-Security: max-age=31536000; includeSubDomains'));
  else {
    const age = +(hsts.match(/max-age\s*=\s*"?(\d+)/i) || [])[1] || 0;
    if (age < 31536000) f.push(F(age ? 'warn' : 'bad', `HSTS max-age is only ${age} seconds`, 'Use at least one year (31536000) so browsers keep insisting on HTTPS.'));
    else if (!/includesubdomains/i.test(hsts)) f.push(F('warn', 'HSTS without includeSubDomains', 'Subdomains can still be reached over plain HTTP. Add includeSubDomains once they all support HTTPS.', 5));
    else f.push(F('ok', `HSTS for ${Math.round(age / 86400)} days, subdomains included${/preload/i.test(hsts) ? ', preload' : ''}`));
  }
  let csp = null;
  if (g('content-security-policy')) {
    csp = gradeCsp(g('content-security-policy'));
    const p = { A: 0, B: 5, C: 10, D: 15, F: 20 }[csp.grade];
    f.push(F(p > 10 ? 'bad' : p ? 'warn' : 'ok', `Content-Security-Policy grade ${csp.grade}`, p ? 'Its weak spots are listed in the CSP findings.' : '', p));
  } else f.push(F('bad', g('content-security-policy-report-only') ? 'CSP is report-only' : 'No Content-Security-Policy',
    'Without an enforced CSP, one XSS bug lets injected scripts run freely. Start with a nonce-based script-src; the CSP Evaluator explains each part.'));
  const xfo = g('x-frame-options').trim().toUpperCase(), fa = csp && csp.directives['frame-ancestors'];
  f.push(fa || xfo === 'DENY' || xfo === 'SAMEORIGIN' ? F('ok', `Framing blocked (${fa ? 'CSP frame-ancestors' : 'X-Frame-Options ' + xfo})`)
    : F('warn', 'Any site can frame this page', 'That enables clickjacking. Add X-Frame-Options: DENY or CSP frame-ancestors \'none\'.'));
  f.push(/nosniff/i.test(g('x-content-type-options')) ? F('ok', 'X-Content-Type-Options: nosniff')
    : F('warn', 'No X-Content-Type-Options: nosniff', 'Browsers may guess a file\'s type and run an uploaded file as script. Add X-Content-Type-Options: nosniff.'));
  const rp = g('referrer-policy').split(',').map(s => s.trim().toLowerCase()).filter(Boolean).pop(); // the last value a browser knows wins
  if (!rp) f.push(F('info', 'No Referrer-Policy', 'Browsers default to strict-origin-when-cross-origin, which is reasonable. Setting it makes that explicit.'));
  else if (rp === 'unsafe-url' || rp === 'no-referrer-when-downgrade') f.push(F(rp === 'unsafe-url' ? 'bad' : 'warn', `Referrer-Policy: ${rp}`, 'Full URLs (paths, search terms, tokens in links) leak to other sites. Use strict-origin-when-cross-origin.'));
  else f.push(F('ok', `Referrer-Policy: ${rp}`));
  f.push(g('permissions-policy') ? F('ok', 'Permissions-Policy is set')
    : F('warn', 'No Permissions-Policy', 'It limits which browser features (camera, microphone, location) the page and its frames may use. Turn off what you don\'t need.', 5));
  for (const [name, why] of XO) { const v = g(name.toLowerCase()); f.push(v ? F('ok', `${name}: ${v}`) : F('info', `No ${name}`, why)); }
  for (const c of [].concat(h['set-cookie'] || [])) {
    const name = String(c).split('=')[0].trim(), a = String(c).toLowerCase();
    const miss = [!/;\s*secure\b/.test(a) && 'Secure', !/;\s*httponly\b/.test(a) && 'HttpOnly', !/;\s*samesite\s*=/.test(a) && 'SameSite'].filter(Boolean);
    // Limit: "session cookie" is guessed from the name; HttpOnly is only graded hard on those
    const sessiony = /sess|sid|auth|token|login/i.test(name);
    f.push(!miss.length ? F('ok', `Cookie ${name}: Secure, HttpOnly, SameSite`)
      : F(miss.includes('Secure') || (sessiony && miss.includes('HttpOnly')) ? 'warn' : 'info', `Cookie ${name} lacks ${miss.join(', ')}`, miss.map(k => COOKIE_WHY[k]).join(' ')));
  }
  if (g('x-powered-by')) f.push(F('warn', `X-Powered-By: ${g('x-powered-by')}`, 'Advertises the server software, which helps attackers pick exploits. Remove the header.', 5));
  if (/\d/.test(g('server'))) f.push(F('warn', `Server: ${g('server')}`, 'Reveals the exact server version. Configure the server to hide it.', 5));
  return { findings: f, csp, ...grade(f) };
}

/* ---------- URL inspection (pure) ---------- */
const refang = s => String(s).trim().replace(/^hxxp/i, 'http').replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, '.')
  .replace(/\[:\/\/\]/g, '://').replace(/\[:\]/g, ':').replace(/\[@\]|\[at\]/gi, '@');
const defang = s => refang(s).replace(/^http/i, 'hxxp').replace(/\./g, '[.]');
// Letters from other alphabets that pass for Latin ones (Cyrillic, Greek, Armenian, Latin IPA), in \u form so nobody misreads them.
const LOOK_FROM = '\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0456\u0458\u0455\u0501\u04cf\u04bb\u051b\u051d\u03bf\u03b1\u03bd\u03c1\u03b9\u03ba\u03c5\u03c7\u0585\u057d\u0578\u0570\u0131\u0251\u0261';
const LOOK_TO = 'aeopcyxijsdlhqwoavpikuxounhiag';
const APPLE = 'https://\u0430\u0440\u0440\u04cf\u0435.com/'; // "apple" in Cyrillic: Xudong Zheng's 2017 homograph proof of concept
const lookalike = s => [...s].map(c => { const i = LOOK_FROM.indexOf(c); return i < 0 ? c : LOOK_TO[i]; }).join('');
// Limit: a dozen scripts; letters from others (Georgian, Ethiopic…) are not counted. Unicode's full confusables table is the upgrade.
const SCRIPTS = ['Latin', 'Cyrillic', 'Greek', 'Armenian', 'Hebrew', 'Arabic', 'Devanagari', 'Thai', 'Hangul', 'Han', 'Hiragana', 'Katakana'].map(n => [n, new RegExp(`\\p{Script=${n}}`, 'u')]);
function scriptsOf(label) {
  const set = new Set();
  for (const ch of label) { const hit = SCRIPTS.find(([, r]) => r.test(ch)); if (hit) set.add(/Han|Hira|Kata|Hangul/.test(hit[0]) ? 'CJK' : hit[0]); }
  return set;
}
const mixed = l => { const s = scriptsOf(l); return s.size > 1 && !(s.size === 2 && s.has('Latin') && s.has('CJK')); }; // Latin + CJK is normal in Japan/Korea/China
const dec = x => { try { return decodeURIComponent(x); } catch (e) { return x; } };

function inspectUrl(raw) {
  const s = refang(raw), defanged = s !== String(raw).trim();
  const full = /^[a-z][a-z0-9+.-]*:(\/\/|(?!\d))/i.test(s) ? s : 'http://' + s; // "host:8080" is a port, not a scheme
  let u; try { u = new URL(full); } catch (e) { return null; }
  const rawHost = ((full.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i) || [])[1] || '').replace(/^.*@/, '').replace(/:\d*$/, '').toLowerCase();
  const host = u.hostname, uni = /[^\x00-\x7f]/.test(rawHost) ? rawHost : host, f = [];
  if (defanged) f.push(F('info', 'Input was defanged', 'Refanged it to inspect. Keep the defanged form when you paste it into chats or tickets.'));
  if (/^(javascript|data|vbscript):$/i.test(u.protocol)) f.push(F('bad', `${u.protocol} link`, 'This runs code or embeds content instead of opening a website. Don\'t click it.'));
  if (u.username || u.password) f.push(F('bad', 'Userinfo trick: the part before @ is not the site', `The browser opens ${host}, not "${dec(u.username)}". Attackers put a trusted name before the @ to fool readers.`));
  if (S.isIP(host) || host.startsWith('[')) f.push(S.isIP(host) && rawHost !== host
    ? F('bad', 'Disguised IP address', `"${rawHost}" is an IP address written in hex, octal or as one big number; the browser reads it as ${host}. That only serves to hide where a link goes.`)
    : F('warn', 'Host is a bare IP address', 'Real sites use names. A link straight to an IP often points at a throwaway server.'));
  if (host.split('.').some(l => l.startsWith('xn--'))) {
    const mix = uni.split('.').filter(mixed), look = lookalike(uni);
    if (mix.length) f.push(F('bad', 'Mixed alphabets in one name', `"${mix.join('.')}" mixes ${[...scriptsOf(mix[0])].join(' and ')} letters, a classic homograph trick.`));
    if (look !== uni && !/[^\x00-\x7f]/.test(look)) f.push(F('bad', `Looks like ${look}`, `Letters from another alphabet imitate Latin ones. The real name is ${host}.`));
    // Limit: xn-- input is not decoded back to Unicode; add an RFC 3492 decoder if people paste punycode a lot
    else if (!mix.length) f.push(uni === host
      ? F('info', 'Punycode name (IDN)', 'Browsers may display this name in another alphabet. Paste the displayed form to check it for lookalike letters.')
      : F('info', 'Internationalized name (IDN)', `Shown as ${uni}, looked up in DNS as ${host}. Normal for non-English names; make sure it is the site you expect.`));
  }
  if (/(^|\.)(com|net|org|gov|edu|io|co)(\.|$)/.test(host.split('.').slice(0, -2).join('.')))
    f.push(F('warn', 'A domain name hides inside the subdomain', `The site belongs to whoever owns the end of ${host}, not to the familiar name at the start.`));
  if (u.protocol === 'http:' && full === s) f.push(F('info', 'Not encrypted (http)', 'Anyone on the network path can read or change this page. Prefer https.'));
  if (u.port) f.push(F('info', `Unusual port ${u.port}`, 'Websites normally use 443 (https) or 80 (http). A custom port is common on test or throwaway servers.'));
  return { href: u.href, scheme: u.protocol.replace(':', ''), host, hostUnicode: uni, port: u.port, user: dec(u.username),
    path: dec(u.pathname), query: [...u.searchParams], fragment: dec(u.hash.slice(1)), defanged: defang(u.href), findings: f };
}

Object.assign(S.lib, { parseCsp, gradeCsp, parseHttpHeaders, gradeHeaders, inspectUrl, defang, refang });

/* ---------- shared report UI ---------- */
const SEV = { bad: ['b-danger', 'x', 'fail'], warn: ['b-warn', 'alert', 'warn'], info: ['b-info', 'info', 'note'], ok: ['b-safe', 'check', 'pass'] };
const ORDER = ['bad', 'warn', 'info', 'ok'];
const list = fs => `<ul class="signals">${[...fs].sort((a, b) => ORDER.indexOf(a.sev) - ORDER.indexOf(b.sev)).map(x =>
  `<li>${badge(...SEV[x.sev])}<div><b>${esc(x.title)}</b>${x.fix ? `<div class="mut">${esc(x.fix)}</div>` : ''}</div></li>`).join('')}</ul>`;
const WORD = { safe: ['check', 'strong'], warn: ['alert', 'partial'], danger: ['x', 'weak'] };
function gradeCard(r, what) {
  const cls = 'AB'.includes(r.grade) ? 'safe' : 'CD'.includes(r.grade) ? 'warn' : 'danger';
  const n = r.findings.filter(x => x.sev === 'bad' || x.sev === 'warn').length;
  return `<div class="card verdict ${cls} full"><h2 class="big">${svg(WORD[cls][0])}Grade ${r.grade}: ${WORD[cls][1]}</h2>
    <div class="sub">Score ${r.score}/100. ${n ? `${n} thing${n > 1 ? 's' : ''} to fix, worst first below.` : 'Nothing important to fix.'} The grade is Sentinel's own scale, not an industry standard; the findings are what matter.</div></div>`;
}
function headerReport(h, extra = '') {
  const r = gradeHeaders(h);
  const rows = Object.entries(h).flatMap(([k, v]) => [].concat(v).map(x => `<tr><td class="mono">${esc(k)}</td><td class="mono" style="word-break:break-word">${esc(x)}</td></tr>`)).join('');
  return gradeCard(r, 'Security headers') + extra +
    `<div class="card full"><h2>Findings</h2>${list(r.findings)}</div>` +
    (r.csp ? `<div class="card full"><h2>${t('CSP')} findings (grade ${r.csp.grade})</h2>${list(r.csp.findings)}</div>` : '') +
    `<div class="card full"><h2>Headers received</h2><div class="table-wrap"><table><thead><tr><th>Name</th><th>Value</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
}
// A textarea that re-renders on every keystroke, plus the header Run example that fills it.
function pasteTool(mount, { label, placeholder, help, sample, narrate, render }) {
  mount.innerHTML = `<div class="field"><label for="pin">${esc(label)}</label><textarea id="pin" rows="8" spellcheck="false" autocomplete="off" placeholder="${esc(placeholder)}"></textarea></div>
    <p class="mut" style="font-size:var(--text-sm)">${help}</p><div id="out" class="grid"></div>`;
  const ta = $('#pin', mount), out = $('#out', mount), run = () => { out.innerHTML = render(ta.value.trim()); };
  ta.addEventListener('input', run); run();
  demoButton(() => { ta.value = sample; run(); S.toast(narrate); });
}
const emptyCard = (title, body) => `<div class="card full empty"><b>${title}</b>${body}</div>`;
const errNote = (title, body) => `<div class="note warn">${svg('alert')}<div><b>${title}</b> ${body}</div></div>`;

/* ---------- demo data (real captures) ---------- */
// Captured 2026-10-14 with: curl -sI -A 'Mozilla/5.0' https://www.facebook.com
// Kept: default-src, script-src, style-src, object-src and the two flag directives, verbatim. Other fetch directives dropped for length.
const FB_CSP = "default-src blob: 'self' https://*.fbsbx.com *.facebook.com *.fbcdn.net *.facebook.net *.whatsapp.com *.whatsapp.net;script-src *.facebook.com *.fbcdn.net *.facebook.net 127.0.0.1:* 'nonce-uuielhVM' blob: 'self' connect.facebook.net 'unsafe-eval' https://accounts.google.com https://*.google-analytics.com *.google.com;style-src *.fbcdn.net data: *.facebook.com 'unsafe-inline' https://accounts.google.com https://fonts.googleapis.com;object-src data: blob: 'self' https://*.fbsbx.com *.facebook.com *.fbcdn.net;block-all-mixed-content;upgrade-insecure-requests;";
// Captured 2026-10-14 with: curl -sI https://github.com
// Shortened: the host lists in connect-src, img-src and media-src (first hosts kept), the _gh_sess cookie value, and the vary list. Everything graded is verbatim.
const GH_HEADERS = `HTTP/2 200
date: Tue, 13 Oct 2026 20:12:14 GMT
content-type: text/html; charset=utf-8
cache-control: max-age=0, private, must-revalidate
strict-transport-security: max-age=31536000; includeSubdomains; preload
x-frame-options: deny
x-content-type-options: nosniff
x-xss-protection: 0
referrer-policy: origin-when-cross-origin, strict-origin-when-cross-origin
content-security-policy: default-src 'none'; base-uri 'self'; child-src github.githubassets.com github.com/assets-cdn/worker/ github.com/assets/ gist.github.com/assets-cdn/worker/; connect-src 'self' uploads.github.com www.githubstatus.com collector.github.com raw.githubusercontent.com api.github.com; font-src github.githubassets.com; form-action 'self' github.com gist.github.com copilot-workspace.githubnext.com objects-origin.githubusercontent.com; frame-ancestors 'none'; frame-src viewscreen.githubusercontent.com notebooks.githubusercontent.com www.youtube-nocookie.com; img-src 'self' data: blob: github.githubassets.com media.githubusercontent.com camo.githubusercontent.com; manifest-src 'self'; media-src github.com user-images.githubusercontent.com; script-src github.githubassets.com 'sha256-tSjmyPUky1KbRZ0fw9VUil3wFEbeM82rtbJDygGJAXw='; style-src 'unsafe-inline' github.githubassets.com; upgrade-insecure-requests; worker-src github.githubassets.com github.com/assets-cdn/worker/ github.com/assets/ gist.github.com/assets-cdn/worker/
server: github.com
accept-ranges: bytes
set-cookie: _gh_sess=SHORTENED; path=/; HttpOnly; secure; SameSite=Lax
set-cookie: _octo=GH1.1.1103185224.1791922336; expires=Wed, 13 Oct 2027 20:12:16 GMT; domain=.github.com; path=/; secure; SameSite=Lax
set-cookie: logged_in=no; expires=Wed, 13 Oct 2027 20:12:16 GMT; domain=.github.com; path=/; HttpOnly; secure; SameSite=Lax
x-github-request-id: 8C06:2B9D5C:4F3EC:58E9D:6ACE90A0`;

/* ---------- tools ---------- */
S.register({ id: 'csp', name: 'CSP Evaluator', group: 'Web & email', icon: 'e-code', tag: 'local',
  tile: 'Paste a Content-Security-Policy and get an A–F grade with a fix for every weak spot.',
  blurb: 'Paste a Content-Security-Policy to see which attacks it blocks, which it lets through, and how to tighten it. Runs entirely in your browser.',
  why: `A ${t('CSP')} is a site's last line of defence against ${t('XSS (cross-site scripting)', 'cross-site scripting')}: even if an attacker injects a script, the browser refuses to run it unless the policy allows it. Most policies are too loose to help, usually because of 'unsafe-inline' or wide wildcards. Strong ones use ${t('CSP nonce', 'nonces')} or ${t('hash', 'hashes')} instead of host lists.`,
  render(mount) {
    pasteTool(mount, { label: 'Content-Security-Policy', placeholder: "default-src 'self'; script-src 'self' 'nonce-…'; object-src 'none'; base-uri 'none'",
      help: 'Find it in DevTools → Network → the page → Response Headers, or with <code>curl -sI https://example.com</code>. Nothing you paste leaves this page.',
      sample: FB_CSP, narrate: 'Grading the real CSP facebook.com sent on 2026-10-14: a nonce, but also unsafe-eval and no base-uri.',
      render: v => {
        if (!v) return emptyCard('Paste a policy to grade it', 'Directives are separated by semicolons, like <code>script-src \'self\'; object-src \'none\'</code>.');
        const r = gradeCsp(v), names = Object.keys(r.directives);
        if (!names.some(k => KNOWN.has(k))) return errNote('This doesn\'t look like a CSP.', 'No known directive (like default-src or script-src) was found. Paste the header value, not the page HTML.');
        return gradeCard(r, 'CSP') + `<div class="card full"><h2>Findings</h2>${list(r.findings)}</div>
          <div class="card full"><h2>Directives</h2><div class="table-wrap"><table><thead><tr><th>Directive</th><th>Allowed sources</th></tr></thead><tbody>${
          names.map(k => `<tr><td class="mono">${esc(k)}</td><td class="mono">${esc(r.directives[k].join(' ')) || '<span class="mut">(no value)</span>'}</td></tr>`).join('')}</tbody></table></div></div>`;
      } });
  } });

S.register({ id: 'headers', name: 'Header Analyzer', group: 'Web & email', icon: 'e-list', tag: 'local',
  tile: 'Paste a site\'s raw response headers and grade HSTS, CSP, framing, cookies and more, A to F.',
  blurb: 'Paste raw HTTP response headers to grade the security features a site switches on. Runs entirely in your browser.',
  why: `Before any page content, a server sends ${t('response headers')}. A handful of them turn on browser defences: ${t('HSTS')} forces HTTPS, a ${t('CSP')} blocks injected scripts, X-Frame-Options stops ${t('clickjacking')}, nosniff stops ${t('MIME sniffing')}, and ${t('cookie flags')} protect your login session. Missing headers don't prove a site is vulnerable, but each one removes a safety net.`,
  render(mount) {
    pasteTool(mount, { label: 'Raw response headers', placeholder: 'HTTP/2 200\nstrict-transport-security: max-age=31536000\ncontent-security-policy: …',
      help: 'Get them with <code>curl -sI https://example.com</code>, or DevTools → Network → the page → Response Headers (Raw). Companion running? <a href="#/secheaders">Security Headers (live)</a> fetches them for you.',
      sample: GH_HEADERS, narrate: 'Grading the headers github.com sent on 2026-10-14, captured with curl -sI.',
      render: v => {
        if (!v) return emptyCard('Paste headers to grade them', 'One per line, like <code>x-frame-options: DENY</code>. Nothing you paste leaves this page.');
        const { headers } = parseHttpHeaders(v);
        return Object.keys(headers).length ? headerReport(headers)
          : errNote('No headers found.', 'Each line should look like <code>name: value</code>. Paste the response headers, not the page HTML.');
      } });
  } });

S.register({ id: 'secheaders', name: 'Security Headers (live)', group: 'Native', icon: 'e-server', tag: 'native',
  tile: 'Fetch any URL through the local companion and grade its security headers, following redirects.',
  blurb: 'Type a URL; the companion fetches it from your machine, follows redirects, and grades the security headers of the final response.',
  why: `Browsers won't let one site read another site's ${t('response headers')}, so this fetch runs in the Sentinel companion on your own computer. It follows each redirect, then grades the final response exactly like the Header Analyzer: ${t('HSTS')}, ${t('CSP')}, framing, ${t('cookie flags')} and more.`,
  render(mount) {
    if (!S.companion()) {
      mount.innerHTML = `<div class="grid">${emptyCard('This tool needs the Sentinel companion',
        `<p>Browsers block reading another site's headers. The companion is a small helper that runs on your own computer and fetches pages for Sentinel.</p>
        <p style="margin-top:8px">From the Sentinel folder, run <code>node companion/server.mjs</code>, then open <a href="http://127.0.0.1:7777">http://127.0.0.1:7777</a>.</p>
        <p style="margin-top:8px">No companion? Paste headers into the <a href="#/headers">Header Analyzer</a> instead.</p>`)}</div>`;
      return;
    }
    searchTool(mount, { label: 'URL', placeholder: 'https://example.com', cta: 'Fetch and grade', wide: true, examples: ['github.com', 'example.com'],
      demo: { input: 'github.com', narrate: 'The companion fetches github.com from your machine and grades the headers it sends back.' },
      run: async (v, out) => {
        const url = /^https?:\/\//i.test(v) ? v : 'https://' + v;
        try { new URL(url); } catch (e) { throw new Error(`"${v}" isn't a valid URL. Try something like https://example.com`); }
        loading(out); S.say('The companion is fetching ' + url + '…');
        let r;
        try { r = await S.native('/api/http', { url }); }
        catch (e) { out.innerHTML = ''; throw new Error(`Couldn't fetch ${url}: ${e.message}. Check the address, and that the companion is still running.`); }
        if (!r || !r.headers || typeof r.headers !== 'object') { out.innerHTML = ''; throw new Error('The companion answered without headers. Restart it and try again.'); }
        const hops = r.chain || [];
        out.innerHTML = headerReport(r.headers, `<div class="card full"><h2>Fetch</h2><div class="kv">
          <div class="k">Final URL</div><div class="v">${esc(r.finalUrl || url)}</div>
          <div class="k">Status</div><div class="v">${esc(r.status)}</div>
          <div class="k">Time</div><div class="v">${esc(r.ms)} ms</div>
          ${hops.length > 1 ? `<div class="k">Redirects</div><div class="v">${hops.map(c => `${esc(c.status)} ${esc(c.url)}`).join('<br>')}</div>` : ''}</div></div>`);
        S.say('');
      } });
  } });

S.register({ id: 'urlinspect', name: 'URL Inspector', group: 'Web & email', icon: 'e-link', tag: 'local',
  tile: 'Take a suspicious link apart: real host, lookalike letters, @ tricks, hidden IPs, defang and refang.',
  blurb: 'Paste a link to see where it really goes, spot lookalike letters and disguised addresses, and get a defanged copy that is safe to share. Runs entirely in your browser.',
  why: `Phishing links lean on how people read URLs: a trusted name before an @, a real brand inside a longer domain, or ${t('homoglyph', 'lookalike letters')} from another alphabet (an ${t('IDN')} that travels as ${t('punycode')}). This splits the link the way a browser does, decodes ${t('percent-encoding')}, and gives you a ${t('defang', 'defanged')} copy for reports.`,
  render(mount) {
    searchTool(mount, { label: 'URL', placeholder: 'hxxps://example[.]com/login', cta: 'Inspect', wide: true,
      examples: [APPLE, 'http://paypal.com@0xcb007107/verify', 'hxxps://login.microsoftonline.com.example[.]net/?next=%2Fmail'],
      demo: { input: APPLE, narrate: 'Inspecting the 2017 proof-of-concept domain that spells "apple" in Cyrillic letters.' },
      run: async (v, out) => { // async: core only catches errors from a returned promise
        const r = inspectUrl(v);
        if (!r) { out.innerHTML = ''; throw new Error(`"${v}" couldn't be parsed as a URL. Check for spaces or a missing domain, like example.com/path.`); }
        const bad = r.findings.some(x => x.sev === 'bad'), warn = r.findings.some(x => x.sev === 'warn');
        const cls = bad ? 'danger' : warn ? 'warn' : 'safe';
        const kv = (k, v) => v ? `<div class="k">${k}</div><div class="v">${v}</div>` : '';
        out.innerHTML = `<div class="card verdict ${cls} full">
            <h2 class="big">${svg(bad ? 'x' : warn ? 'alert' : 'check')}${bad ? 'Deceptive link' : warn ? 'Suspicious signs' : 'No red flags in the link itself'}</h2>
            <div class="sub">${r.host ? `This link opens <b class="mono">${esc(r.hostUnicode)}</b>${r.hostUnicode !== r.host ? ` (<span class="mono">${esc(r.host)}</span>)` : ''}.` : 'This link has no website address.'} ${bad || warn ? 'Details below, worst first.' : 'This checks how the link is built, not whether the site itself is safe.'}</div></div>
          <div class="card full"><h2>Findings</h2>${r.findings.length ? list(r.findings) : '<span class="mut">Nothing unusual in how this link is built.</span>'}</div>
          <div class="card full"><h2>Parts</h2><div class="kv">${kv('Scheme', esc(r.scheme))}${kv('Username', esc(r.user))}
            ${kv('Host (as shown)', esc(r.hostUnicode))}${r.hostUnicode !== r.host ? kv(`Host (${t('punycode')})`, esc(r.host)) : ''}${kv('Port', esc(r.port))}
            ${kv('Path (decoded)', esc(r.path))}${kv('Fragment', esc(r.fragment))}${kv(t('defang', 'Defanged'), esc(r.defanged))}</div></div>
          ${r.query.length ? `<div class="card full"><h2>Query parameters (decoded)</h2><div class="table-wrap"><table><thead><tr><th>Name</th><th>Value</th></tr></thead><tbody>${
            r.query.map(([k, x]) => `<tr><td class="mono">${esc(k)}</td><td class="mono" style="word-break:break-word">${esc(x)}</td></tr>`).join('')}</tbody></table></div></div>` : ''}`;
      } });
  } });
})();
