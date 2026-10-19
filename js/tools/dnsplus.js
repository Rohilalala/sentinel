/* Sentinel tool file: DNS+ (Reverse DNS, DNS Propagation, Email Auth Deep Check). Pure helpers go on Sentinel.lib for tests. */
(() => {
const S = Sentinel, api = S.api, esc = S.esc, svg = S.svg, t = S.t;
const { searchTool, loading, badge } = S.ui;

S.addIcons({ /* Lucide (ISC): rotate-ccw, network, mail-check */
  'a-reverse': 'M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8M3 3v5h5',
  'a-network': 'M17 16h4a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1h-4a1 1 0 0 1-1-1v-4a1 1 0 0 1 1-1zM3 16h4a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1H3a1 1 0 0 1-1-1v-4a1 1 0 0 1 1-1zM10 2h4a1 1 0 0 1 1 1v4a1 1 0 0 1-1 1h-4a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1zM5 16v-3a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v3M12 12V8',
  'a-mailcheck': 'M22 13V6a2 2 0 0 0-2-2H4a2 2 0 0 0-2 2v12c0 1.1.9 2 2 2h8M22 7l-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7M16 19l2 2 4-4',
});
S.addTerms({
  'PTR record': 'The reverse of an A record: it maps an IP address back to a name. It lives under the special in-addr.arpa domain.',
  'forward-confirmed reverse DNS': 'The PTR name resolves back to the same IP. Only the IP owner can set the PTR and only the domain owner can set the A record, so a match means both agree.',
  'TTL': 'Time to live: how many seconds a resolver may keep a DNS answer in its cache before asking again.',
  'resolver': 'The DNS server that looks names up for you and caches the answers, like Cloudflare 1.1.1.1 or Google 8.8.8.8.',
  'geo-DNS': 'Answering the same name with different IPs depending on who asks, to send each user to a nearby server.',
  'DKIM selector': 'The label that says where a DKIM public key lives: selector._domainkey.domain. Each sending service usually gets its own.',
  'key length': 'The size of a cryptographic key in bits. For RSA, 1024 bits is now weak and 2048 or more is recommended.',
  'MTA-STS': 'Tells other mail servers to deliver to this domain only over encrypted, certificate-checked connections, so an attacker cannot force plaintext.',
  'TLS-RPT': 'TLS Reporting: an address where other mail servers send daily reports about encrypted deliveries to this domain that failed.',
  'BIMI': 'Publishes a brand logo that supporting inboxes show next to mail that passes DMARC. Only works when DMARC is enforced.',
});

/* ---------- pure logic ---------- */
/* "1.2.3.4" -> "4.3.2.1.in-addr.arpa". Limit: IPv4 only; IPv6 needs the nibble-reversed ip6.arpa form. */
const ptrName = ip => ip.split('.').reverse().join('.') + '.in-addr.arpa';
/* TXT data from DoH JSON: Cloudflare quotes and splits long records ("a" "b"), Google returns them joined and unquoted. */
const dohTxt = d => /^"/.test(d) ? (d.match(/"((?:[^"\\]|\\.)*)"/g) || []).map(s => s.slice(1, -1)).join('') : d;
/* Same answer set from two DoH responses: ignores order, case, trailing dots, quoting, TTL and RRSIG (type 46) records. */
const answerKey = r => r.Status + '|' + (r.Answer || []).filter(a => a.type !== 46).map(a => a.type + ' ' + dohTxt(a.data).replace(/\.$/, '').toLowerCase()).sort().join(',');
const sameDnsAnswers = (a, b) => answerKey(a) === answerKey(b);
/* RSA key size from a DKIM p= tag (Base64 SubjectPublicKeyInfo). 0 = empty (revoked) or unreadable.
   Limit: estimated from the DER length rounded to 256 bits; walk the ASN.1 if odd key sizes ever matter. */
function dkimKeyBits(p) {
  try { const n = atob(String(p).replace(/\s+/g, '')).length; return n > 36 ? Math.round((n - 36) * 8 / 256) * 256 : 0; }
  catch (e) { return 0; }
}
/* Grades the whole email-auth stack. x = {spf, dmarc, mtasts, tlsrpt, bimi: record string or null, dkim: [{sel, bits, ed}]}.
   Returns {grade, cls, score, spoofable, parts:[{name, max, pts, cls, word, note}]}. cls per part: ok | warn | bad | mut. */
function gradeEmailAuth(x) {
  const parts = [], add = (name, max, pts, cls, word, note) => parts.push({ name, max, pts, cls, word, note });
  const q = x.spf ? (x.spf.match(/\s([-~?+]?)all\s*$/i) || [])[1] : null;
  if (!x.spf) add('SPF', 25, 0, 'bad', 'missing', 'No SPF record, so receivers cannot tell which servers may send as this domain.');
  else if (q === '-') add('SPF', 25, 25, 'ok', 'strict', 'Ends in -all: mail from servers not on the list should be rejected.');
  else if (q === '~') add('SPF', 25, 20, 'ok', 'soft', 'Ends in ~all (soft fail): unlisted servers are marked suspicious and DMARC decides the rest.');
  else if (/\bredirect=/i.test(x.spf)) add('SPF', 25, 20, 'ok', 'delegated', 'Hands the policy to another domain with redirect=.');
  else add('SPF', 25, 5, 'warn', 'weak', 'Ends in ?all, +all or has no all, so it does not stop anyone sending as this domain.');
  const pol = ((x.dmarc || '').match(/\bp=(\w+)/i) || [])[1];
  const p = (pol || '').toLowerCase();
  if (!x.dmarc) add('DMARC', 35, 0, 'bad', 'missing', 'No DMARC policy, so receivers have no instruction to block mail that fails SPF and DKIM.');
  else if (p === 'reject') add('DMARC', 35, 35, 'ok', 'reject', 'p=reject: receivers are told to refuse mail that fails the checks.');
  else if (p === 'quarantine') add('DMARC', 35, 28, 'ok', 'quarantine', 'p=quarantine: mail that fails the checks goes to spam.');
  else add('DMARC', 35, 8, 'warn', 'monitor only', 'p=none: receivers only report failures, so spoofed mail is still delivered.');
  const strength = k => k.ed ? 4096 : k.bits, keys = x.dkim.filter(k => strength(k) > 0).sort((a, b) => strength(a) - strength(b)), w = keys[0];
  /* max 0 when no selector matched: DKIM may live under a name we did not guess, so it is not graded either way */
  if (!w) add('DKIM', 0, 0, 'mut', x.dkim.length ? 'revoked' : 'not found', (x.dkim.length ? 'Only revoked (empty) keys at the common selectors.' : 'No key at the common selectors.') +
    ' Senders choose their own selector names, so DKIM may still exist under another one.');
  else if (strength(w) < 1024) add('DKIM', 20, 0, 'bad', 'weak', `Selector "${w.sel}" uses a ${w.bits}-bit key, short enough to be cracked. Rotate to 2048 bits.`);
  else if (strength(w) < 2048) add('DKIM', 20, 12, 'warn', '1024-bit', `Selector "${w.sel}" uses a 1024-bit key. Still accepted, but 2048 bits is the recommendation.`);
  else add('DKIM', 20, 20, 'ok', 'strong', `${keys.length} key${keys.length > 1 ? 's' : ''} found, all 2048 bits or stronger.`);
  if (x.mtasts) add('MTA-STS', 10, 10, 'ok', 'on', 'Other mail servers must use encrypted, certificate-checked delivery.');
  else add('MTA-STS', 10, 0, 'mut', 'not set', 'Not published, so an attacker on the network path can downgrade incoming mail to plaintext.');
  if (x.tlsrpt) add('TLS-RPT', 5, 5, 'ok', 'on', 'The domain receives reports when encrypted delivery to it fails.');
  else add('TLS-RPT', 5, 0, 'mut', 'not set', 'Not published, so the owner never hears about failed encrypted deliveries.');
  if (x.bimi) add('BIMI', 5, 5, 'ok', 'on', 'Publishes a logo that supporting inboxes show beside authenticated mail.');
  else add('BIMI', 5, 0, 'mut', 'not set', 'Optional: a brand logo for supporting inboxes. Needs DMARC enforcement first.');
  const max = parts.reduce((s, r) => s + r.max, 0), score = Math.round(100 * parts.reduce((s, r) => s + r.pts, 0) / max);
  const spoofable = !x.spf || !/^(reject|quarantine)$/.test(p);
  let grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'F';
  if (spoofable && grade < 'D') grade = 'D'; /* anyone can send as this domain: no better than D, whatever else is set */
  return { grade, score, spoofable, parts, cls: grade <= 'B' ? 'safe' : grade === 'C' ? 'warn' : 'danger' };
}
Object.assign(S.lib, { ptrName, dohTxt, sameDnsAnswers, dkimKeyBits, gradeEmailAuth });

/* ---------- shared bits ---------- */
const fail = (out, e) => { out.innerHTML = ''; const m = e.message;
  S.say(/fetch|network|load failed/i.test(m) ? 'Could not reach the DNS service. Check your connection (or an ad blocker) and try again.'
    : /^HTTP \d/.test(m) ? m + '. The service may be busy; try again in a minute.'
    : /^No A record/.test(m) ? m + '. Check the spelling, or enter an IP address.' : m, true); };
const verdict = (cls, title, big, sub) => `<div class="card verdict ${cls} full">
  <h2 class="big">${svg(cls === 'safe' ? 'check' : cls === 'warn' ? 'alert' : cls === 'danger' ? 'x' : 'info')}${big}</h2><div class="sub">${sub}</div></div>`;
const toIP = async v => {
  if (v.includes(':')) throw new Error('IPv6 is not supported yet. Enter an IPv4 address like 8.8.8.8, or a domain.');
  return S.isIP(v) ? v : api.resolveA(S.cleanHost(v));
};
const isDomain = d => /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(d);

/* ---------- Reverse DNS ---------- */
S.register({ id: 'rdns', name: 'Reverse DNS', group: 'Recon', icon: 'a-reverse', tag: 'live',
  tile: 'Turn an IP address back into a name, and check that the name points back.',
  blurb: 'Look up the name behind an IP address and check whether it is forward-confirmed.',
  why: `Normal ${t('DNS')} turns a name into an IP. A ${t('PTR record')} goes the other way, and whoever controls the IP block can write any name there, even google.com. So the name only counts when it is ${t('forward-confirmed reverse DNS', 'forward-confirmed')}: it resolves back to the same IP. Mail servers check this, and so do analysts reading logs full of raw IPs.`,
  render(mount) {
    searchTool(mount, { label: 'IPv4 address or domain', placeholder: '8.8.8.8', wide: true, examples: ['8.8.8.8', '1.1.1.1', 'github.com'],
      demo: { input: '8.8.8.8', narrate: 'Reversing 8.8.8.8 into its in-addr.arpa name, reading the PTR, then resolving that name back to compare.' },
      run: runRdns });
  } });
async function runRdns(v, out) {
  loading(out); S.say('Resolving…');
  try {
    const ip = await toIP(v), rev = ptrName(ip);
    S.say('Reading the PTR record…');
    const r = await api.doh(rev, 'PTR');
    const names = (r.Answer || []).filter(a => a.type === 12).map(a => a.data.replace(/\.$/, ''));
    S.say('Checking each name resolves back…');
    const back = await Promise.all(names.map(n => api.doh(n, 'A').then(d => (d.Answer || []).filter(a => a.type === 1).map(a => a.data)).catch(() => [])));
    const ok = names.map((n, i) => back[i].includes(ip)), first = names[ok.indexOf(true)];
    const v1 = !names.length ? verdict('', 'Reverse DNS', 'No PTR record',
        `Nobody has set a reverse name for ${esc(ip)}. That is common for home and cloud addresses, but a mail server without one will see its email rejected.`)
      : first ? verdict('safe', 'Reverse DNS', esc(first), `${esc(ip)} names ${esc(first)}, and that name resolves back to ${esc(ip)}: ${t('forward-confirmed reverse DNS', 'forward-confirmed')}. Both the IP owner and the domain owner agree on it.`)
      : verdict('warn', 'Reverse DNS', 'Name does not point back', `${esc(ip)} claims the name ${esc(names[0])}, but that name does not resolve to ${esc(ip)}. Anyone holding an IP block can write any name in its PTR, so an unconfirmed one proves nothing. Many mail servers reject mail from it.`);
    out.innerHTML = v1 + `
      <div class="card full"><h2>Lookup</h2><div class="kv">
        <div class="k">IP address</div><div class="v">${esc(ip)}</div>
        <div class="k">Reverse name</div><div class="v">${esc(rev)}</div>
        <div class="k">${t('PTR record')}</div><div class="v">${names.length ? names.map(esc).join('<br>') : '<span class="mut">none</span>'}</div>
        ${names.map((n, i) => `<div class="k">${esc(n)} resolves to</div><div class="v">${back[i].length ? back[i].map(esc).join(', ') : '<span class="mut">no A record</span>'} ${ok[i] ? badge('b-safe', 'check', 'matches') : badge('b-warn', 'alert', 'no match')}</div>`).join('')}
        ${r.Answer && r.Answer[0] ? `<div class="k">${t('TTL')}</div><div class="v">${esc(r.Answer[0].TTL)} s</div>` : ''}
      </div><p class="mut" style="margin-top:12px">Next: <a href="#/exposed?q=${encodeURIComponent(ip)}">Exposed Services</a> · <a href="#/blocklist?q=${encodeURIComponent(ip)}">IP Reputation</a></p></div>`;
    S.say('');
  } catch (e) { fail(out, e); }
}

/* ---------- DNS Propagation ---------- */
const TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME'], TN = { 1: 'A', 28: 'AAAA', 15: 'MX', 2: 'NS', 16: 'TXT', 5: 'CNAME' };
const RCODE = { 0: 'OK', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED' };
/* Google DoH JSON, verified 2026-10-14: GET dns.google/resolve?name=&type=&do=1 -> 200, access-control-allow-origin: *.
   {Status, AD, Answer:[{name:'github.com.', type:1, TTL:60, data:'20.207.73.82'}], Comment}. TXT data arrives unquoted and joined;
   with do=1, RRSIG (type 46) records ride along in Answer. Cloudflare's shape is the same, with quoted TXT chunks. */
const RESOLVERS = [['Cloudflare (1.1.1.1)', (n, ty) => api.doh(n, ty, true)],
  ['Google (8.8.8.8)', (n, ty) => api.jget(`https://dns.google/resolve?name=${encodeURIComponent(n)}&type=${ty}&do=1`)]];
S.register({ id: 'propagation', name: 'DNS Propagation', group: 'Recon', icon: 'a-network', tag: 'live',
  tile: 'Ask two public resolvers the same DNS question and see whether they agree.',
  blurb: 'Compare one DNS record across Cloudflare and Google to see if a change has spread.',
  why: `Every ${t('resolver')} caches answers for the record's ${t('TTL')}. After you change a record, resolvers keep serving the old value until their copy expires, which is what "waiting for DNS to propagate" means. Big sites also answer different resolvers differently on purpose (${t('geo-DNS')}), so a difference is not always a problem.`,
  render(mount) {
    const run = async (v, out) => {
      const [name, ty0] = v.split(/\s+/), sel = mount.querySelector('#ptype');
      const ty = TYPES.includes((ty0 || '').toUpperCase()) ? ty0.toUpperCase() : sel ? sel.value : 'A';
      if (sel) sel.value = ty;
      return runProp(S.cleanHost(name), ty, out);
    };
    const { q } = searchTool(mount, { label: 'Domain and record type', placeholder: 'github.com', wide: true, examples: ['github.com', 'google.com', 'github.com MX'],
      demo: { input: 'google.com A', narrate: 'Asking Cloudflare and Google for google.com. Big sites often answer each resolver differently: that is load balancing, not tampering.' }, run });
    q.insertAdjacentHTML('afterend', `<select id="ptype" aria-label="Record type">${TYPES.map(x => `<option>${x}</option>`).join('')}</select>`);
  } });
async function runProp(name, ty, out) {
  if (!isDomain(name)) { S.say('Enter a domain like github.com, optionally followed by a record type.', true); return; }
  loading(out); S.say(`Asking both resolvers for ${name} ${ty}…`);
  try {
    const res = await Promise.all(RESOLVERS.map(([, f]) => f(name, ty)));
    const same = sameDnsAnswers(res[0], res[1]), none = res.every(r => !(r.Answer || []).length), nx = res.every(r => r.Status === 3);
    const v1 = nx ? verdict('', 'Propagation', 'Name does not exist', `Both resolvers say ${esc(name)} does not exist (NXDOMAIN). Check the spelling, or wait if the domain was registered minutes ago.`)
      : same && none ? verdict('', 'Propagation', `No ${ty} record`, `Both resolvers agree ${esc(name)} has no ${ty} record. Try another record type.`)
      : same ? verdict('safe', 'Propagation', 'Consistent', `Cloudflare and Google return the same ${ty} answer for ${esc(name)}. Any recent change has reached both.`)
      : verdict('warn', 'Propagation', 'Answers differ', `The two resolvers disagree. Each one caches answers for the ${t('TTL')}, so after a change some keep the old value until it expires. Big sites also hand different resolvers different IPs on purpose (${t('geo-DNS')}), so this is often normal.`);
    const rows = res.map((r, i) => {
      const ans = (r.Answer || []).filter(a => a.type !== 46);
      return `<tr><td>${esc(RESOLVERS[i][0])}</td><td class="mono">${esc(RCODE[r.Status] || r.Status)}</td>
        <td class="mono">${ans.length ? ans.map(a => (TN[a.type] !== ty ? esc(TN[a.type] || a.type) + ' ' : '') + esc(dohTxt(a.data))).join('<br>') : '<span class="mut">none</span>'}</td>
        <td class="num">${ans.length ? Math.min(...ans.map(a => a.TTL)) + ' s' : '—'}</td>
        <td>${r.AD ? badge('b-safe', 'check', 'validated') : badge('b-mut', 'info', 'unsigned')}</td></tr>`;
    }).join('');
    out.innerHTML = v1 + `<div class="card full"><h2>Per resolver</h2><div class="table-wrap"><table>
      <thead><tr><th>${t('resolver', 'Resolver')}</th><th>Status</th><th>Answers</th><th class="num">${t('TTL')} left</th><th>${t('DNSSEC')}</th></tr></thead><tbody>${rows}</tbody></table></div>
      <p class="mut" style="margin-top:12px">The TTL is the cache time remaining, so it often differs even when the answers match.</p></div>`;
    S.say('');
  } catch (e) { fail(out, e); }
}

/* ---------- Email Auth Deep Check ---------- */
const SELECTORS = ['google', 'selector1', 'selector2', 'k1', 'default', 's1', 's2', 'mail', 'dkim'];
const STACK = [['', /^v=spf1/i], ['_dmarc.', /^v=DMARC1/i], ['_mta-sts.', /^v=STSv1/i], ['_smtp._tls.', /^v=TLSRPTv1/i], ['default._bimi.', /^v=BIMI1/i]];
const PART_BADGE = { ok: ['b-safe', 'check'], warn: ['b-warn', 'alert'], bad: ['b-danger', 'x'], mut: ['b-mut', 'info'] };
S.register({ id: 'emailauth', name: 'Email Auth Deep Check', group: 'Web & email', icon: 'a-mailcheck', tag: 'live',
  tile: 'Grade a domain\'s whole email security stack: SPF, DMARC, DKIM keys, MTA-STS, TLS-RPT and BIMI.',
  blurb: 'Audit every DNS record that protects a domain\'s email, from spoofing rules to encrypted delivery.',
  why: `${t('SPF')} and ${t('DMARC')} decide whether someone can send mail as a domain. ${t('DKIM')} signs each message with a key published under a ${t('DKIM selector')}, and a short ${t('key length')} can be cracked. ${t('MTA-STS')} and ${t('TLS-RPT')} protect mail in transit, and ${t('BIMI')} adds a logo once everything else is enforced. This check reads all of them and grades the stack.`,
  render(mount) {
    searchTool(mount, { label: 'Domain', placeholder: 'cloudflare.com', wide: true, examples: ['cloudflare.com', 'google.com', 'github.com'],
      demo: { input: 'cloudflare.com', narrate: 'Reading 14 DNS records for cloudflare.com: SPF, DMARC, nine common DKIM selectors, MTA-STS, TLS-RPT and BIMI.' },
      run: runEmailAuth });
  } });
async function runEmailAuth(v, out) {
  const d = S.cleanHost(v);
  if (!isDomain(d)) { S.say('Enter a domain like cloudflare.com.', true); return; }
  loading(out); S.say('Reading SPF, DMARC, DKIM, MTA-STS, TLS-RPT and BIMI records…');
  try {
    const names = [...STACK.map(([pre]) => pre + d), ...SELECTORS.map(s => `${s}._domainkey.${d}`)];
    const res = await Promise.all(names.map(n => api.doh(n, 'TXT')));
    if (res[0].Status === 3) throw new Error(`${d} does not exist in DNS. Check the spelling and try again.`);
    const txt = r => (r.Answer || []).filter(a => a.type === 16).map(a => dohTxt(a.data));
    const [spf, dmarc, mtasts, tlsrpt, bimi] = STACK.map(([, re], i) => txt(res[i]).find(s => re.test(s)) || null);
    const dkim = SELECTORS.map((sel, i) => {
      const rec = txt(res[STACK.length + i]).find(s => /(^|;)\s*p=/i.test(s)); if (!rec) return null;
      const ed = /(^|;)\s*k=ed25519/i.test(rec);
      return { sel, rec, ed, bits: ed ? 256 : dkimKeyBits((rec.match(/(?:^|;)\s*p=([^;]*)/i) || [])[1] || '') };
    }).filter(Boolean);
    const g = gradeEmailAuth({ spf, dmarc, mtasts, tlsrpt, bimi, dkim });
    const keyTxt = k => k.ed ? 'Ed25519' : k.bits ? `${k.bits}-bit RSA` : 'empty (revoked)';
    const keyBadge = k => k.ed || k.bits >= 2048 ? badge('b-safe', 'check', 'strong') : !k.bits ? badge('b-mut', 'info', 'revoked') : k.bits >= 1024 ? badge('b-warn', 'alert', 'weak') : badge('b-danger', 'x', 'crackable');
    const raw = [['SPF', spf], ['DMARC', dmarc], ['MTA-STS', mtasts], ['TLS-RPT', tlsrpt], ['BIMI', bimi], ...dkim.map(k => ['DKIM ' + k.sel, k.rec])].filter(r => r[1]);
    out.innerHTML = verdict(g.cls, 'Email security grade', `Grade ${g.grade} · ${g.score}/100`,
        g.spoofable ? `Anyone can send email that appears to come from ${esc(d)}: it lacks an enforced ${t('SPF')} + ${t('DMARC')} pair, so the grade is capped at D. Fix that first.`
          : `Spoofing protection is enforced for ${esc(d)}. The rest of the grade covers ${t('DKIM')} key strength and protection for mail in transit.`) + `
      <div class="card full"><h2>The stack</h2><div class="table-wrap"><table><thead><tr><th>Check</th><th>Result</th><th class="num">Points</th><th>What it means</th></tr></thead><tbody>${
        g.parts.map(p => `<tr><td>${t(p.name)}</td><td>${badge(...PART_BADGE[p.cls], p.word)}</td><td class="num">${p.max ? `${p.pts}/${p.max}` : '—'}</td><td>${esc(p.note)}</td></tr>`).join('')}</tbody></table></div></div>
      <div class="card full"><h2>${t('DKIM selector', 'DKIM selectors')} found</h2>${dkim.length ? `<div class="table-wrap"><table><thead><tr><th>Selector</th><th>${t('key length', 'Key')}</th><th>Strength</th></tr></thead><tbody>${
        dkim.map(k => `<tr><td class="mono">${esc(k.sel)}._domainkey</td><td class="mono">${esc(keyTxt(k))}</td><td>${keyBadge(k)}</td></tr>`).join('')}</tbody></table></div>`
        : '<p class="mut">None of the common selectors answered.</p>'}
        <div class="note">${svg('info')}<div>Checked: ${SELECTORS.map(esc).join(', ')}. Senders choose their own selector names, so a miss here is not proof that DKIM is off.</div></div></div>
      ${raw.length ? `<div class="card full"><h2>Raw records</h2><pre class="out-pre">${raw.map(([k, r]) => esc(k) + '\n  ' + esc(r)).join('\n\n')}</pre></div>` : ''}`;
    S.say('');
  } catch (e) { fail(out, e); }
}

})();
