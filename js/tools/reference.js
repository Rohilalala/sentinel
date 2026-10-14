/* Sentinel tool file: Reference (MITRE ATT&CK, OWASP Top 10). Pure helpers go on Sentinel.lib for tests. */
(() => {
const S = Sentinel, esc = S.esc, svg = S.svg, t = S.t, $ = S.helpers.$;
const { loading, demoButton } = S.ui;

S.addIcons({
  'b-matrix': 'M3 3h18v18H3zM3 9h18M3 15h18M9 3v18M15 3v18',
  'b-list': 'M9 6h12M9 12h12M9 18h12M4 6h.01M4 12h.01M4 18h.01',
});
S.addTerms({
  'MITRE ATT&CK': 'A free knowledge base of the techniques real attackers use, grouped by goal. Defenders use it to check what they can detect.',
  'tactic': 'In ATT&CK, the attacker\'s goal at one stage, such as Initial Access or Exfiltration. It is the "why".',
  'technique': 'In ATT&CK, one specific way to reach a tactic\'s goal, such as Phishing for Initial Access. It is the "how". IDs look like T1566.',
  'sub-technique': 'A more specific variant of a technique, with an ID like T1566.001 (Spearphishing Attachment).',
  'OWASP': 'The Open Worldwide Application Security Project: a nonprofit community that publishes free web security guides and tools.',
  'access control': 'The rules that decide what each user is allowed to see and do once they are logged in.',
  'SSRF': 'Server-side request forgery: tricking a server into fetching a URL the attacker chooses, often an internal one the attacker could not reach directly.',
  'injection': 'When user input is treated as code or a command, so an attacker can run their own database query, shell command or script.',
  'XSS': 'Cross-site scripting: an attacker gets their JavaScript to run in other people\'s browsers on a site those people trust.',
  'MFA': 'Multi-factor authentication: a second proof besides the password, such as a code from an app or a hardware security key.',
  'supply chain attack': 'An attack on the libraries, tools or update channels you depend on, so the harm arrives inside something you trust.',
  'fail open': 'When an error makes a security check let everyone through instead of blocking them.',
});

/* ---------- MITRE ATT&CK ---------- */
// Search: every word must appear in the ID, name or description. Exact ID/name first, then prefix, then name hits, then the rest.
function attackFilter(list, q, tactic) {
  const words = String(q || '').toLowerCase().split(/\s+/).filter(Boolean), qq = words.join(' ');
  const rank = x => { const n = x.name.toLowerCase(), id = x.id.toLowerCase();
    return n === qq || id === qq ? 3 : n.startsWith(qq) || id.startsWith(qq) ? 2 : words.some(w => (id + ' ' + n).includes(w)) ? 1 : 0; };
  return list.filter(x => (!tactic || x.tactics.includes(tactic)) && words.every(w => (x.id + ' ' + x.name + ' ' + x.desc).toLowerCase().includes(w)))
    .sort((a, b) => rank(b) - rank(a));
}
S.lib.attackFilter = attackFilter;

let attackP; // data/attack.json is built by scripts/build-attack.mjs; same-origin, cached by the service worker
const loadAttack = () => attackP ||= fetch('data/attack.json').then(r => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
  .catch(e => { attackP = null; throw e; });
const SHOW = 60;

S.register({ id: 'attack', name: 'MITRE ATT&CK', group: 'Reference', icon: 'b-matrix', tag: '',
  tile: 'Search MITRE ATT&CK: the techniques real attackers use, grouped by goal, with links to the full entries.',
  blurb: 'Search the 700+ attacker techniques in MITRE ATT&CK Enterprise, or browse them by the attacker\'s goal.',
  why: `${t('MITRE ATT&CK')} is a public catalog of what real attackers do, built from incident reports. Each ${t('tactic')} is a goal (get in, stay in, steal data) and each ${t('technique')} is one way to reach it, sometimes split into ${t('sub-technique', 'sub-techniques')}. Defenders map their detections to it; students use it to learn the attacker's playbook from the defender's side.`,
  render(mount) {
    mount.innerHTML = `
      <div class="bar" style="align-items:flex-end">
        <div class="field" style="flex:2"><label for="ak-q">Search techniques</label><input id="ak-q" type="search" placeholder="phishing, T1059, credential" autocomplete="off" spellcheck="false" autocapitalize="off"></div>
        <div class="field"><label for="ak-t">Tactic</label><select id="ak-t"><option value="">All tactics</option></select></div>
      </div>
      <div id="status" role="status" aria-live="polite"></div>
      <div id="ak-detail"></div>
      <div id="ak-list" style="margin-top:16px"></div>
      <div class="note" id="ak-notice">${svg('info')}<div>Data: MITRE ATT&amp;CK® Enterprise. <a href="https://attack.mitre.org/resources/legal-and-branding/terms-of-use/" target="_blank" rel="noopener">Terms of use</a></div></div>`;
    const q = $('#ak-q', mount), tac = $('#ak-t', mount), list = $('#ak-list', mount), detail = $('#ak-detail', mount);
    let data;
    const tName = s => (data.tactics.find(x => x.short === s) || { name: s }).name;
    // sub-techniques carry their parent's name, as MITRE writes them: "Phishing: Spearphishing Link"
    const full = x => x.sub ? `${(data.techniques.find(y => y.id === x.id.split('.')[0]) || {}).name}: ${x.name}` : x.name;
    const link = x => `<a href="${esc(x.url)}" data-id="${esc(x.id)}">${esc(x.id)} ${esc(full(x))}</a>`;
    const draw = () => {
      const hits = attackFilter(data.techniques, q.value, tac.value);
      list.innerHTML = !hits.length
        ? `<div class="list"><div class="empty"><b>No technique matches “${esc(q.value.trim())}”${tac.value ? ` in ${esc(tName(tac.value))}` : ''}</b>Try a shorter or broader word, or set Tactic to All tactics.</div></div>`
        : `<p class="mut" style="margin-bottom:8px">${hits.length > SHOW ? `Showing ${SHOW} of ${hits.length} techniques. Search or pick a tactic to narrow the list.` : `${hits.length} technique${hits.length === 1 ? '' : 's'}`}</p>
           <div class="list">${hits.slice(0, SHOW).map(x => `<button type="button" class="list-row noicon" data-id="${esc(x.id)}"><span class="name">${esc(full(x))}</span><span class="desc">${esc(x.desc)}</span><span class="mono mut">${esc(x.id)}</span>${svg('right')}</button>`).join('')}</div>`;
    };
    const open = id => {
      const x = data.techniques.find(y => y.id === id); if (!x) return;
      const parent = x.sub && data.techniques.find(y => y.id === x.id.split('.')[0]);
      const subs = data.techniques.filter(y => y.sub && y.id.startsWith(x.id + '.'));
      detail.innerHTML = `<div class="card" tabindex="-1" style="margin-top:16px">
        <h3 style="font-size:var(--text-xl)">${esc(full(x))} <span class="mono mut" style="font-size:var(--text-md);font-weight:500">${esc(x.id)}</span></h3>
        <p style="margin-top:8px;color:var(--fg-2)">${esc(x.desc)}</p>
        <div class="kv" style="margin-top:14px">
          <div class="k">Type</div><div class="v">${x.sub ? t('sub-technique') : t('technique')}</div>
          <div class="k">${t('tactic', x.tactics.length > 1 ? 'Tactics' : 'Tactic')}</div><div class="v">${x.tactics.map(s => esc(tName(s))).join(', ')}</div>
          ${parent ? `<div class="k">Parent technique</div><div class="v">${link(parent)}</div>` : ''}
          ${subs.length ? `<div class="k">Sub-techniques</div><div class="v">${subs.map(link).join('<br>')}</div>` : ''}
        </div>
        <p style="margin-top:14px"><a href="${esc(x.url)}" target="_blank" rel="noopener">Read the full entry on attack.mitre.org</a></p></div>`;
      detail.firstChild.focus({ preventScroll: true }); detail.scrollIntoView({ block: 'nearest' });
    };
    mount.addEventListener('click', e => {
      const el = e.target.closest('[data-id]'); if (!el || !data) return;
      e.preventDefault(); open(el.dataset.id);
    });
    q.addEventListener('input', () => data && draw());
    tac.addEventListener('change', () => data && draw());
    loading(list); S.say('Loading the ATT&CK dataset…');
    const ready = loadAttack().then(d => {
      data = d;
      tac.insertAdjacentHTML('beforeend', d.tactics.map(x => `<option value="${esc(x.short)}">${esc(x.name)}</option>`).join(''));
      $('#ak-notice', mount).lastChild.innerHTML = `ATT&amp;CK ${esc(d.version)}, ${d.techniques.length} techniques. ${esc(d.notice)} ${esc(d.license)} <a href="https://attack.mitre.org/resources/legal-and-branding/terms-of-use/" target="_blank" rel="noopener">Terms of use</a>`;
      draw(); S.say('');
    });
    demoButton(() => ready.then(() => {
      q.value = 'phishing'; tac.value = ''; draw(); open('T1566');
      S.toast('Searching ATT&CK for "phishing" and opening T1566, the technique and its sub-techniques.');
    }, () => {}));
    ready.catch(e => {
      list.innerHTML = `<div class="note warn">${svg('alert')}<div><b>Could not load the ATT&amp;CK dataset (data/attack.json): ${esc(e.message)}.</b> Reload the page. If you opened index.html straight from disk, serve the folder instead: <span class="mono">python3 -m http.server 8777</span>.</div></div>`;
      S.say('');
    });
  } });

/* ---------- OWASP Top 10:2025 (own words; OWASP's text is not copied) ---------- */
const OWASP = [
  ['A01', 'Broken_Access_Control', 'Broken Access Control',
    `The app lets people see data or do things they shouldn't, because it doesn't check ${t('access control', 'permissions')} on every request. Changing an ID in a URL, calling an admin API as a normal user, and making the server fetch an internal address (${t('SSRF')}, now part of this category) all count.`,
    'You view your invoice at /invoices/1001, change it to /invoices/1002, and see a stranger\'s invoice. The server checked that you were logged in, not that invoice 1002 is yours.',
    'Log in as two test users. Replay one user\'s requests with the other\'s session and change the IDs. Anything that works across accounts is a finding.', ''],
  ['A02', 'Security_Misconfiguration', 'Security Misconfiguration',
    'The software is fine but set up unsafely: default passwords, debug mode left on, detailed error pages, public cloud storage, missing security headers, or features enabled that nobody uses.',
    'A team deploys with debug mode still on. Every error page now shows stack traces, file paths and configuration values to anyone who triggers one.',
    'Compare live settings with a hardening checklist. Look for default logins, directory listings, verbose errors and missing headers. Files a site publishes, like robots.txt, often point at forgotten areas.', 'sitefiles'],
  ['A03', 'Software_Supply_Chain_Failures', 'Software Supply Chain Failures',
    `Your app is only as safe as everything it is built from: libraries, their own ${t('dependency', 'dependencies')}, build servers and update channels. This covers both outdated components with known flaws and a ${t('supply chain attack')} that tampers with something you trust.`,
    'A project still ships an old logging library with a public remote-code-execution bug. Or an attacker publishes a poisoned update of a popular package, and thousands of builds pull it in automatically.',
    'Keep a list of every dependency and version, and check it against advisory databases. Pin versions, review new packages before adding them, and lock down who can publish your packages and run your builds.', 'pkgvulns'],
  ['A04', 'Cryptographic_Failures', 'Cryptographic Failures',
    `Sensitive data is exposed because encryption is missing, weak or misused: plain HTTP, outdated algorithms, keys written into the code, or passwords stored with a fast ${t('hash')} instead of a slow password hash.`,
    'A site stores passwords as unsalted MD5. After its database leaks, attackers recover most of them within hours using precomputed tables.',
    'List everywhere sensitive data is stored or sent. Check for HTTPS everywhere, modern TLS, keys kept out of source code, and passwords hashed with bcrypt, scrypt or Argon2.', 'toolkit'],
  ['A05', 'Injection', 'Injection',
    `Untrusted input is mixed into a command, query or page and runs as code. SQL ${t('injection')}, operating-system command injection and ${t('XSS')} are the classic forms.`,
    'A login form builds the query "SELECT * FROM users WHERE name = \'" + input + "\'". Typing  \' OR \'1\'=\'1  as the name makes the condition always true.',
    'Trace every place user input reaches a database, shell, template or page. Safe code uses parameterized queries and output encoding instead of gluing strings together. Typing quotes and angle brackets into fields shows where it doesn\'t.', ''],
  ['A06', 'Insecure_Design', 'Insecure Design',
    'The flaw is in the plan, not the code: a feature designed without asking how it could be abused. Perfect code cannot fix a design that never considered an attacker.',
    'A password reset asks a security question whose answer is on the user\'s public social profile. The code works exactly as designed; the design is the bug.',
    'Before building a feature, ask "how would I abuse this?" at each step. Look for missing rate limits, trust in checks done only in the browser, and business rules a user can skip.', ''],
  ['A07', 'Authentication_Failures', 'Authentication Failures',
    `Weak spots in how the app confirms who you are: allowing weak or leaked passwords, no limit on login guesses, no ${t('MFA')}, or sessions that never expire.`,
    'A site has no limit on login attempts. An attacker tries a list of leaked email and password pairs and gets into every account that reused its password.',
    'Try many wrong passwords and see whether anything slows you down. Check that known-leaked passwords are refused, MFA is offered, and logging out really ends the session.', 'pwned'],
  ['A08', 'Software_or_Data_Integrity_Failures', 'Software or Data Integrity Failures',
    'The app trusts code or data without checking it wasn\'t tampered with: unsigned updates, scripts loaded from other servers with no integrity check, or rebuilding objects from data an attacker controls (insecure deserialization).',
    'An app stores user settings as a serialized object in a cookie and loads it back as-is. An attacker edits the cookie so the server builds an object that runs a command.',
    'Check that updates and downloads are signed and verified, that third-party scripts carry an integrity hash (SRI), and that the app never deserializes untrusted data into live objects.', ''],
  ['A09', 'Security_Logging_and_Alerting_Failures', 'Security Logging and Alerting Failures',
    'Attacks happen and nobody notices: important events aren\'t logged, logs aren\'t watched, or nothing alerts a person. Breaches then go undetected for months.',
    'An attacker tries 50,000 passwords against the admin login over a weekend. The server records nothing useful, so no one knows until customer data shows up online.',
    'Ask: if someone attacked us right now, which log would show it, and who would be told? Then test it by triggering failed logins and confirming an alert reaches a person.', ''],
  ['A10', 'Mishandling_of_Exceptional_Conditions', 'Mishandling of Exceptional Conditions',
    `The app doesn't plan for things going wrong: errors, timeouts, missing data, odd states. Poor handling can crash the service, leak details in error messages, or ${t('fail open')} so a broken check lets everyone through.`,
    'A payment check times out. The code treats any error as "not declined" and ships the order without payment.',
    'In a test setup, feed the app strange input and cut its network or database mid-request. Every error path should deny by default, log the problem, and show users a generic message.', ''],
];

S.register({ id: 'owasp', name: 'OWASP Top 10', group: 'Reference', icon: 'b-list', tag: '',
  tile: 'The ten most critical web application risks (2025 edition), each explained with a beginner example and how to spot it.',
  blurb: 'The 2025 list of the ten most critical web application security risks, in plain words, with an example and a way to spot each one.',
  why: `The ${t('OWASP')} Top 10 is the best-known shortlist of web application risks, rebuilt every few years from contributed testing data and a community survey. Developers use it as a checklist and many courses and audits refer to it. This is the 2025 edition, the current one.`,
  render(mount) {
    mount.innerHTML = `
      <div class="field"><label for="ow-q">Filter risks</label><div class="bar"><input id="ow-q" type="search" placeholder="password, injection, logging" autocomplete="off" spellcheck="false" autocapitalize="off"></div></div>
      <div class="grid" id="ow-list">${OWASP.map(([code, slug, name, what, ex, spot, tool]) => `
        <div class="card full" data-code="${code}"><h2>${code}:2025</h2>
          <h3 style="font-size:var(--text-lg)">${esc(name)}</h3>
          <p style="margin-top:6px;color:var(--fg-2)">${what}</p>
          <ul class="signals" style="margin-top:8px">
            <li>${svg('b-bug')}<span><b>Beginner example.</b> ${esc(ex)}</span></li>
            <li>${svg('search')}<span><b>How to spot it.</b> ${esc(spot)}</span></li>
          </ul>
          <p style="margin-top:8px"><a href="https://owasp.org/Top10/2025/${code}_2025-${slug}/" target="_blank" rel="noopener">OWASP's ${code} page</a>${tool && S.modules[tool] ? ` · <a href="#/${tool}">Try it in Sentinel: ${esc(S.modules[tool].name)}</a>` : ''}</p>
        </div>`).join('')}
        <div class="card full" id="ow-empty" hidden><div class="empty"><b>No risk matches “<span id="ow-term"></span>”</b>Try a broader word, or clear the filter to see all ten.</div></div>
      </div>
      <div class="note">${svg('info')}<div>Category names and ranking: OWASP Top 10:2025 by the OWASP Top 10 team (<a href="https://owasp.org/Top10/2025/" target="_blank" rel="noopener">owasp.org/Top10</a>), CC BY 3.0. The explanations here are Sentinel's own words.</div></div>`;
    const q = $('#ow-q', mount), cards = [...mount.querySelectorAll('[data-code]')];
    const filter = () => {
      const words = q.value.toLowerCase().split(/\s+/).filter(Boolean);
      let shown = 0;
      cards.forEach(c => { c.hidden = !words.every(w => c.textContent.toLowerCase().includes(w)); shown += !c.hidden; });
      $('#ow-term', mount).textContent = q.value.trim(); $('#ow-empty', mount).hidden = shown > 0;
    };
    q.addEventListener('input', filter);
    demoButton(() => { q.value = 'injection'; filter(); S.toast('Filtering the Top 10 for "injection": the risk behind SQL injection and cross-site scripting.'); });
  } });

})();
