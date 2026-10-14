/* Sentinel tool file: Vulnerabilities (CVE Lookup, Package Vulns). Pure helpers go on Sentinel.lib for tests. */
(() => {
const S = Sentinel, api = S.api, esc = S.esc, svg = S.svg, t = S.t, $ = S.helpers.$;
const { searchTool, loading, demoButton, badge } = S.ui;

S.addIcons({
  'b-bug': 'M8 6a4 4 0 0 1 8 0M6 9h12v5a6 6 0 0 1-12 0zM12 9v11M3 13h3M18 13h3M4 7l2 2M20 7l-2 2M4 19l2-2M20 19l-2-2',
  'b-package': 'M7.5 4.27l9 5.15M21 8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16zM3.3 7L12 12l8.7-5M12 22V12',
});
S.addTerms({
  'CVE': 'Common Vulnerabilities and Exposures. A public ID like CVE-2021-44228 that names one specific security flaw, so everyone talks about the same bug.',
  'NVD': 'The US National Vulnerability Database. It adds severity scores, weakness types and reference links to every CVE.',
  'CVSS': 'Common Vulnerability Scoring System. Rates how bad a flaw is from 0 to 10, based on how it can be attacked and what an attacker gains.',
  'CVSS vector': 'The short code behind a CVSS score, like AV:N/AC:L. Each part records one fact about the attack, such as whether it works over the network.',
  'EPSS': 'Exploit Prediction Scoring System. FIRST\'s daily estimate of the chance a flaw will be exploited in the next 30 days.',
  'KEV': 'CISA\'s Known Exploited Vulnerabilities catalog: flaws attackers are confirmed to be using. US federal agencies must patch them by a deadline.',
  'CWE': 'Common Weakness Enumeration. Names the kind of mistake behind a flaw, such as CWE-79 (cross-site scripting).',
  'exploit': 'Code or steps that take advantage of a vulnerability to make a system do something it should not.',
  'ransomware': 'Malware that encrypts a victim\'s files and demands payment for the key.',
  'dependency': 'Someone else\'s code your project pulls in, such as an npm or PyPI package. Its vulnerabilities become yours.',
  'OSV': 'Open Source Vulnerabilities (osv.dev): a free database that merges security advisories for open-source packages from many sources.',
  'advisory': 'A published notice about a vulnerability: what is affected, how bad it is, and which version fixes it.',
});

/* ---------- pure logic (tested in tests/vuln.test.mjs) ---------- */
const cveId = s => { const m = String(s || '').trim().toUpperCase().match(/^CVE-\d{4}-\d{4,}$/); return m ? m[0] : null; };
const cvssRating = n => n == null ? 'Unscored' : n === 0 ? 'None' : n < 4 ? 'Low' : n < 7 ? 'Medium' : n < 9 ? 'High' : 'Critical';
const cia = (name, h, l) => [name, { H: ['High', h], L: ['Low', l], N: ['None', 'Not affected.'] }, 'H'];
// metric → [name, {value: [label, plain-English meaning]}, the value that most favours the attacker]
const CVSS_M = {
  AV: ['Attack vector', { N: ['Network', 'Can be attacked remotely, across the internet.'], A: ['Adjacent', 'Attacker must be on the same local network, such as the same Wi-Fi.'],
    L: ['Local', 'Attacker must already be able to run code or log in on the machine.'], P: ['Physical', 'Attacker must physically touch the device.'] }, 'N'],
  AC: ['Attack complexity', { L: ['Low', 'No special conditions: the attack works reliably.'], H: ['High', 'Only works under conditions the attacker cannot fully control.'] }, 'L'],
  AT: ['Attack requirements', { N: ['None', 'No special setup on the target is needed.'], P: ['Present', 'Only works when certain conditions exist on the target.'] }, 'N'],
  PR: ['Privileges required', { N: ['None', 'No account needed: anyone can try it.'], L: ['Low', 'Needs an ordinary user account.'], H: ['High', 'Needs an admin account.'] }, 'N'],
  UI: ['User interaction', { N: ['None', 'No victim has to do anything.'], R: ['Required', 'A user must do something, such as open a file or click a link.'],
    P: ['Passive', 'A user only has to do something normal, such as view a page.'], A: ['Active', 'A user must deliberately do something, such as click through a warning.'] }, 'N'],
  S: ['Scope', { U: ['Unchanged', 'Damage stays inside the vulnerable component.'], C: ['Changed', 'Damage can spread beyond it, for example from an app into its host.'] }, 'C'],
  C: cia('Confidentiality', 'Attacker can read all protected data.', 'Attacker can read some data.'),
  I: cia('Integrity', 'Attacker can change any data.', 'Attacker can change some data.'),
  A: cia('Availability', 'Attacker can shut the service down.', 'Attacker can slow it down or partly disrupt it.'),
  VC: cia('Confidentiality (this system)', 'Attacker can read all its data.', 'Attacker can read some of its data.'),
  VI: cia('Integrity (this system)', 'Attacker can change any of its data.', 'Attacker can change some of its data.'),
  VA: cia('Availability (this system)', 'Attacker can shut it down.', 'Attacker can partly disrupt it.'),
  SC: cia('Confidentiality (other systems)', 'Data on connected systems is fully exposed.', 'Some data on connected systems is exposed.'),
  SI: cia('Integrity (other systems)', 'Connected systems can be fully altered.', 'Connected systems can be partly altered.'),
  SA: cia('Availability (other systems)', 'Connected systems can be shut down.', 'Connected systems can be partly disrupted.'),
  E: ['Exploit maturity', { A: ['Attacked', 'Attacks have been reported.'], P: ['Proof of concept', 'Public exploit code exists.'], U: ['Unreported', 'No public exploit is known.'] }, 'A'],
};
// CVSS 3.x / 4.0 vector → [{key, name, value, meaning, bad}]; other formats (CVSS v2) → []
function cvssExplain(vec) {
  if (!/^CVSS:[34]\.\d\//.test(vec || '')) return [];
  return vec.split('/').slice(1).map(p => p.split(':')).filter(([k, v]) => CVSS_M[k] && CVSS_M[k][1][v])
    .map(([k, v]) => ({ key: k, name: CVSS_M[k][0], value: CVSS_M[k][1][v][0], meaning: CVSS_M[k][1][v][1], bad: CVSS_M[k][2] === v }));
}
// severity × exploited → verdict. kev: KEV entry or null; epss: probability 0..1 or null.
function cveVerdict({ score, kev, epss, rejected }) {
  const r = cvssRating(score), pct = epss == null ? '' : +(epss * 100).toFixed(1) + '%';
  const likely = epss != null && epss >= 0.1;
  if (rejected) return { cls: '', icon: 'info', big: 'Rejected CVE', sub: 'This ID was withdrawn, usually as a duplicate or not a real vulnerability. There is nothing to patch.' };
  if (kev) return { cls: 'danger', icon: 'x', big: `${r}, exploited in the wild`,
    sub: `CISA has confirmed attackers are using this flaw. Patch or mitigate now${kev.dueDate ? `; US federal agencies had to fix it by ${kev.dueDate}` : ''}.` };
  if (score >= 7 && likely) return { cls: 'danger', icon: 'alert', big: `${r}, likely to be exploited`, sub: `EPSS gives it a ${pct} chance of being exploited in the next 30 days. Patch soon.` };
  if (score >= 7) return { cls: 'warn', icon: 'alert', big: `${r}, no known exploitation`, sub: 'Serious if exploited, but there is no confirmed attack activity. Patch on a short schedule.' };
  if (likely) return { cls: 'warn', icon: 'alert', big: `${r}, but likely to be exploited`, sub: `EPSS gives it a ${pct} chance of being exploited in the next 30 days. Patch soon.` };
  if (score == null) return { cls: '', icon: 'info', big: 'Not scored yet', sub: 'NVD has not scored this CVE yet. Read the description and references, and check again in a few days.' };
  if (score >= 4) return { cls: '', icon: 'info', big: `${r}, no known exploitation`, sub: 'Moderate impact and no known attacks. Patch on your normal update schedule.' };
  return { cls: 'safe', icon: 'check', big: `${r}, no known exploitation`, sub: 'Limited impact and no known attacks. Fix it in routine updates.' };
}
// OSV vulns → one row per real flaw (GHSA, PYSEC and GO records of the same bug are merged), worst first
const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
function osvSummarize(vulns, name) {
  const sevOf = v => { const s = String((v.database_specific || {}).severity || '').toUpperCase(); return s === 'MODERATE' ? 'MEDIUM' : SEV_RANK[s] ? s : ''; };
  const rich = v => (sevOf(v) ? 2 : 0) + ((v.severity || []).length ? 1 : 0);
  const seen = new Set(), out = [];
  for (const v of [...(vulns || [])].sort((a, b) => rich(b) - rich(a))) {
    const ids = [v.id, ...(v.aliases || [])];
    if (ids.some(x => seen.has(x))) continue;
    ids.forEach(x => seen.add(x));
    const mine = (v.affected || []).filter(a => a.package && a.package.name.toLowerCase() === String(name).toLowerCase());
    const fixed = [...new Set((mine.length ? mine : v.affected || []).flatMap(a => (a.ranges || []).filter(r => r.type !== 'GIT')
      .flatMap(r => (r.events || []).map(e => e.fixed).filter(Boolean))))];
    out.push({ id: v.id, severity: sevOf(v), summary: v.summary || String(v.details || '').split('\n')[0].slice(0, 200),
      cves: ids.filter(cveId), fixed });
  }
  return out.sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0));
}
Object.assign(S.lib, { cveId, cvssRating, cvssExplain, cveVerdict, osvSummarize });

const sevBadge = (sev, txt) => { const u = String(sev).toUpperCase(); txt = txt || (sev ? u[0] + u.slice(1).toLowerCase() : 'Unrated');
  return u === 'CRITICAL' || u === 'HIGH' ? badge('b-danger', 'alert', txt) : u === 'MEDIUM' ? badge('b-warn', 'alert', txt)
    : u === 'LOW' ? badge('b-info', 'info', txt) : u === 'NONE' ? badge('b-safe', 'check', txt) : badge('b-mut', 'info', txt); };
const httpUrl = u => /^https?:\/\//i.test(u || '');
const day = s => String(s || '').slice(0, 10);

/* ---------- sources ---------- */
// NVD API 2.0, verified 2026-10-14: GET services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228 → 200, access-control-allow-origin: *
// {totalResults, vulnerabilities:[{cve:{id, published, lastModified, vulnStatus, descriptions:[{lang, value}],
//   metrics:{cvssMetricV31|V30|V40:[{source, type:'Primary'|'Secondary', cvssData:{version, vectorString, baseScore}}], cvssMetricV2},
//   weaknesses:[{description:[{value:'CWE-917'}]}], references:[{url, tags}], cisaExploitAdd?, cisaActionDue?, cisaRequiredAction?}}]}
// Unknown ID → 200 with totalResults 0. Malformed ID → 404. Keyless limit: 5 requests per rolling 30 s.
const nvdCache = new Map(); let nvdHits = [];
async function nvdGet(id) {
  if (nvdCache.has(id)) return nvdCache.get(id);
  const now = Date.now(); nvdHits = nvdHits.filter(x => now - x < 30000);
  // Limit: per-tab guard only; a shared IP can still hit NVD's limit (the 403 branch below covers it)
  if (nvdHits.length >= 5) throw new Error(`NVD allows 5 lookups per 30 seconds without an API key. Try again in ${Math.ceil((30000 - (now - nvdHits[0])) / 1000)} seconds.`);
  nvdHits.push(now);
  const d = await api.jget(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`).catch(e => {
    throw new Error(/HTTP (403|429|503)/.test(e.message) ? 'NVD is rate-limiting or busy right now. Wait 30 seconds and try again.' : `Could not reach NVD (${e.message}). Check your connection and try again.`);
  });
  const c = ((d.vulnerabilities || [])[0] || {}).cve || null;
  if (c) nvdCache.set(id, c);
  return c;
}
// FIRST EPSS, verified 2026-10-14: GET api.first.org/data/v1/epss?cve=CVE-2021-44228 → 200, access-control-allow-origin: *
// {data:[{cve, epss:'0.999990000', percentile:'1.000000000', date:'2026-10-13'}]}; unknown CVE → data: []
const epssGet = id => api.jget(`https://api.first.org/data/v1/epss?cve=${id}`).then(d => d.data[0] || null);
// CISA KEV GitHub mirror, verified 2026-10-14: → 200, access-control-allow-origin: *, ~1.8 MB, fetched once per session
// {catalogVersion, count, vulnerabilities:[{cveID, vulnerabilityName, dateAdded, dueDate, requiredAction, knownRansomwareCampaignUse:'Known'|'Unknown'}]}
const KEV_URL = 'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json';
let kevP;
const kevGet = () => kevP ||= api.jget(KEV_URL).then(d => new Map(d.vulnerabilities.map(v => [v.cveID, v]))).catch(e => { kevP = null; throw e; });
// OSV.dev, verified 2026-10-14: POST api.osv.dev/v1/query {package:{name, ecosystem}, version} → 200; CORS preflight 200,
// access-control-allow-origin echoes the page origin. → {vulns:[{id, summary, details, aliases, severity:[{type, score:vector}],
// database_specific:{severity:'LOW|MODERATE|HIGH|CRITICAL'} (GitHub advisories only), affected:[{package:{name}, ranges:[{type, events:[{fixed}]}]}]}]}
// No advisories (or unknown package) → {}. Unknown ecosystem → 400.
const osvQuery = (ecosystem, name, version) => api.jget('https://api.osv.dev/v1/query', { method: 'POST',
  headers: { 'content-type': 'application/json' }, body: JSON.stringify({ package: { name, ecosystem }, version }) });

/* ---------- CVE Lookup ---------- */
S.register({ id: 'cve', name: 'CVE Lookup', group: 'Threat intel', icon: 'b-bug', tag: 'live',
  tile: 'Look up any CVE: severity, what its CVSS score means, the chance it gets exploited, and whether attackers already use it.',
  blurb: 'Enter a CVE ID to see how severe it is, how likely it is to be exploited, and whether attackers are already using it.',
  why: `Every publicly known security flaw gets a ${t('CVE')} ID. Severity alone doesn't tell you what to patch first, so this combines three sources: ${t('NVD')}'s ${t('CVSS')} score (how bad), FIRST's ${t('EPSS')} (how likely to be exploited soon) and CISA's ${t('KEV')} list (already exploited). That combination is how security teams decide what to fix this week.`,
  render(mount) {
    searchTool(mount, { label: 'CVE ID', placeholder: 'CVE-2021-44228', cta: 'Look up', examples: ['CVE-2021-44228', 'CVE-2014-0160', 'CVE-2020-28500'],
      demo: { input: 'CVE-2021-44228', narrate: 'Looking up Log4Shell: its NVD severity, its EPSS exploit odds, and the CISA known-exploited list.' },
      run: runCVE });
  } });

async function runCVE(input, out) {
  out.innerHTML = '';
  const id = cveId(input);
  if (!id) throw new Error('That is not a CVE ID. Use the format CVE-YYYY-NNNN, for example CVE-2021-44228.');
  loading(out); S.say('Asking NVD, FIRST EPSS and the CISA KEV catalog…');
  const [nvd, ep, kv] = await Promise.allSettled([nvdGet(id), epssGet(id), kevGet()]);
  if (nvd.status === 'rejected') { out.innerHTML = ''; throw nvd.reason; }
  const c = nvd.value;
  if (!c) { out.innerHTML = ''; throw new Error(`NVD has no record of ${id}. Check the number; brand-new CVEs can take a few days to appear.`); }

  const m = c.metrics || {};
  const pick = ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV40', 'cvssMetricV2'].map(k => (m[k] || []).find(x => x.type === 'Primary') || (m[k] || [])[0]).find(Boolean);
  const cd = pick ? pick.cvssData : {}, score = pick ? cd.baseScore : null;
  const e = ep.status === 'fulfilled' ? ep.value : null, epss = e ? +e.epss : null;
  const kev = (kv.status === 'fulfilled' && kv.value.get(id)) || (c.cisaExploitAdd
    ? { dateAdded: c.cisaExploitAdd, dueDate: c.cisaActionDue, requiredAction: c.cisaRequiredAction, vulnerabilityName: c.cisaVulnerabilityName } : null);
  const v = cveVerdict({ score, kev, epss, rejected: c.vulnStatus === 'Rejected' });
  const rows = cvssExplain(cd.vectorString);
  const desc = ((c.descriptions || []).find(d => d.lang === 'en') || {}).value || 'No description.';
  const cwes = [...new Set((c.weaknesses || []).flatMap(w => (w.description || []).map(d => d.value)))].filter(x => /^CWE-\d+$/.test(x));
  const refs = (c.references || []).filter(r => httpUrl(r.url));
  const missing = [ep.status === 'rejected' && `${t('EPSS')} (${esc(ep.reason.message)})`,
    kv.status === 'rejected' && `the CISA ${t('KEV')} catalog (${esc(kv.reason.message)})${kev ? '; KEV status below comes from NVD\'s copy' : ''}`].filter(Boolean);
  const epssHtml = ep.status === 'rejected' ? badge('b-mut', 'info', 'unavailable')
    : !e ? '<span class="mut">No EPSS score yet</span>'
    : `${badge(epss >= 0.1 ? 'b-danger' : epss >= 0.01 ? 'b-warn' : 'b-safe', epss >= 0.1 ? 'alert' : 'info', +(epss * 100).toFixed(2) + '%')}
       <span class="mut">chance of exploitation in the next 30 days; riskier than ${esc(+Math.min(99.9, e.percentile * 100).toFixed(1))}% of all scored CVEs</span>
       <div class="meter" role="img" aria-label="EPSS ${esc(+(epss * 100).toFixed(2))} percent"><i style="width:${Math.max(1, epss * 100)}%;background:var(${epss >= 0.1 ? '--bad' : epss >= 0.01 ? '--warn' : '--ok'})"></i></div>`;
  const kevHtml = kev
    ? `${badge('b-danger', 'x', 'Listed')} <span class="mut">added ${esc(kev.dateAdded)}, federal due date ${esc(kev.dueDate)}</span>${kev.knownRansomwareCampaignUse === 'Known' ? ` ${badge('b-danger', 'alert', 'used by ransomware')}` : ''}`
    : kv.status === 'rejected' ? badge('b-mut', 'info', 'unavailable') : badge('b-safe', 'check', 'Not listed');

  out.innerHTML = `
    <div class="card verdict ${v.cls} full"><h2 class="big">${svg(v.icon)}${esc(v.big)}</h2><div class="sub">${esc(v.sub)}</div></div>
    ${missing.length ? `<div class="note warn" style="grid-column:1/-1;margin:0">${svg('alert')}<div><b>Partial result.</b> Could not reach ${missing.join(' or ')}. Everything else is complete; run the lookup again later to fill the gap.</div></div>` : ''}
    <div class="card"><h2>${esc(c.id)}</h2><div class="kv">
      <div class="k">${t('CVSS')} ${esc(cd.version || '')}</div><div class="v">${score != null ? sevBadge(cvssRating(score), `${cvssRating(score)} ${score.toFixed(1)}`) : '<span class="mut">not scored yet</span>'}</div>
      <div class="k">${t('CVSS vector', 'Vector')}</div><div class="v">${esc(cd.vectorString || '—')}</div>
      <div class="k">${t('EPSS')}</div><div class="v">${epssHtml}</div>
      <div class="k">${t('KEV', 'CISA KEV')}</div><div class="v">${kevHtml}</div>
      <div class="k">Weakness</div><div class="v">${cwes.length ? cwes.map(w => `<a href="https://cwe.mitre.org/data/definitions/${w.slice(4)}.html" target="_blank" rel="noopener">${esc(w)}</a>`).join(', ') : '<span class="mut">not classified</span>'} <span class="mut">(${t('CWE')})</span></div>
      <div class="k">Status</div><div class="v">${esc(c.vulnStatus || '—')}</div>
      <div class="k">Published</div><div class="v">${esc(day(c.published))}</div>
      <div class="k">Last modified</div><div class="v">${esc(day(c.lastModified))}</div>
    </div></div>
    <div class="card"><h2>What the ${t('CVSS vector', 'vector')} says</h2>${rows.length
      ? `<ul class="signals">${rows.map(r => `<li>${svg(r.bad ? 'alert' : 'info')}<span><b>${esc(r.name)}: ${esc(r.value)}</b>${r.bad ? ' <span class="mut">(worst case)</span>' : ''}<br><span class="mut">${esc(r.meaning)}</span></span></li>`).join('')}</ul>`
      : `<p class="mut">${cd.vectorString ? 'This is an old CVSS v2 vector; only v3 and v4 vectors are explained here.' : 'No CVSS vector yet.'}</p>`}</div>
    <div class="card full"><h2>Description${kev && kev.vulnerabilityName ? ` · ${esc(kev.vulnerabilityName)}` : ''}</h2><p>${esc(desc)}</p>
      ${kev && kev.requiredAction ? `<p class="mut" style="margin-top:8px"><b>CISA required action:</b> ${esc(kev.requiredAction)}</p>` : ''}</div>
    <div class="card full"><h2>References <span class="mut">(${refs.length ? `${Math.min(refs.length, 12)} of ${refs.length}` : 'none'})</span></h2>${refs.length
      ? `<ul class="signals">${refs.slice(0, 12).map(r => `<li>${svg('file')}<span><a href="${esc(r.url)}" target="_blank" rel="noopener">${esc(r.url.replace(/^https?:\/\/([^/?#]+).*$/i, '$1'))}</a> <span class="mut">${esc((r.tags || []).join(', '))}</span></span></li>`).join('')}</ul>
         <p style="margin-top:8px"><a href="https://nvd.nist.gov/vuln/detail/${esc(c.id)}" target="_blank" rel="noopener">Full record on NVD</a></p>`
      : '<p class="mut">NVD lists no references.</p>'}</div>`;
  S.say('');
}

/* ---------- Package Vulns ---------- */
const ECOS = ['npm', 'PyPI', 'Go', 'Maven', 'crates.io', 'RubyGems'];
const PKG_EX = [['npm', 'lodash', '4.17.15'], ['PyPI', 'django', '3.2.0'], ['Maven', 'org.apache.logging.log4j:log4j-core', '2.14.1']];
S.register({ id: 'pkgvulns', name: 'Package Vulns', group: 'Threat intel', icon: 'b-package', tag: 'live',
  tile: 'Check one version of an npm, PyPI, Go, Maven, crates.io or RubyGems package for known vulnerabilities.',
  blurb: 'Pick a package and the exact version you use, and see every published security advisory that affects it, with the version that fixes each one.',
  why: `Most of the code in a modern app is someone else's: every ${t('dependency')} you install brings its bugs with it. ${t('OSV')} merges ${t('advisory', 'advisories')} from GitHub, PyPI, the Go team, RustSec and others into one free database. Checking the exact version you run tells you whether you are exposed and which upgrade fixes it.`,
  render(mount) {
    mount.innerHTML = `
      <form id="pvf" class="bar" style="align-items:flex-end" novalidate>
        <div class="field"><label for="pv-eco">Ecosystem</label><select id="pv-eco">${ECOS.map(x => `<option>${x}</option>`).join('')}</select></div>
        <div class="field" style="flex:2"><label for="pv-name">Package name</label><input id="pv-name" type="text" placeholder="lodash" autocomplete="off" spellcheck="false" autocapitalize="off"></div>
        <div class="field" style="flex:1"><label for="pv-ver">Version</label><input id="pv-ver" type="text" placeholder="4.17.15" autocomplete="off" spellcheck="false" autocapitalize="off"></div>
        <div class="field"><button class="btn secondary" id="pv-go">Check</button></div>
      </form>
      <p class="try">Try:${PKG_EX.map((x, i) => `<button type="button" data-i="${i}">${esc(`${x[0]} ${x[1]}@${x[2]}`)}</button>`).join('')}</p>
      <div id="status" role="status" aria-live="polite"></div>
      <div id="out" class="grid"></div>`;
    const eco = $('#pv-eco', mount), nm = $('#pv-name', mount), ver = $('#pv-ver', mount), go = $('#pv-go', mount), out = $('#out', mount);
    const fill = x => { [eco.value, nm.value, ver.value] = x; };
    const run = () => runPkg(eco.value, nm.value.trim(), ver.value.trim(), out, go, nm, ver);
    $('#pvf', mount).onsubmit = e => { e.preventDefault(); run(); };
    mount.querySelectorAll('.try button').forEach(b => b.onclick = () => { fill(PKG_EX[b.dataset.i]); run(); });
    demoButton(() => { fill(PKG_EX[0]); S.toast('Checking lodash 4.17.15 against every advisory in OSV.dev and listing the version that fixes each one.'); run(); });
  } });

async function runPkg(ecosystem, name, version, out, go, nm, ver) {
  if (!name) { S.say('Enter a package name, for example lodash.', true); nm.focus(); return; }
  if (!/\d/.test(version)) { S.say('Enter the exact version you use, for example 4.17.15. Your lock file (package-lock.json, poetry.lock, go.sum) lists it.', true); ver.focus(); return; }
  go.setAttribute('aria-busy', 'true'); loading(out); S.say(`Querying OSV.dev for ${name} ${version}…`);
  try {
    const d = await osvQuery(ecosystem, name, version);
    const rows = osvSummarize(d.vulns, name);
    const worst = rows.filter(r => SEV_RANK[r.severity] >= 3).length;
    const cls = !rows.length ? 'safe' : worst ? 'danger' : 'warn';
    const big = !rows.length ? 'No known vulnerabilities' : `${rows.length} known ${rows.length === 1 ? 'vulnerability' : 'vulnerabilities'}`;
    const sub = !rows.length ? `OSV.dev has no advisories for ${name} ${version}. It only knows publicly reported flaws, and it also returns nothing for a misspelled package, so double-check the name.`
      : worst ? `${worst} rated high or critical. Upgrade to a version listed under "Fixed in" for each one.`
      : 'None rated high or critical. Upgrade to a version listed under "Fixed in" when convenient.';
    out.innerHTML = `
      <div class="card verdict ${cls} full"><h2 class="big">${svg(cls === 'safe' ? 'check' : cls === 'warn' ? 'alert' : 'x')}${esc(big)}</h2><div class="sub">${esc(sub)}</div></div>
      ${rows.length ? `<div class="card full"><h2>${t('advisory', 'Advisories')} for <span class="mono">${esc(ecosystem)} ${esc(name)} ${esc(version)}</span></h2>
        <div class="table-wrap"><table><thead><tr><th>Advisory</th><th>Severity</th><th>Summary</th><th>Fixed in</th></tr></thead><tbody>${rows.map(r => `<tr>
          <td class="mono"><a href="https://osv.dev/vulnerability/${encodeURIComponent(r.id)}" target="_blank" rel="noopener">${esc(r.id)}</a>${r.cves.map(c => `<br><a href="#/cve?q=${c}">${c}</a>`).join('')}</td>
          <td>${sevBadge(r.severity)}</td>
          <td>${esc(r.summary)}</td>
          <td class="mono">${r.fixed.length ? esc(r.fixed.join(', ')) : '<span class="mut">no fix yet</span>'}</td></tr>`).join('')}</tbody></table></div>
        ${rows.some(r => !r.severity) ? `<div class="note">${svg('info')}<div><b>Unrated</b> means the source database (the Go one, for example) does not publish a severity. Open the linked ${t('CVE')} for NVD's score.</div></div>` : ''}</div>` : ''}`;
    S.record({ tool: 'pkgvulns', input: `${ecosystem} ${name}@${version}`, cls, title: big });
    S.say('');
  } catch (e) {
    out.innerHTML = '';
    S.say(/HTTP 400/.test(e.message) ? 'OSV.dev rejected the query. Check the ecosystem and the package name spelling.' : `Could not reach OSV.dev (${e.message}). Check your connection and try again.`, true);
  } finally { go.removeAttribute('aria-busy'); }
}

})();
