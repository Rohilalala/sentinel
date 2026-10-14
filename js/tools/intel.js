/* Sentinel tool file: passive threat intel (Exposed Services). Pure helpers go on Sentinel.lib for tests. */
(() => {
const S = Sentinel, api = S.api, esc = S.esc, svg = S.svg, t = S.t;
const { searchTool, loading, badge } = S.ui;

S.addIcons({ /* Lucide (ISC): server */
  'a-server': 'M4 2h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2zM4 14h16a2 2 0 0 1 2 2v4a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2v-4a2 2 0 0 1 2-2zM6 6h.01M6 18h.01',
});
S.addTerms({
  'open port': 'A numbered door on a computer where a program is listening for connections, like 443 for websites or 22 for SSH logins.',
  'Shodan': 'A search engine that constantly scans the whole internet and records which ports are open and what software answers on them.',
  'CPE': 'Common Platform Enumeration: a standard name for a product and version, like cpe:/a:apache:http_server:2.4.7, used to match it to known bugs.',
});

/* Port -> [service, risky when open to the whole internet]. Limit: common ports only; unknown ports show as "unknown". */
const PORTS = { 21: ['FTP file transfer', 1], 22: ['SSH remote login', 0], 23: ['Telnet (unencrypted login)', 1], 25: ['SMTP mail', 0], 53: ['DNS', 0],
  80: ['HTTP web', 0], 110: ['POP3 mail', 0], 123: ['NTP time', 0], 143: ['IMAP mail', 0], 161: ['SNMP device management', 1], 443: ['HTTPS web', 0],
  445: ['SMB Windows file sharing', 1], 993: ['IMAPS mail', 0], 995: ['POP3S mail', 0], 1433: ['Microsoft SQL Server database', 1], 2375: ['Docker API (no auth)', 1],
  3306: ['MySQL database', 1], 3389: ['Remote Desktop', 1], 5432: ['PostgreSQL database', 1], 5900: ['VNC remote screen', 1], 6379: ['Redis database', 1],
  8080: ['HTTP alternate', 0], 8443: ['HTTPS alternate', 0], 9200: ['Elasticsearch database', 1], 11211: ['Memcached', 1], 27017: ['MongoDB database', 1] };
/* InternetDB record -> verdict class plus the reasons. d = null when Shodan has no data. */
function exposureLevel(d) {
  const ports = (d && d.ports) || [], vulns = (d && d.vulns) || [], tags = (d && d.tags) || [];
  const risky = ports.filter(p => (PORTS[p] || [])[1]), flagged = tags.filter(x => /^(compromised|malware|doublepulsar|c2)$/.test(x)), eol = tags.filter(x => /^eol-/.test(x));
  const cls = !ports.length && !vulns.length ? 'safe' : vulns.length || flagged.length ? 'danger' : risky.length || eol.length ? 'warn' : '';
  return { cls, risky, flagged, eol };
}
S.lib.exposureLevel = exposureLevel;

/* Shodan InternetDB, verified 2026-10-14: GET https://internetdb.shodan.io/<ip> -> 200, access-control-allow-origin: *, no key.
   {ip:'45.33.32.156', ports:[22,80,123,31337], hostnames:['scanme.nmap.org'], cpes:['cpe:/a:apache:http_server:2.4.7'],
    tags:['cloud','self-signed'], vulns:['CVE-2021-44224', ...]}. No data -> 404 {"detail":"No information available"}, also with CORS. */
async function internetdb(ip) {
  const r = await fetch(`https://internetdb.shodan.io/${ip}`);
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`Shodan InternetDB answered HTTP ${r.status}. It may be rate-limiting; try again in a minute.`);
  return r.json();
}

S.register({ id: 'exposed', name: 'Exposed Services', group: 'Threat intel', icon: 'a-server', tag: 'live',
  tile: 'See which ports and known vulnerabilities Shodan has already found on an IP, without scanning it.',
  blurb: 'Read Shodan\'s existing scan of an IP: open ports, software versions and known CVEs.',
  why: `${t('Shodan')} scans the entire internet all the time, so attackers rarely need to scan you themselves: they look you up. This tool reads Shodan's free InternetDB, a passive lookup that sends nothing to the target. Each ${t('open port')} is a service someone can talk to, and each ${t('CVE')} matched to the software version (${t('CPE')}) is a publicly known bug.`,
  render(mount) {
    searchTool(mount, { label: 'IPv4 address or domain', placeholder: '45.33.32.156 · scanme.nmap.org', examples: ['scanme.nmap.org', '8.8.8.8', '1.1.1.1'],
      demo: { input: 'scanme.nmap.org', narrate: 'Reading Shodan\'s existing scan of scanme.nmap.org, a host Nmap runs for practice. Nothing is sent to it.' },
      run: runExposed });
  } });

async function runExposed(v, out) {
  loading(out); S.say('Resolving…');
  try {
    if (v.includes(':')) throw new Error('IPv6 is not supported yet. Enter an IPv4 address like 8.8.8.8, or a domain.');
    const ip = S.isIP(v) ? v : await api.resolveA(S.cleanHost(v)).catch(e => { throw new Error(e.message + '. Check the spelling, or enter an IP address.'); });
    S.say('Reading Shodan InternetDB…');
    const d = await internetdb(ip), x = exposureLevel(d);
    const ports = (d && d.ports) || [], vulns = ((d && d.vulns) || []).slice().sort((a, b) => b.localeCompare(a, 'en', { numeric: true }));
    const name = p => (PORTS[p] || ['unknown'])[0], plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;
    const [big, sub] = x.cls === 'safe' ? ['Nothing known', `${t('Shodan')} has no open ports or vulnerabilities on record for ${esc(ip)}. It may expose nothing, or Shodan has not scanned it. This is not proof it is closed.`]
      : x.cls === 'danger' ? [vulns.length ? plural(vulns.length, 'known CVE') : 'Flagged host', (x.flagged.length ? `Shodan tagged this host <b>${x.flagged.map(esc).join(', ')}</b>. ` : '') +
          (vulns.length ? `Shodan's last scan saw software on ${esc(ip)} with publicly known bugs. These matches come from version numbers, and vendors often patch without changing them, so treat each ${t('CVE')} as a lead to verify, not proof.` : '')]
      : x.cls === 'warn' ? [`${plural(ports.length, 'open port')}, ${x.risky.length} risky`, (x.risky.length ? `${x.risky.map(p => esc(name(p))).join(', ')} should not normally face the whole internet: these services are common break-in points. ` : '') +
          (x.eol.length ? 'Shodan saw software that no longer gets security updates.' : '')]
      : [plural(ports.length, 'open port'), `These look like ordinary services for a server. An ${t('open port')} only becomes a problem when the software behind it is outdated or misconfigured.`];
    out.innerHTML = `<div class="card verdict ${x.cls} full"><h2 class="big">${svg({ safe: 'check', warn: 'alert', danger: 'x' }[x.cls] || 'info')}${big}</h2><div class="sub">${sub}</div></div>` + (d ? `
      <div class="card"><h2>${t('open port', 'Open ports')}</h2>${ports.length ? `<div class="table-wrap"><table><thead><tr><th class="num">Port</th><th>Usually</th><th></th></tr></thead><tbody>${
        ports.map(p => `<tr><td class="num">${esc(p)}</td><td>${esc(name(p))}</td><td>${(PORTS[p] || [])[1] ? badge('b-warn', 'alert', 'risky') : ''}</td></tr>`).join('')}</tbody></table></div>` : '<p class="mut">None seen.</p>'}</div>
      <div class="card"><h2>Host</h2><div class="kv">
        <div class="k">IP address</div><div class="v">${esc(ip)}</div>
        <div class="k">Hostnames</div><div class="v">${(d.hostnames || []).length ? d.hostnames.map(esc).join('<br>') : '<span class="mut">none</span>'}</div>
        <div class="k">Tags</div><div class="v">${(d.tags || []).length ? d.tags.map(g => badge(x.flagged.includes(g) ? 'b-danger' : 'b-mut', x.flagged.includes(g) ? 'x' : 'info', g)).join(' ') : '<span class="mut">none</span>'}</div>
        <div class="k">${t('CPE', 'Software')}</div><div class="v">${(d.cpes || []).length ? d.cpes.map(esc).join('<br>') : '<span class="mut">none identified</span>'}</div>
      </div></div>
      ${vulns.length ? `<div class="card full"><h2>Known vulnerabilities (${vulns.length}), newest first</h2>
        <div class="mono" style="display:flex;flex-wrap:wrap;gap:6px 16px">${vulns.map(c => `<a href="#/cve?q=${encodeURIComponent(c)}">${esc(c)}</a>`).join('')}</div>
        <div class="note">${svg('info')}<div>Open any ID in CVE Lookup to see its severity and whether attackers are exploiting it.</div></div></div>` : ''}` : '') + `
      <div class="note" style="grid-column:1/-1;margin:0">${svg('info')}<div><b>Passive lookup.</b> This reads Shodan's most recent scan, which may be days or weeks old. Nothing was sent to ${esc(ip)}.</div></div>`;
    S.say('');
  } catch (e) {
    out.innerHTML = '';
    S.say(/fetch|network|load failed/i.test(e.message) ? 'Could not reach Shodan InternetDB. Check your connection (or an ad blocker) and try again.' : e.message, true);
  }
}

/* Scanner Check (GreyNoise community API) is deliberately not built: verified 2026-10-14, api.greynoise.io/v3/community/<ip>
   sends no access-control-allow-origin header and answers 403 to any request carrying an Origin header, so browsers cannot use it. */

})();
