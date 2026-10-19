// Bundle B: vulnerabilities and reference (js/tools/vuln.js, js/tools/reference.js, scripts/build-attack.mjs).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { S, L } from './_load.mjs';
import { compact, firstSentence } from '../scripts/build-attack.mjs';

test('bundle B tools register with pinned group, tag and a real icon', () => {
  for (const [id, group, tag] of [['cve', 'Threat intel', 'live'], ['pkgvulns', 'Threat intel', 'live'], ['attack', 'Reference', ''], ['owasp', 'Reference', '']]) {
    const m = S.modules[id];
    assert.ok(m && m.tile && m.why, id);
    assert.equal(m.group, group); assert.equal(m.tag, tag);
    assert.notEqual(S.svg(m.icon), S.svg('no-such-icon'), `${id} icon ${m.icon} missing`);
  }
});

test('CVE id + CVSS rating', () => {
  assert.equal(L.cveId(' cve-2021-44228 '), 'CVE-2021-44228');
  assert.equal(L.cveId('CVE-21-1'), null); assert.equal(L.cveId('log4shell'), null);
  assert.equal(L.cvssRating(10), 'Critical'); assert.equal(L.cvssRating(7), 'High'); assert.equal(L.cvssRating(6.9), 'Medium');
  assert.equal(L.cvssRating(0.1), 'Low'); assert.equal(L.cvssRating(0), 'None'); assert.equal(L.cvssRating(null), 'Unscored');
});

test('CVSS vector explainer', () => {
  const r = L.cvssExplain('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H');
  assert.equal(r.length, 8);
  assert.equal(r[0].name, 'Attack vector'); assert.equal(r[0].value, 'Network'); assert.equal(r[0].bad, true);
  assert.equal(r.filter(x => x.bad).length, 8);
  const v4 = L.cvssExplain('CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:A/VC:N/VI:L/VA:L/SC:H/SI:H/SA:H/E:P');
  assert.equal(v4.find(x => x.key === 'PR').value, 'High'); assert.equal(v4.find(x => x.key === 'UI').value, 'Active');
  assert.equal(v4.find(x => x.key === 'E').value, 'Proof of concept');
  assert.equal(L.cvssExplain('AV:N/AC:M/Au:N/C:C/I:C/A:C').length, 0); // CVSS v2: not explained
});

test('CVE verdict: severity x exploited', () => {
  const v = o => L.cveVerdict(o);
  assert.equal(v({ score: 10, kev: { dueDate: '2021-12-24' }, epss: 0.99 }).cls, 'danger');
  assert.match(v({ score: 10, kev: { dueDate: '2021-12-24' }, epss: 0.99 }).sub, /2021-12-24/);
  assert.equal(v({ score: 5, kev: {}, epss: null }).cls, 'danger');         // exploited beats severity
  assert.equal(v({ score: 9.8, kev: null, epss: 0.5 }).cls, 'danger');      // severe and likely
  assert.equal(v({ score: 9.8, kev: null, epss: 0.001 }).cls, 'warn');
  assert.equal(v({ score: 5.3, kev: null, epss: 0.3 }).cls, 'warn');
  assert.equal(v({ score: 5.3, kev: null, epss: 0.001 }).cls, '');
  assert.equal(v({ score: 2.1, kev: null, epss: null }).cls, 'safe');
  assert.equal(v({ score: null, kev: null, epss: null }).big, 'Not scored yet');
  assert.equal(v({ score: null, kev: null, epss: null, rejected: true }).big, 'Rejected CVE');
});

test('OSV summarize: merges aliases, picks fixed versions for the queried package, worst first', () => {
  const vulns = [
    { id: 'PYSEC-1', aliases: ['CVE-2020-1234', 'GHSA-a'], affected: [{ package: { name: 'demo' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '1.2.0' }] }] }] },
    { id: 'GHSA-a', aliases: ['CVE-2020-1234'], summary: 'Bug A', database_specific: { severity: 'MODERATE' }, severity: [{ type: 'CVSS_V3', score: 'x' }],
      affected: [{ package: { name: 'Demo' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.0' }] }, { type: 'GIT', events: [{ fixed: 'abc123' }] }] },
        { package: { name: 'demo-extra' }, ranges: [{ type: 'SEMVER', events: [{ fixed: '9.9.9' }] }] }] },
    { id: 'GHSA-b', summary: 'Bug B', database_specific: { severity: 'CRITICAL' }, affected: [{ package: { name: 'demo' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { last_affected: '2.0' }] }] }] },
    { id: 'GO-1', details: 'Unrated bug\nmore text', affected: [] },
  ];
  const rows = L.osvSummarize(vulns, 'demo');
  assert.equal(rows.map(r => r.id).join(), 'GHSA-b,GHSA-a,GO-1');
  assert.equal(rows[1].severity, 'MEDIUM'); assert.equal(rows[1].cves.join(), 'CVE-2020-1234'); assert.equal(rows[1].fixed.join(), '1.2.0');
  assert.equal(rows[0].fixed.length, 0); assert.equal(rows[2].severity, ''); assert.equal(rows[2].summary, 'Unrated bug');
  assert.equal(L.osvSummarize(undefined, 'demo').length, 0);
});

test('ATT&CK builder: skips revoked/deprecated, cleans descriptions', () => {
  assert.equal(firstSentence('Adversaries may use tools (e.g. PowerShell) to run code.(Citation: X) More text.'), 'Adversaries may use tools (e.g. PowerShell) to run code.');
  assert.equal(firstSentence('See [PowerShell](https://attack.mitre.org/techniques/T1059/001) and <code>cmd</code>. Next.'), 'See PowerShell and cmd.');
  assert.ok(firstSentence('word '.repeat(80)).length <= 240);
  const ref = id => [{ source_name: 'mitre-attack', external_id: id, url: 'https://attack.mitre.org/techniques/' + id.replace('.', '/') }];
  const kc = [{ kill_chain_name: 'mitre-attack', phase_name: 'initial-access' }];
  const out = compact({ objects: [
    { type: 'x-mitre-matrix', tactic_refs: ['tac-1'] },
    { type: 'x-mitre-tactic', id: 'tac-1', name: 'Initial Access', x_mitre_shortname: 'initial-access', external_references: [{ source_name: 'mitre-attack', external_id: 'TA0001' }] },
    { type: 'attack-pattern', name: 'Spearphishing Attachment', external_references: ref('T1566.001'), kill_chain_phases: kc, description: 'Sub. More.', x_mitre_is_subtechnique: true },
    { type: 'attack-pattern', name: 'Phishing', external_references: ref('T1566'), kill_chain_phases: kc, description: 'Adversaries may phish. More.' },
    { type: 'attack-pattern', name: 'Old', external_references: ref('T1000'), kill_chain_phases: kc, description: 'x', revoked: true },
    { type: 'attack-pattern', name: 'Older', external_references: ref('T1001'), kill_chain_phases: kc, description: 'x', x_mitre_deprecated: true },
  ] });
  assert.equal(out.tactics[0].id, 'TA0001');
  assert.equal(out.techniques.map(x => x.id).join(), 'T1566,T1566.001');
  assert.equal(out.techniques[0].desc, 'Adversaries may phish.'); assert.equal(out.techniques[1].sub, true);
});

test('ATT&CK dataset + search', () => {
  const d = JSON.parse(fs.readFileSync('data/attack.json', 'utf8'));
  assert.match(d.notice, /permission of The MITRE Corporation/);
  assert.ok(d.techniques.length > 500 && d.tactics.length >= 14);
  const shorts = new Set(d.tactics.map(x => x.short));
  for (const x of d.techniques) {
    assert.match(x.id, /^T\d{4}(\.\d{3})?$/); assert.ok(x.desc.length <= 240, x.id);
    assert.ok(x.tactics.length && x.tactics.every(s => shorts.has(s)), x.id);
  }
  const hits = L.attackFilter(d.techniques, 'phishing', '');
  assert.equal(hits[0].id, 'T1566'); assert.equal(L.attackFilter(d.techniques, 't1059', '')[0].id, 'T1059');
  assert.ok(L.attackFilter(d.techniques, 'phishing', 'initial-access').every(x => x.tactics.includes('initial-access')));
  assert.equal(L.attackFilter(d.techniques, 'zzzz-no-match', '').length, 0);
  assert.equal(L.attackFilter(d.techniques, '', '').length, d.techniques.length);
});
