// Bundle A (DNS+ and passive intel): pure logic on Sentinel.lib.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { S, L } from './_load.mjs';

test('bundle A tools register', () => {
  for (const id of ['rdns', 'propagation', 'emailauth', 'exposed']) {
    const m = S.modules[id];
    for (const k of ['id', 'name', 'group', 'icon', 'tile', 'blurb', 'why', 'tag', 'render']) assert.ok(m && m[k], `${id} missing ${k}`);
  }
});
test('ptrName', () => assert.equal(L.ptrName('8.8.4.4'), '4.4.8.8.in-addr.arpa'));
test('dohTxt joins Cloudflare\'s quoted chunks and leaves Google\'s plain text alone', () => {
  assert.equal(L.dohTxt('"v=DKIM1; k=rsa; p=AB" "CD"'), 'v=DKIM1; k=rsa; p=ABCD');
  assert.equal(L.dohTxt('v=spf1 -all'), 'v=spf1 -all');
});
test('sameDnsAnswers ignores order, quoting, trailing dots, TTL and RRSIG', () => {
  const cf = { Status: 0, Answer: [{ type: 1, TTL: 12, data: '104.16.133.229' }, { type: 1, TTL: 12, data: '104.16.132.229' }, { type: 46, TTL: 12, data: 'A 13 2 300 x' }] };
  const gg = { Status: 0, Answer: [{ type: 1, TTL: 300, data: '104.16.132.229' }, { type: 1, TTL: 300, data: '104.16.133.229' }] };
  assert.equal(L.sameDnsAnswers(cf, gg), true);
  assert.equal(L.sameDnsAnswers({ Status: 0, Answer: [{ type: 16, data: '"v=spf1 " "-all"' }] }, { Status: 0, Answer: [{ type: 16, data: 'v=spf1 -all' }] }), true);
  assert.equal(L.sameDnsAnswers({ Status: 0, Answer: [{ type: 2, data: 'ns1.example.com.' }] }, { Status: 0, Answer: [{ type: 2, data: 'NS1.example.com' }] }), true);
  assert.equal(L.sameDnsAnswers(gg, { Status: 0, Answer: [{ type: 1, TTL: 300, data: '142.251.221.174' }] }), false);
  assert.equal(L.sameDnsAnswers({ Status: 3 }, { Status: 0 }), false);
});
test('dkimKeyBits reads the RSA size from a real public key', () => {
  for (const bits of [1024, 2048]) {
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: bits, publicKeyEncoding: { type: 'spki', format: 'der' } });
    assert.equal(L.dkimKeyBits(publicKey.toString('base64')), bits);
  }
  assert.equal(L.dkimKeyBits(''), 0);      // empty p= means a revoked key
  assert.equal(L.dkimKeyBits('not base64!'), 0);
});
test('gradeEmailAuth', () => {
  const full = { spf: 'v=spf1 include:_spf.example.net -all', dmarc: 'v=DMARC1; p=reject', dkim: [{ sel: 's1', bits: 2048 }],
    mtasts: 'v=STSv1; id=1', tlsrpt: 'v=TLSRPTv1; rua=mailto:tls@example.com', bimi: 'v=BIMI1; l=https://example.com/logo.svg' };
  const g = L.gradeEmailAuth(full);
  assert.equal(g.grade, 'A'); assert.equal(g.score, 100); assert.equal(g.cls, 'safe');
  assert.equal(L.gradeEmailAuth({ ...full, dmarc: 'v=DMARC1; sp=none; p=reject' }).grade, 'A'); // sp= is not p=
  assert.equal(L.gradeEmailAuth({ ...full, dmarc: 'v=DMARC1; p=none' }).grade, 'D');            // spoofable caps at D
  assert.equal(L.gradeEmailAuth({ spf: null, dmarc: null, dkim: [], mtasts: null, tlsrpt: null, bimi: null }).grade, 'F');
  // no selector matched: DKIM is left out of the score instead of counted as zero
  assert.equal(L.gradeEmailAuth({ ...full, dkim: [] }).score, 100);
  // the weakest key decides; a revoked (0-bit) key is ignored
  const weak = L.gradeEmailAuth({ ...full, dkim: [{ sel: 's1', bits: 2048 }, { sel: 'k1', bits: 1024 }, { sel: 'old', bits: 0 }] });
  assert.equal(weak.score, 92); assert.match(weak.parts.find(p => p.name === 'DKIM').note, /"k1"/);
  assert.equal(L.gradeEmailAuth({ ...full, dkim: [{ sel: 'ed', bits: 256, ed: true }] }).score, 100); // Ed25519 is strong
});
test('exposureLevel', () => {
  assert.equal(L.exposureLevel(null).cls, 'safe');
  assert.equal(L.exposureLevel({ ports: [80, 443], vulns: [], tags: ['cdn'] }).cls, '');
  assert.equal(L.exposureLevel({ ports: [443, 3389], vulns: [], tags: [] }).cls, 'warn');
  assert.equal(L.exposureLevel({ ports: [80], vulns: [], tags: ['eol-product'] }).cls, 'warn');
  assert.equal(L.exposureLevel({ ports: [80], vulns: ['CVE-2021-44224'], tags: [] }).cls, 'danger');
  assert.equal(L.exposureLevel({ ports: [80], vulns: [], tags: ['compromised'] }).cls, 'danger');
});
