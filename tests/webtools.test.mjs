// Bundle E: privacy + web grading logic on Sentinel.lib. No network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { S, L } from './_load.mjs';

const titles = r => r.findings.map(f => `${f.sev}:${f.title}`);

test('CSP grader: weak vs strong policies', () => {
  const weak = L.gradeCsp("script-src 'self' 'unsafe-inline' https: data:");
  assert.ok(titles(weak).includes("bad:'unsafe-inline' in script-src"));
  assert.ok(titles(weak).includes('bad:https: in script-src'));
  assert.ok(titles(weak).includes('bad:data: in script-src'));
  assert.ok(titles(weak).includes('warn:No base-uri'));
  assert.equal(weak.grade, 'F');
  const strong = L.gradeCsp("Content-Security-Policy: script-src 'nonce-r4nd0m' 'strict-dynamic' https: 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'");
  assert.equal(strong.grade, 'A');
  assert.ok(titles(strong).includes("info:'unsafe-inline' in script-src is ignored"));
  assert.ok(!titles(strong).some(x => x.startsWith('bad:')));
  assert.equal(L.gradeCsp("default-src 'none'").findings.find(f => f.title.startsWith('Plugins')).sev, 'ok'); // default-src covers object-src
  assert.ok(titles(L.gradeCsp("scritp-src 'self'")).includes('info:Unknown directive "scritp-src"'));
  assert.ok(titles(L.gradeCsp("script-src 'self' 'unsafe-eval'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")).includes("warn:'unsafe-eval' in script-src"));
});

test('one failing check caps the grade at C', () => {
  assert.equal(L.gradeCsp("script-src 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'").grade, 'C');
});

test('raw headers parse into the companion /api/http shape', () => {
  const { status, headers } = L.parseHttpHeaders('HTTP/1.1 301 Moved\r\nLocation: https://x.example/\r\n\r\nHTTP/2 200\r\nX-Frame-Options: DENY\r\nVary: a\r\nVary: b\r\nSet-Cookie: a=1; Secure\r\nSet-Cookie: b=2\r\nnot a header\r\n__proto__: x');
  assert.equal(status, 200);
  assert.equal(headers.location, undefined); // only the last response is kept
  assert.equal(headers['x-frame-options'], 'DENY');
  assert.equal(headers.vary, 'a, b');
  assert.equal(JSON.stringify(headers['set-cookie']), '["a=1; Secure","b=2"]');
  assert.equal(headers.__proto__, 'x'); // hostile names are plain keys
});

test('header grader: strong set grades A, empty set fails', () => {
  const strong = L.gradeHeaders({
    'strict-transport-security': 'max-age=31536000; includeSubDomains; preload',
    'content-security-policy': "default-src 'none'; script-src 'sha256-abc='; base-uri 'self'; frame-ancestors 'none'",
    'x-content-type-options': 'nosniff', 'referrer-policy': 'origin-when-cross-origin, strict-origin-when-cross-origin',
    'set-cookie': ['sess=1; Secure; HttpOnly; SameSite=Lax', '_ga=2; Secure; SameSite=Lax'],
  });
  assert.equal(strong.csp.grade, 'A');
  assert.equal(strong.grade, 'A');
  assert.ok(titles(strong).includes('ok:Framing blocked (CSP frame-ancestors)'));
  assert.ok(titles(strong).includes('ok:Referrer-Policy: strict-origin-when-cross-origin'));
  assert.ok(titles(strong).includes('info:Cookie _ga lacks HttpOnly')); // not a session cookie: a note, not a warning
  const bare = L.gradeHeaders({ 'set-cookie': ['sessionid=abc'], 'x-powered-by': 'PHP/8.1', 'strict-transport-security': 'max-age=300' });
  assert.ok(titles(bare).includes('bad:No Content-Security-Policy'));
  assert.ok(titles(bare).includes('warn:HSTS max-age is only 300 seconds'));
  assert.ok(titles(bare).includes('warn:Cookie sessionid lacks Secure, HttpOnly, SameSite'));
  assert.ok(titles(bare).includes('warn:X-Powered-By: PHP/8.1'));
  assert.equal(bare.grade, 'F');
});

test('defang / refang', () => {
  assert.equal(L.defang('https://evil.example/a'), 'hxxps://evil[.]example/a');
  assert.equal(L.refang('hxxps[:]//evil[.]example(.)com/x'), 'https://evil.example.com/x');
  assert.equal(L.refang(L.defang('http://a.b.example/')), 'http://a.b.example/');
});

test('URL inspector: homographs, @ tricks, disguised IPs, brand in subdomain', () => {
  const apple = L.inspectUrl('https://аррӏе.com/'); // all-Cyrillic "apple"
  assert.equal(apple.host, 'xn--80ak6aa92e.com');
  assert.ok(titles(apple).includes('bad:Looks like apple.com'));
  const mix = L.inspectUrl('https://pаypal.com/login'); // Latin + one Cyrillic a
  assert.ok(titles(mix).includes('bad:Mixed alphabets in one name'));
  const at = L.inspectUrl('http://paypal.com@0xcb007107/verify');
  assert.equal(at.host, '203.0.113.7');
  assert.ok(titles(at).some(x => x.startsWith('bad:Userinfo trick')));
  assert.ok(titles(at).includes('bad:Disguised IP address'));
  const sub = L.inspectUrl('hxxps://login.microsoftonline.com.example[.]net/?next=%2Fmail');
  assert.ok(titles(sub).includes('info:Input was defanged'));
  assert.ok(titles(sub).includes('warn:A domain name hides inside the subdomain'));
  assert.equal(JSON.stringify(sub.query), '[["next","/mail"]]'); // sandbox arrays are cross-realm: compare as JSON
  const plain = L.inspectUrl('example.com:8080/a%20b');
  assert.equal(plain.path, '/a b');
  assert.ok(!titles(plain).some(x => x.startsWith('bad:') || x.startsWith('warn:')));
  assert.equal(L.inspectUrl('http://exa mple.com'), null);
});

test('user agent parsing', () => {
  const mac = L.parseUA('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36');
  assert.deepEqual({ ...mac }, { browser: 'Chrome', version: '141', os: 'macOS' });
  assert.equal(L.parseUA('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0').browser, 'Edge');
  assert.equal(L.parseUA('Mozilla/5.0 (X11; Linux x86_64; rv:143.0) Gecko/20100101 Firefox/143.0').os, 'Linux');
  const ios = L.parseUA('Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1');
  assert.deepEqual({ ...ios }, { browser: 'Safari', version: '18', os: 'iOS 18.6' });
});

test('WebRTC candidates and leak verdict', () => {
  const mdns = 'candidate:1 1 udp 2113937151 0a1b2c3d-1111-2222-3333-444455556666.local 54400 typ host generation 0';
  const srflx = 'candidate:2 1 udp 1677729535 203.0.113.5 54400 typ srflx raddr 0.0.0.0 rport 0 generation 0';
  const lan = 'candidate:3 1 udp 2113937151 192.168.1.20 54400 typ host generation 0';
  const p = L.parseCandidate(srflx);
  assert.equal(p.ip, '203.0.113.5'); assert.equal(p.type, 'srflx'); assert.equal(p.kind, 'public');
  assert.equal(L.parseCandidate(mdns).kind, 'mdns');
  assert.equal(L.parseCandidate(lan).kind, 'private');
  assert.equal(L.webrtcVerdict([mdns, srflx], ['203.0.113.5']).cls, 'safe');
  assert.equal(L.webrtcVerdict([mdns, srflx], ['198.51.100.9']).cls, 'danger'); // VPN leak
  assert.equal(L.webrtcVerdict([lan, srflx], ['203.0.113.5']).cls, 'warn');
  assert.equal(L.webrtcVerdict([], ['203.0.113.5']).cls, 'safe');
  assert.equal(L.webrtcVerdict([mdns], ['203.0.113.5']).cls, ''); // STUN unreachable: inconclusive
});

test('fingerprint scoring', () => {
  const full = L.scoreFingerprint({ canvas: { hash: 'ab'.repeat(32), noisy: false }, webgl: 'Apple / Apple M2', fonts: ['Arial', 'Menlo'],
    screen: '1440×900, 30-bit, 2x', timezone: 'Asia/Kolkata', languages: 'en-US, en', cores: 8, memory: '8 GB (rounded)' });
  assert.equal(full.bits, 34); assert.equal(full.cls, 'warn');
  const hidden = L.scoreFingerprint({ canvas: { hash: 'ab'.repeat(32), noisy: true }, webgl: null, fonts: [], screen: '1000×1000, 24-bit, 1x', timezone: 'UTC', languages: 'en-US', cores: null, memory: null });
  assert.equal(hidden.rows.find(r => r.k === 'canvas').bits, 0);
  assert.equal(hidden.cls, 'safe');
});

test('bundle E tools register with tags and existing icons', () => {
  const want = { whatsites: ['Privacy', 'live'], webrtc: ['Privacy', 'live'], fingerprint: ['Privacy', 'local'], csp: ['Web & email', 'local'],
    headers: ['Web & email', 'local'], secheaders: ['Native', 'native'], urlinspect: ['Web & email', 'local'] };
  for (const [id, [group, tag]] of Object.entries(want)) {
    const m = S.modules[id];
    assert.ok(m, id); assert.equal(m.group, group); assert.equal(m.tag, tag);
    for (const k of ['tile', 'why']) assert.ok(m[k], `${id} missing ${k}`);
    assert.notEqual(S.svg(m.icon), S.svg('no-such-icon'), `${id} icon ${m.icon} is not registered`);
  }
});
