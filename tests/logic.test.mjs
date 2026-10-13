// Loads the real browser files into a sandbox and tests the pure logic on Sentinel.lib.
// Run: node --test tests/
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { S, L } from './_load.mjs';

test('every tool registers with the required fields', () => {
  for (const id of S.order) {
    const m = S.modules[id];
    for (const k of ['id', 'name', 'group', 'icon', 'blurb', 'render']) assert.ok(m[k], `${id} missing ${k}`);
  }
});
test('core helpers', () => {
  assert.equal(S.isIP('8.8.8.8'), true); assert.equal(S.isIP('999.1.1.1'), false);
  assert.equal(S.cleanHost('https://Example.com/path?q=1'), 'example.com');
  assert.equal(S.esc('<a href="x">'), '&lt;a href=&quot;x&quot;&gt;');
});
test('cidr', () => {
  const c = L.cidrInfo('192.168.1.10/24');
  assert.equal(c.network, '192.168.1.0'); assert.equal(c.broadcast, '192.168.1.255'); assert.equal(c.usable, 254);
  assert.equal(L.cidrInfo('10.0.0.0/30').usable, 2); assert.equal(L.cidrInfo('1.2.3.4/32').usable, 1);
  assert.equal(L.cidrInfo('300.0.0.0/8'), null);
});
test('encoding roundtrips', () => {
  assert.equal(L.b64dec(L.b64enc('héllo 世界')), 'héllo 世界');
  assert.equal(L.rot13('Hello'), 'Uryyb'); assert.equal(L.rot13(L.rot13('abcXYZ')), 'abcXYZ');
  assert.equal(L.fromHex(L.toHex('Hi!')), 'Hi!');
});
test('password strength', () => {
  assert.equal(L.strength('password123').score, 0);
  assert.ok(L.strength('9#Kv2!xQ7mLp$w').score >= 3);
});
test('typosquat variants', () => {
  const v = L.genVariants('paypal.com');
  assert.ok(v.includes('paypa1.com')); assert.ok(v.includes('paypal.net')); assert.ok(!v.includes('paypal.com'));
});
test('email header parsing', () => {
  const h = L.parseHeaders('Received: from evil.example (x) by mx.google.com; Mon, 1 Jan 2026\nAuthentication-Results: mx; spf=fail; dkim=none; dmarc=fail\nFrom: A <a@b.com>');
  assert.equal(h.spf, 'fail'); assert.equal(h.dmarc, 'fail'); assert.equal(h.hops[0].from, 'evil.example'); assert.equal(h.get('From'), 'A <a@b.com>');
});
test('blocklists configured', () => { assert.equal(L.DNSBLS.length, 4); });
