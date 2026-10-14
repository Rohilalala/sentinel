// Bundle D: forensics + code security pure logic. Fixtures are built in memory; secret samples are assembled
// by concatenation so no key-shaped literal is ever committed.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { S, L } from './_load.mjs';

const plain = x => JSON.parse(JSON.stringify(x)); // sandbox objects have another realm's prototypes
const bytes = (...parts) => Uint8Array.from(parts.flatMap(p => typeof p === 'string' ? [...p].map(c => c.charCodeAt(0)) : p));

test('bundle D tools register in Forensics, tagged local', () => {
  for (const id of ['fileinspect', 'exif', 'exe', 'secrets', 'iam']) {
    const m = S.modules[id];
    assert.ok(m, id);
    assert.equal(m.group, 'Forensics'); assert.equal(m.tag, 'local');
    for (const k of ['name', 'icon', 'tile', 'blurb', 'why']) assert.ok(m[k], `${id} missing ${k}`);
  }
});

test('magic bytes, entropy, strings, IOCs', () => {
  assert.equal(L.sniffMagic(bytes([0x89], 'PNG\r\n', [0x1a], '\n')).type, 'PNG image');
  assert.equal(L.sniffMagic(bytes('MZ', [0x90, 0])).exec, true);
  assert.equal(L.sniffMagic(bytes('%PDF-1.7')).type, 'PDF document');
  assert.equal(L.sniffMagic(bytes('hello')), null);
  assert.equal(L.byteEntropy(new Uint8Array(64)), 0);
  assert.equal(L.byteEntropy(Uint8Array.from({ length: 256 }, (_, i) => i)), 8);
  const strs = L.printableStrings(bytes('hi', [0], 'hello world', [0, 1], 'see http://evil.example/x and 10.0.0.1', [0xff], 'v 999.1.1.1'));
  assert.deepEqual(plain(strs), ['hello world', 'see http://evil.example/x and 10.0.0.1', 'v 999.1.1.1']);
  assert.deepEqual(plain(L.findIocs(strs)), { urls: ['http://evil.example/x'], ips: ['10.0.0.1'] });
});

// Minimal little-endian TIFF: IFD0 {Make, GPS pointer} → GPS IFD {N 40°26'46.302", W 79°58'56"}
function exifJpeg() {
  const t = new DataView(new ArrayBuffer(168)), u8 = new Uint8Array(t.buffer);
  const entry = (at, tag, type, cnt, v) => { t.setUint16(at, tag, true); t.setUint16(at + 2, type, true); t.setUint32(at + 4, cnt, true); t.setUint32(at + 8, v, true); };
  const rat = (at, ...r) => r.forEach(([n, d], k) => { t.setUint32(at + 8 * k, n, true); t.setUint32(at + 8 * k + 4, d, true); });
  u8.set([0x49, 0x49]); t.setUint16(2, 42, true); t.setUint32(4, 8, true);
  t.setUint16(8, 2, true); entry(10, 0x10f, 2, 6, 100); entry(22, 0x8825, 4, 1, 38);
  t.setUint16(38, 4, true);
  entry(40, 1, 2, 2, 0); u8[48] = 0x4e; entry(52, 2, 5, 3, 120); entry(64, 3, 2, 2, 0); u8[72] = 0x57; entry(76, 4, 5, 3, 144);
  u8.set(bytes('Canon', [0]), 100); rat(120, [40, 1], [26, 1], [46302, 1000]); rat(144, [79, 1], [58, 1], [56, 1]);
  const len = 2 + 6 + u8.length;
  return bytes([0xff, 0xd8, 0xff, 0xe1, len >> 8, len & 255], 'Exif', [0, 0], [...u8], [0xff, 0xd9]);
}
test('parseExif reads camera and converts GPS DMS to decimal', () => {
  const x = L.parseExif(exifJpeg());
  assert.equal(x.make, 'Canon');
  assert.ok(Math.abs(x.gps.lat - 40.446195) < 1e-6, String(x.gps.lat));
  assert.ok(Math.abs(x.gps.lon + 79.982222) < 1e-6, String(x.gps.lon));
  assert.equal(L.parseExif(bytes([0xff, 0xd8, 0xff, 0xdb, 0, 4, 0, 0, 0xff, 0xd9])), null); // JPEG without EXIF
  assert.equal(L.parseExif(bytes('not a jpeg')), null);
  const broken = exifJpeg(); new DataView(broken.buffer).setUint32(16, 0xfffffff0, true); // IFD0 offset past the end
  assert.equal(L.parseExif(broken).gps, null);
});

// Minimal PE32+: 2 sections, .text (R-X) and UPX1 (RWX, random-looking bytes), timestamp 2021
function tinyPE() {
  const b = new Uint8Array(0x400), d = new DataView(b.buffer);
  b.set(bytes('MZ')); d.setUint32(0x3c, 0x80, true); b.set(bytes('PE', [0, 0]), 0x80);
  d.setUint16(0x84, 0x8664, true); d.setUint16(0x86, 2, true); d.setUint32(0x88, 0x60000000, true); d.setUint16(0x94, 0xf0, true); d.setUint16(0x96, 0x22, true);
  d.setUint16(0x98, 0x20b, true); d.setUint32(0x98 + 16, 0x1000, true); d.setUint16(0x98 + 68, 3, true);
  const sec = (at, name, ptr, flags) => { b.set(bytes(name), at); d.setUint32(at + 8, 0x100, true); d.setUint32(at + 16, 0x100, true); d.setUint32(at + 20, ptr, true); d.setUint32(at + 36, flags, true); };
  sec(0x188, '.text', 0x200, 0x60000020); sec(0x1b0, 'UPX1', 0x300, 0xe0000040);
  for (let i = 0; i < 256; i++) b[0x300 + i] = i;
  return b;
}
test('parseExe reads PE headers and flags red signs', () => {
  const x = L.parseExe(tinyPE(), Date.UTC(2001, 0, 1));
  assert.equal(x.format, 'PE'); assert.equal(x.bits, 64); assert.equal(x.machine, 'x86-64'); assert.equal(x.subsystem, 'Windows console');
  assert.equal(x.entry, '0x1000');
  assert.deepEqual(plain(x.sections.map(s => [s.name, s.r, s.w, s.x])), [['.text', true, false, true], ['UPX1', true, true, true]]);
  assert.equal(x.sections[1].entropy, 8);
  const txt = x.signals.map(s => s[0] + ':' + s[1]).join('\n');
  assert.match(txt, /bad:.*UPX1.*writable and executable/); assert.match(txt, /entropy 8\.00/); assert.match(txt, /known packer/); assert.match(txt, /in the future/);
  assert.equal(L.parseExe(tinyPE(), Date.UTC(2030, 0, 1)).signals.some(s => /future/.test(s[1])), false);
  assert.throws(() => L.parseExe(bytes('MZ', [0, 0])), /truncated or corrupt/);
  assert.equal(L.parseExe(bytes('%PDF-1.7')), null);
});
test('parseExe reads an ELF header', () => {
  const b = new Uint8Array(64), d = new DataView(b.buffer);
  b.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]); d.setUint16(16, 3, true); d.setUint16(18, 62, true); d.setBigUint64(24, 0x1040n, true);
  const x = L.parseExe(b);
  assert.deepEqual([x.format, x.bits, x.machine, x.kind, x.entry], ['ELF', 64, 'x86-64', 'Shared library or PIE executable', '0x1040']);
});

test('scanSecrets finds known formats, masks them, and skips placeholders', () => {
  const aws = 'AKIA' + 'IOSFODNN7EXAMPLE', gh = 'gh' + 'p_' + 'a1B2'.repeat(9), stripe = 's' + 'k_live_' + 'x9Y8'.repeat(6);
  const text = [
    `aws_access_key_id = ${aws}`,
    `token: "${gh}"`,
    `const stripe = '${stripe}'`,
    'password = process.env.DB_PASS',
    'DB_PASSWORD="correct-horse-battery-staple"',
    '-----BEGIN ' + 'RSA PRIVATE KEY-----',
    'MIIEowIBAAKCAQEA7bq9EXAMPLEb0dyb9Qx3kL2mZ8pN4rT6vW1yA3cE5gH7jK9',
    '-----END ' + 'RSA PRIVATE KEY-----',
    'timeout = 30',
  ].join('\n');
  const hits = L.scanSecrets(text);
  assert.deepEqual(plain(hits.map(h => [h.line, h.rule, h.sev])), [
    [1, 'AWS access key ID', 'high'], [2, 'GitHub token', 'high'], [3, 'Stripe live key', 'high'],
    [5, 'Hard-coded password or secret', 'medium'], [6, 'Private key block', 'high']]);
  for (const h of hits) for (const s of [aws, gh, stripe, 'correct-horse-battery-staple']) assert.ok(!h.masked.includes(s));
  assert.equal(hits[0].masked, 'AKIA' + '•'.repeat(8));
  const ent = L.scanSecrets('x = "Zq8vLm3Rt7Wp2Kx9Nc4Bh6Fj"');
  assert.equal(ent.length, 1); assert.equal(ent[0].rule, 'High-entropy string');
  assert.equal(L.scanSecrets('const greeting = "hello"\nimport os').length, 0);
});

test('analyzeIam flags wildcards, NotAction, PassRole, public principals', () => {
  const pol = st => JSON.stringify({ Version: '2012-10-17', Statement: st });
  const find = st => L.analyzeIam(pol(st)).map(f => f.sev + ':' + f.issue);
  assert.match(find([{ Effect: 'Allow', Action: '*', Resource: '*' }])[0], /^high:.*full administrator/);
  assert.match(find([{ Effect: 'Allow', NotAction: 'iam:*', Resource: '*' }])[0], /^high:.*NotAction/);
  assert.ok(find([{ Effect: 'Allow', Action: ['iam:PassRole'], Resource: '*' }]).some(x => /^high:iam:PassRole/.test(x)));
  assert.ok(find({ Effect: 'Allow', Action: 's3:*', Resource: '*' }).some(x => /^high:s3:\*/.test(x)));
  assert.ok(find([{ Effect: 'Allow', Action: 'kms:Decrypt', Resource: 'arn:aws:kms:us-east-1:111122223333:key/abc' }]).some(x => /^medium:Sensitive.*kms:Decrypt/.test(x)));
  assert.match(find([{ Effect: 'Allow', Principal: { AWS: '*' }, Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*' }])[0], /^high:Principal is "\*"/);
  assert.match(find([{ Effect: 'Allow', Principal: '*', Action: 's3:GetObject', Resource: 'arn:aws:s3:::b/*', Condition: { StringEquals: { 'aws:PrincipalOrgID': 'o-1' } } }])[0], /^medium:/);
  assert.match(find([{ Effect: 'Allow', Action: 'ec2:DescribeInstances', Resource: '*' }])[0], /^medium:Resource is "\*"/);
  assert.equal(find([{ Effect: 'Allow', Action: ['s3:GetObject'], Resource: 'arn:aws:s3:::b/*' }, { Effect: 'Deny', Action: '*', Resource: '*' }]).length, 0);
  assert.throws(() => L.analyzeIam('{ nope'), /valid JSON/);
  assert.throws(() => L.analyzeIam('{}'), /No "Statement"/);
});
