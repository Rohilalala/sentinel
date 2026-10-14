// Bundle C: crypto lab, certificate decoder, password generator, hash identifier. No network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { L } from './_load.mjs';

const fixture = f => fs.readFileSync(new URL('./fixtures/' + f, import.meta.url), 'utf8');

test('AES-GCM blob is salt‖iv‖ciphertext‖tag and round-trips; wrong passphrase or a changed byte fails', async () => {
  const text = 'meet at 6 ☕', blob = await L.aesEncrypt(text, 'correct horse');
  const raw = Buffer.from(blob, 'base64');
  assert.equal(raw.length, 16 + 12 + Buffer.byteLength(text) + 16);
  assert.equal(await L.aesDecrypt(blob, 'correct horse'), text);
  await assert.rejects(L.aesDecrypt(blob, 'correct horsf'), /wrong passphrase/);
  raw[30] ^= 1;
  await assert.rejects(L.aesDecrypt(raw.toString('base64'), 'correct horse'), /data was changed/);
  await assert.rejects(L.aesDecrypt('bm90IGEgYmxvYg==', 'x'), /isn’t an encrypted blob/);
});

test('signatures verify, and one changed character breaks them', async () => {
  assert.equal(L.tamperOneChar('owe $20'), 'owe $30');
  for (const alg of ['ecdsa', 'rsa']) {
    const k = await L.makeKeypair(alg), msg = 'I, Sam, owe Alex $20.', sig = await L.signText(alg, k.privateKey, msg);
    assert.equal(await L.verifyText(alg, k.publicKey, msg, sig), true, alg);
    assert.equal(await L.verifyText(alg, k.publicKey, L.tamperOneChar(msg), sig), false, alg);
    assert.equal(k.privateKey.extractable, false);
    assert.match(await L.publicKeyPem(k.publicKey), /^-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+\n-----END PUBLIC KEY-----$/);
  }
});

test('HMAC-SHA256 matches RFC 4231 test case 2 and verifies', async () => {
  const tag = await L.hmacSha256('Jefe', 'what do ya want for nothing?');
  assert.equal(tag, '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
  assert.equal(await L.hmacVerify('Jefe', 'what do ya want for nothing?', tag.toUpperCase()), true);
  assert.equal(await L.hmacVerify('Jefe', 'what do ya want for nothing!', tag), false);
  await assert.rejects(L.hmacVerify('Jefe', 'x', 'abc'), /64 hex characters/);
});

test('parseCert reads ISRG Root X1 (self-signed root)', () => {
  const c = L.parseCert(fixture('isrgrootx1.pem'));
  assert.equal(c.subject.CN, 'ISRG Root X1'); assert.equal(c.subject.O, 'Internet Security Research Group'); assert.equal(c.subject.C, 'US');
  assert.equal(c.issuer.CN, 'ISRG Root X1');
  assert.equal(c.notBefore.toISOString(), '2015-06-04T11:04:38.000Z'); assert.equal(c.notAfter.toISOString(), '2035-06-04T11:04:38.000Z');
  assert.equal(c.serial, '82:10:cf:b0:d2:40:e3:59:44:63:e0:bb:63:82:8b:00');
  assert.equal(c.version, 3); assert.equal(c.keyAlg, 'RSA'); assert.equal(c.keySize, '4096-bit'); assert.equal(c.sigAlg, 'SHA-256 with RSA');
  assert.equal(c.selfSigned, true); assert.equal(c.isCA, true); assert.equal(c.san.length, 0);
  assert.equal(L.certStatus(c, Date.UTC(2026, 0, 1)).kind, 'root');
  assert.equal(L.certStatus(c, Date.UTC(2035, 4, 20)).kind, 'expiring');
  assert.equal(L.certStatus(c, Date.UTC(2036, 0, 1)).kind, 'expired');
  assert.throws(() => L.parseCert('hello'), /doesn’t look like a certificate/);
  assert.throws(() => L.parseCert(fixture('isrgrootx1.pem').slice(0, 900) + '-----END CERTIFICATE-----'), /cut off/);
});

test('parseCert reads SAN DNS names and an EC key from a self-signed leaf', () => {
  const c = L.parseCert(fixture('selfsigned-leaf.pem'));
  assert.equal(c.subject.CN, 'example.test');
  assert.deepEqual([...c.san], ['example.test', 'www.example.test']); // the IP SAN is skipped
  assert.equal(c.keyAlg, 'EC'); assert.equal(c.keySize, 'P-256'); assert.equal(c.sigAlg, 'ECDSA with SHA-256');
  assert.equal(c.isCA, false); assert.equal(L.certStatus(c, Date.UTC(2027, 0, 1)).kind, 'self');
});

test('random sampler stays in range and redraws the biased tail', () => {
  const seen = new Set();
  for (let i = 0; i < 3000; i++) { const x = L.secureRandInt(6); assert.ok(Number.isInteger(x) && x >= 0 && x < 6); seen.add(x); }
  assert.equal(seen.size, 6);
  const draws = [2 ** 32 - 1, 5]; // 2^32-1 sits above the last whole multiple of 7776, so it must be thrown away
  assert.equal(L.secureRandInt(7776, () => draws.shift()), 5);
  assert.match(L.makePassword(40, 'ab'), /^[ab]{40}$/);
});

test('EFF wordlist: 7,776 words, license header skipped', () => {
  const w = L.parseEffWordlist(fs.readFileSync(new URL('../data/eff_large_wordlist.txt', import.meta.url), 'utf8'));
  assert.equal(w.length, 7776); assert.equal(new Set(w).size, 7776);
  assert.equal(w[0], 'abacus'); assert.equal(w[7775], 'zoom');
});

test('crack time text', () => {
  assert.equal(L.crackTimeText(1), 'under a second');
  assert.equal(L.crackTimeText(60), '67 days');
  assert.equal(L.crackTimeText(128), 'longer than the age of the universe');
});

test('hash identifier', () => {
  const id = s => (L.identifyHash(s) || {}).name;
  const bcrypt = '$2y$12$CqWpfYGmS8l3dhc7GtMdu.11jj0OES2P8BqnvHNIbCLOjAA7ax7ki';
  assert.equal(id(bcrypt), 'bcrypt'); assert.match(L.identifyHash(bcrypt).detail, /cost 12/);
  assert.equal(id('$argon2id$v=19$m=19456,t=2,p=1$c2Vhc2FsdDEyM3NlYXNhbHQ$dEu5RQtu+0Uwf7Rus0npFLr+iAOevgYNCR6u73o52jI'), 'Argon2');
  assert.equal(id('$6$saltsalt$8iYtNHxjWRl.NF6oNZ5tF.iKFlQREaXBLlSmZKP6dy9l5z3vsooWNW0/GZ6Nej73/TFug6pIPSqbJoCT6dfnj.'), 'sha512crypt');
  assert.equal(id('$1$saltsalt$ZliGyAN3DciDHEkDboonh/'), 'md5crypt');
  assert.equal(id('pbkdf2_sha256$600000$seasalt123$C3T2PtYJuBuLml+66apFWZHwZwaZ24TBVBCnzf03xCM='), 'Django PBKDF2-SHA256');
  assert.equal(id('5f4dcc3b5aa765d61d8327deb882cf99'), 'MD5 or NTLM');
  assert.equal(id('5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8'), 'SHA-1');
  assert.equal(id('5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'), 'SHA-256');
  assert.equal(id('b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86'), 'SHA-512');
  const b64u = o => btoa(JSON.stringify(o)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
  assert.equal(id(`${b64u({ alg: 'HS256', typ: 'JWT' })}.${b64u({ sub: 'demo' })}.c2ln`), 'JWT');
  assert.equal(L.identifyHash('not a hash'), null);
});
