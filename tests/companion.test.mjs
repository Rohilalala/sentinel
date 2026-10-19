// Native tools: companion validators (imported from the server module) and the browser-side parsers on Sentinel.lib.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { L } from './_load.mjs';
import { validTarget, isLinkLocal, isPrivate, TOP100, parseNmap } from '../companion/server.mjs';
const j = x => JSON.parse(JSON.stringify(x)); // sandbox objects come from another realm

test('companion rejects argument injection and junk targets', () => {
  for (const ok of ['1.1.1.1', 'github.com', 'scanme.nmap.org', '2606:4700:4700::1111', 'localhost']) assert.ok(validTarget(ok), ok);
  for (const bad of ['-oX', '--script=x', '-1.1.1.1', 'a b', 'x;id', '$(id)', '', 'a'.repeat(254), 'github.com/x', 'a..b', null]) assert.ok(!validTarget(bad), String(bad));
});
test('companion refuses link-local addresses', () => {
  for (const ip of ['169.254.169.254', '::ffff:169.254.1.1', 'fe80::1', 'FEBF::1']) assert.ok(isLinkLocal(ip), ip);
  for (const ip of ['10.0.0.1', '1.1.1.1', '2606:4700::1111', '127.0.0.1']) assert.ok(!isLinkLocal(ip), ip);
});
test('private ranges that a public redirect may not reach', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.1', '192.168.1.1', '100.64.0.1', '0.0.0.0', '::1', 'fd00::1', '::ffff:192.168.0.1', '::ffff:7f00:1', '64:ff9b::7f00:1', '::127.0.0.1']) assert.ok(isPrivate(ip), ip);
  for (const ip of ['1.1.1.1', '172.32.0.1', '100.128.0.1', '8.8.8.8', '2606:4700::1111']) assert.ok(!isPrivate(ip), ip);
});
test('top 100 ports and nmap output', () => {
  assert.equal(new Set(TOP100).size, 100);
  assert.deepEqual(parseNmap('PORT   STATE SERVICE\n22/tcp open  ssh\n80/tcp open  http\n'), [{ port: 22, service: 'ssh' }, { port: 80, service: 'http' }]);
});
test('ping output: macOS, Linux, Windows', () => {
  const mac = L.parsePing('64 bytes from 1.1.1.1: icmp_seq=0 ttl=53 time=61.443 ms\nRequest timeout for icmp_seq 1\n64 bytes from 1.1.1.1: icmp_seq=2 ttl=53 time=38.1 ms\n\n--- 1.1.1.1 ping statistics ---\n3 packets transmitted, 2 packets received, 33.3% packet loss\nround-trip min/avg/max/stddev = 38.1/49.7/61.443/11.6 ms');
  assert.deepEqual(j(mac), { sent: 3, received: 2, loss: 33, min: 38.1, avg: 49.7, max: 61.443, times: [61.443, 38.1] });
  assert.equal(L.parsePing('4 packets transmitted, 4 received, 0% packet loss, time 3004ms\nrtt min/avg/max/mdev = 9.1/9.5/10.2/0.4 ms').avg, 9.5);
  const win = L.parsePing('Reply from 1.1.1.1: bytes=32 time<1ms TTL=57\nPackets: Sent = 4, Received = 4, Lost = 0 (0% loss),\nMinimum = 11ms, Maximum = 14ms, Average = 12ms');
  assert.deepEqual([win.loss, win.min, win.avg, win.max], [0, 11, 12, 14]);
  assert.equal(L.parsePing('ping: cannot resolve nope.invalid: Unknown host'), null);
});
test('traceroute output: hops, silent routers, Windows brackets', () => {
  const h = j(L.parseTraceroute(' 1  172.20.10.1 (172.20.10.1)  6.377 ms\n 2  *\n 3  one.one.one.one (1.1.1.1)  72.620 ms\n'));
  assert.deepEqual(h, [{ hop: 1, host: '172.20.10.1', ip: '172.20.10.1', ms: 6.377 }, { hop: 2, host: null, ip: null, ms: null }, { hop: 3, host: 'one.one.one.one', ip: '1.1.1.1', ms: 72.62 }]);
  const w = j(L.parseTraceroute('Tracing route to one.one.one.one [1.1.1.1]\n  1    <1 ms    <1 ms    <1 ms  192.168.1.1\n  2     *        *        *     Request timed out.\n  3    12 ms    11 ms    13 ms  one.one.one.one [1.1.1.1]'));
  assert.deepEqual(w.map(x => [x.hop, x.ip, x.ms]), [[1, '192.168.1.1', 1], [2, null, null], [3, '1.1.1.1', 11]]);
});
test('dig answers normalise for comparison with DoH', () => {
  const d = j(L.parseDig('gmail.com.\t\t3600\tIN\tMX\t5 gmail-smtp-in.l.google.com.\n;; comment\n'));
  assert.deepEqual(d, [{ name: 'gmail.com.', ttl: 3600, type: 'MX', data: '5 gmail-smtp-in.l.google.com.' }]);
  assert.equal(L.normDns(d[0].data), L.normDns('5  Gmail-SMTP-in.l.google.com'));
});
test('whois parser skips the IANA preamble', () => {
  const w = L.parseWhois('% IANA WHOIS server\nrefer: whois.verisign-grs.com\nnserver: A.GTLD-SERVERS.NET 192.5.6.30\ncreated: 1985-01-01\n\n# whois.verisign-grs.com\n   Domain Name: GITHUB.COM\n   Creation Date: 2007-10-09T18:20:50Z\n   Registry Expiry Date: 2028-10-09T18:20:50Z\n   Registrar: MarkMonitor Inc.\n   Name Server: DNS1.P08.NSONE.NET\n   Name Server: DNS1.P08.NSONE.NET\n');
  assert.deepEqual(j(w), { registrar: 'MarkMonitor Inc.', created: '2007-10-09T18:20:50Z', expires: '2028-10-09T18:20:50Z', nameservers: ['dns1.p08.nsone.net'], notFound: false });
  assert.equal(L.parseWhois('No match for "NOPE-XYZ.COM".').notFound, true);
});
test('tech detector reads headers, cookies and page source', () => {
  const r = L.detectTech({ headers: { server: 'nginx/1.18.0', 'x-powered-by': 'PHP/8.1.2', 'set-cookie': ['PHPSESSID=abc; path=/'] }, bodySample: '<link href="/wp-content/themes/x.css">' });
  assert.deepEqual(j(r.tech.map(x => x.name)), ['nginx', 'PHP', 'WordPress']);
  assert.equal(r.leaks.length, 2);
  assert.equal(L.detectTech({ headers: { server: 'cloudflare', 'set-cookie': [] }, bodySample: '' }).leaks.length, 0);
});
