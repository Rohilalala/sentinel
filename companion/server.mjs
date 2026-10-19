#!/usr/bin/env node
/* Sentinel companion: serves the app on 127.0.0.1 and adds native tools a browser can't run
   (ping, traceroute, dig, whois, port scan, server-side HTTP fetch). Zero dependencies.
   Run: node companion/server.mjs [--port 7777]   then open http://127.0.0.1:7777
   Security model: docs/SPEC.md section 6.1. Never simplify any of it away. */
import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import net from 'node:net';
import dns from 'node:dns/promises';
import { execFile } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';

const VERSION = '1.0.0';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CAP = 256 * 1024;                       // command output cap
const SERVE = ['index.html', 'manifest.webmanifest', 'sw.js', 'config.js', 'icons', 'css', 'js', 'data', 'vendor'];
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.webmanifest': 'application/manifest+json', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.txt': 'text/plain; charset=utf-8', '.ico': 'image/x-icon', '.woff2': 'font/woff2' };

/* ---------- validation (exported for tests) ---------- */
const HOST_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$/;
export const validTarget = t => typeof t === 'string' && t.length > 0 && t.length <= 253 && !t.startsWith('-') && (net.isIP(t) !== 0 || HOST_RE.test(t));
export const DNS_TYPES = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA'];
const blockList = ranges => { const b = new net.BlockList(); for (const [a, p] of ranges) b.addSubnet(a, p, net.isIPv4(a) ? 'ipv4' : 'ipv6'); return b; };
const LINK_LOCAL = blockList([['169.254.0.0', 16], ['fe80::', 10]]);
const PRIVATE = blockList([['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12],
  ['192.168.0.0', 16], ['::', 96], ['64:ff9b::', 96], ['fc00::', 7], ['fe80::', 10]]);
const family = ip => net.isIPv4(ip) ? 'ipv4' : 'ipv6';
export const isLinkLocal = ip => LINK_LOCAL.check(ip, family(ip));   // also matches ::ffff:169.254.x.x
export const isPrivate = ip => PRIVATE.check(ip, family(ip));        // loopback, LAN, CGNAT, ULA, link-local, mapped forms
// nmap's 100 most common TCP ports (nmap --top-ports 100)
export const TOP100 = [7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199, 389, 427,
  443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720,
  1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631,
  5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155,
  49156, 49157];
const SERVICES = { 21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'domain', 80: 'http', 110: 'pop3', 111: 'rpcbind', 135: 'msrpc',
  139: 'netbios-ssn', 143: 'imap', 443: 'https', 445: 'microsoft-ds', 465: 'smtps', 548: 'afp', 587: 'submission', 631: 'ipp', 993: 'imaps',
  995: 'pop3s', 1433: 'ms-sql', 1723: 'pptp', 3000: 'http-alt', 3306: 'mysql', 3389: 'ms-rdp', 5000: 'upnp', 5432: 'postgresql',
  5900: 'vnc', 8000: 'http-alt', 8080: 'http-proxy', 8443: 'https-alt', 8888: 'http-alt', 9100: 'jetdirect' };
export const parseNmap = out => [...out.matchAll(/^(\d+)\/tcp\s+open\s+(\S+)/gm)].map(m => ({ port: +m[1], service: m[2] }));

/* ---------- native binaries (allowlist; never a shell) ---------- */
const DIRS = [...(process.env.PATH || '').split(path.delimiter), '/sbin', '/usr/sbin', '/usr/bin', '/bin', '/usr/local/bin', '/opt/homebrew/bin'];
const WIN = process.platform === 'win32';
const which = name => DIRS.map(d => path.join(d, name + (WIN ? '.exe' : ''))).find(p => { try { fs.accessSync(p, fs.constants.X_OK); return true; } catch { return false; } }) || null;
const BIN = { ping: which('ping'), traceroute: which(WIN ? 'tracert' : 'traceroute'), dig: which('dig'), whois: which('whois'), nmap: which('nmap') };
const tools = () => Object.fromEntries(Object.entries(BIN).map(([k, v]) => [k, !!v]));
const ARGS = {
  ping: t => WIN ? ['-n', '4', t] : ['-c', '4', t],
  traceroute: t => WIN ? ['-h', '20', '-w', '2000', t] : ['-m', '20', '-w', '2', '-q', '1', t],
  dig: (t, type) => ['+noall', '+answer', t, type],
  whois: t => [t],
};
const TIMEOUT = { ping: 15e3, traceroute: 60e3, dig: 10e3, whois: 20e3, scan: 120e3 };
const runBin = (bin, args, ms) => new Promise(res => {
  const t0 = Date.now();
  execFile(bin, args, { timeout: ms, maxBuffer: CAP, windowsHide: true }, (err, stdout, stderr) => res({
    code: !err ? 0 : err.killed ? 'timeout' : typeof err.code === 'number' ? err.code : String(err.code),
    stdout: String(stdout).slice(0, CAP), stderr: String(stderr).slice(0, 8192), ms: Date.now() - t0 }));
});

/* ---------- built-in TCP-connect scanner (used when nmap is absent) ---------- */
function tcpScan(ip, ports, ms = 800, conc = 64) {
  return new Promise(resolve => {
    const open = []; let next = 0, active = 0, closed = 0, filtered = 0;
    const pump = () => {
      if (next >= ports.length && !active) return resolve({ open: open.sort((a, b) => a - b), closed, filtered });
      while (active < conc && next < ports.length) {
        const port = ports[next++]; active++;
        const s = net.connect({ host: ip, port }); let settled = false;
        const done = state => { if (settled) return; settled = true; s.destroy(); active--;
          state === 'open' ? open.push(port) : state === 'closed' ? closed++ : filtered++; pump(); };
        s.setTimeout(ms, () => done('filtered'));
        s.once('connect', () => done('open'));
        s.once('error', e => done(e.code === 'ECONNREFUSED' ? 'closed' : 'filtered'));
      }
    };
    pump();
  });
}

/* ---------- server-side HTTP fetch ---------- */
const fail = (status, error) => Object.assign(new Error(error), { status });
// Link-local is always refused. A fetch that starts at a public address may not redirect into
// loopback or the LAN: Link Unshortener follows untrusted links, and that would make your computer
// send requests to your own devices. The check runs inside the socket's DNS lookup, on the exact
// address it connects to, so a rebinding DNS answer can't slip past it.
function vet(ips, state) {
  if (ips.some(isLinkLocal)) throw fail(400, 'Refusing link-local addresses (169.254.0.0/16, fe80::/10)');
  state.pub = ips.every(ip => !isPrivate(ip));
  if (state.publicOnly && !state.pub) throw fail(400, `Stopped: a redirect pointed to ${state.url}, inside a private network. Sentinel won't follow a public link into your own devices.`);
}
const guardedLookup = state => (hostname, opts, cb) => dns.lookup(hostname, { ...opts, all: true }).then(addrs => {
  try { vet(addrs.map(a => a.address), state); } catch (e) { return cb(e); }
  opts.all ? cb(null, addrs) : cb(null, addrs[0].address, addrs[0].family);
}, () => cb(fail(400, `Could not resolve ${hostname}`)));
function get(u, state, signal) {
  return new Promise((resolve, reject) => {
    const host = u.hostname.replace(/^\[|\]$/g, '');
    if (net.isIP(host)) { try { vet([host], state); } catch (e) { return reject(e); } }   // IP literals never hit the lookup
    const req = (u.protocol === 'https:' ? https : http).request(u, { signal, agent: false, lookup: guardedLookup(state),
      headers: { 'user-agent': `Sentinel-companion/${VERSION}`, accept: '*/*', 'accept-encoding': 'identity' } }, res => {
      const parts = []; let n = 0;
      const done = () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(parts).subarray(0, 65536).toString('utf8') });
      res.on('data', c => { parts.push(c); n += c.length; if (n >= 65536) res.destroy(); });
      res.on('end', done); res.on('close', done);
    });
    req.on('error', e => reject(e.status ? e : fail(502, e.name === 'AbortError' ? 'The site took longer than 10 seconds' : `Fetch failed: ${e.code || e.message}`)));
    req.end();
  });
}
async function httpFetch(raw) {
  if (typeof raw !== 'string' || raw.length > 2048) throw fail(400, 'URL missing or longer than 2,048 characters');
  let u; try { u = new URL(raw); } catch { throw fail(400, 'Not a valid URL. Include the scheme, e.g. https://example.com'); }
  const t0 = Date.now(), signal = AbortSignal.timeout(10e3), chain = [], state = {};
  for (let hop = 0; ; hop++) {
    if (!/^https?:$/.test(u.protocol)) throw fail(400, 'Only http: and https: URLs are allowed');
    Object.assign(state, { url: u.href, publicOnly: hop > 0 && state.startedPublic, pub: undefined });
    const r = await get(u, state, signal);
    if (hop === 0) state.startedPublic = state.pub;
    const loc = r.headers.location || null;
    chain.push({ url: u.href, status: r.status, location: loc });
    if (r.status >= 300 && r.status < 400 && loc) {
      if (hop >= 10) throw fail(502, 'More than 10 redirects');
      u = new URL(loc, u); continue;
    }
    return { chain, status: r.status, headers: { ...r.headers, 'set-cookie': r.headers['set-cookie'] || [] }, finalUrl: u.href, bodySample: r.body, ms: Date.now() - t0 };
  }
}

/* ---------- API ---------- */
let scanning = false;
const api = {
  health: async () => ({ ok: true, version: VERSION, tools: tools() }),
  async run({ tool, target, type = 'A' }) {
    if (!ARGS[tool]) throw fail(400, 'Unknown tool. Use ping, traceroute, dig or whois.');
    if (!validTarget(target)) throw fail(400, 'Target must be a hostname or an IP address');
    if (tool === 'dig' && !DNS_TYPES.includes(type)) throw fail(400, 'Unsupported record type');
    if (!BIN[tool]) throw fail(501, `${tool} is not installed on this computer`);
    return { tool, ...(await runBin(BIN[tool], ARGS[tool](target, type), TIMEOUT[tool])) };
  },
  async scan({ target, profile, authorized }) {
    if (authorized !== true) throw fail(400, 'Port scans need authorized: true. Only scan systems you own or have written permission to test.');
    if (profile !== 'top100') throw fail(400, 'Unknown profile. Use top100.');
    if (!validTarget(target)) throw fail(400, 'Target must be a hostname or an IP address');
    if (scanning) throw fail(429, 'A scan is already running. Wait for it to finish.');
    scanning = true; const t0 = Date.now();
    try {
      if (BIN.nmap) {
        const r = await runBin(BIN.nmap, ['-sT', '-Pn', '--top-ports', '100', '-T4', '--open', target], TIMEOUT.scan);
        if (r.code !== 0) throw fail(502, `nmap failed: ${r.stderr.trim().split('\n')[0] || r.code}`);
        return { method: 'nmap', open: parseNmap(r.stdout), closed: null, filtered: null, ms: Date.now() - t0 };
      }
      const { address } = await dns.lookup(target).catch(() => { throw fail(400, `Could not resolve ${target}`); });
      const r = await tcpScan(address, TOP100);
      return { method: 'tcp-connect', ip: address, open: r.open.map(port => ({ port, service: SERVICES[port] || '' })), closed: r.closed, filtered: r.filtered, ms: Date.now() - t0 };
    } finally { scanning = false; }
  },
  http: ({ url }) => httpFetch(url),
};

/* ---------- HTTP server ---------- */
const send = (res, status, body, type = 'application/json; charset=utf-8', extra = {}) => {
  res.writeHead(status, { 'content-type': type, 'x-content-type-options': 'nosniff', ...extra });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
};
const readBody = req => new Promise((resolve, reject) => {
  let n = 0; const parts = [];
  req.on('data', c => { n += c.length; if (n > 16384) { reject(fail(413, 'Request body too large')); req.destroy(); } else parts.push(c); });
  req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(parts).toString() || '{}')); } catch { reject(fail(400, 'Body must be JSON')); } });
  req.on('error', reject);
});
const sameToken = (a, b) => typeof a === 'string' && a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));

export function createServer(port) {
  const token = crypto.randomBytes(24).toString('hex');
  const hosts = [`127.0.0.1:${port}`, `localhost:${port}`];
  return http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x'), p = url.pathname;
    let tool = '';
    res.on('finish', () => console.log(`${req.method} ${p}${tool ? ' ' + tool : ''} ${res.statusCode}`));
    if (!hosts.includes(req.headers.host)) return send(res, 403, { error: 'Bad Host header' });   // DNS rebinding

    if (p.startsWith('/api/')) {
      const name = p.slice(5);
      if (req.method !== 'POST') return send(res, 405, { error: 'POST only' });
      if (!/^application\/json\b/.test(req.headers['content-type'] || '')) return send(res, 415, { error: 'content-type must be application/json' });
      if (req.headers.origin !== `http://${req.headers.host}`) return send(res, 403, { error: 'Bad Origin' });
      if (!sameToken(req.headers['x-sentinel-token'], token)) return send(res, 401, { error: 'Bad or missing session token. Reload Sentinel from the companion.' });
      if (!Object.hasOwn(api, name)) return send(res, 404, { error: 'Unknown endpoint' });
      try { const body = await readBody(req); tool = body.tool || ''; return send(res, 200, await api[name](body)); }
      catch (e) { return send(res, e.status || 500, { error: e.status ? e.message : 'Companion error' }); }
    }

    if (req.method !== 'GET' && req.method !== 'HEAD') return send(res, 405, { error: 'GET only' });
    if (p === '/companion.js') {
      const sfs = req.headers['sec-fetch-site'];
      const js = sfs === 'same-origin' || sfs === 'none'
        ? `window.SENTINEL_COMPANION = ${JSON.stringify({ token, version: VERSION, tools: tools() })};`
        : 'window.SENTINEL_COMPANION = null;';
      return send(res, 200, js, TYPES['.js'], { 'cache-control': 'no-store' });
    }
    let segs; try { segs = decodeURIComponent(p).split('/').filter(Boolean); } catch { return send(res, 400, 'Bad path', TYPES['.txt']); }
    if (!segs.length) segs = ['index.html'];
    if (!SERVE.includes(segs[0]) || segs.some(s => s.startsWith('.') || s.includes('\\'))) return send(res, 404, 'Not found', TYPES['.txt']);
    const file = path.join(ROOT, ...segs);
    if (!file.startsWith(ROOT + path.sep)) return send(res, 404, 'Not found', TYPES['.txt']);
    fs.stat(file, (err, st) => {
      if (err || !st.isFile()) return send(res, 404, 'Not found', TYPES['.txt']);
      res.writeHead(200, { 'content-type': TYPES[path.extname(file)] || 'application/octet-stream', 'x-content-type-options': 'nosniff', 'content-length': st.size });
      if (req.method === 'HEAD') return res.end();
      fs.createReadStream(file).pipe(res);
    });
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  const i = process.argv.indexOf('--port'), port = i > 0 ? +process.argv[i + 1] : 7777;
  if (!Number.isInteger(port) || port < 1 || port > 65535) { console.error('Usage: node companion/server.mjs [--port 7777]'); process.exit(1); }
  createServer(port).listen(port, '127.0.0.1', () => {
    console.log(`Sentinel companion ${VERSION} on http://127.0.0.1:${port}`);
    console.log(`Native tools: ${Object.entries(tools()).map(([k, v]) => `${k} ${v ? 'yes' : 'no'}`).join(', ')}`);
  });
}
