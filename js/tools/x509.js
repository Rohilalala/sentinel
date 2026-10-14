/* Sentinel tool file: Certificate Decoder. Own minimal DER/ASN.1 walker; nothing leaves the browser. */
(() => {
const S = Sentinel, esc = S.esc, svg = S.svg, t = S.t, $ = S.helpers.$;
const { demoButton } = S.ui;
const dec = new TextDecoder();

S.addTerms({
  'X.509': 'The standard format for TLS certificates: who the certificate is for, who signed it, when it is valid, and its public key.',
  'certificate authority': 'An organization, like Let’s Encrypt, that browsers trust to sign certificates after checking you control a domain. Often shortened to CA.',
  'root certificate': 'A certificate authority’s top certificate. It signs itself and is trusted because it ships pre-installed in your operating system or browser.',
  'self-signed': 'Signed by its own key instead of by a certificate authority. Normal for root certificates; on a website it makes browsers show a warning.',
  'SAN': 'Subject Alternative Name: the list of domain names a certificate is valid for. Browsers check this list, not the Common Name.',
  'Common Name': 'CN: the main name in a certificate’s subject, such as ISRG Root X1. For websites, browsers now rely on the SAN list instead.',
  'DER': 'Distinguished Encoding Rules: the strict binary form certificates are stored in, a nested tag-length-value structure (ASN.1). PEM is DER in Base64.',
});

const OIDS = {
  '2.5.4.3': 'CN', '2.5.4.10': 'O', '2.5.4.11': 'OU', '2.5.4.6': 'C', '2.5.4.8': 'ST', '2.5.4.7': 'L', '2.5.4.5': 'serialNumber', '1.2.840.113549.1.9.1': 'email',
  '1.2.840.113549.1.1.1': 'RSA', '1.2.840.113549.1.1.10': 'RSA-PSS', '1.2.840.10045.2.1': 'EC', '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448',
  '1.2.840.10045.3.1.7': 'P-256', '1.3.132.0.34': 'P-384', '1.3.132.0.35': 'P-521',
  '1.2.840.113549.1.1.4': 'MD5 with RSA', '1.2.840.113549.1.1.5': 'SHA-1 with RSA', '1.2.840.113549.1.1.11': 'SHA-256 with RSA',
  '1.2.840.113549.1.1.12': 'SHA-384 with RSA', '1.2.840.113549.1.1.13': 'SHA-512 with RSA', '1.2.840.10045.4.1': 'ECDSA with SHA-1',
  '1.2.840.10045.4.3.2': 'ECDSA with SHA-256', '1.2.840.10045.4.3.3': 'ECDSA with SHA-384', '1.2.840.10045.4.3.4': 'ECDSA with SHA-512',
};

/* DER: every value is tag, length, bytes. Constructed values (SEQUENCE, SET, [n]) contain more of them. */
function tlv(u8, pos) {
  let len = u8[pos + 1], off = pos + 2;
  if (len > 0x80) { const n = len & 0x7f; len = 0; for (let i = 0; i < n; i++) len = len * 256 + u8[off++]; }
  if (len === 0x80 || !(off + len <= u8.length)) throw new Error('bad DER');
  return { tag: u8[pos], start: pos, off, end: off + len };
}
const kids = (u8, n) => { const a = []; for (let p = n.off; p < n.end; p = a[a.length - 1].end) a.push(tlv(u8, p)); return a; };
const val = (u8, n) => u8.subarray(n.off, n.end);
function oid(b) { const a = [Math.floor(b[0] / 40), b[0] % 40]; let v = 0; for (const x of b.subarray(1)) { v = v * 128 + (x & 127); if (x < 128) { a.push(v); v = 0; } } return a.join('.'); }
const named = (u8, n) => { const o = oid(val(u8, n)); return OIDS[o] || o; };
// Limit: strings decode as UTF-8; legacy BMPString/T61String names render garbled, decode them by tag if real certs need it
function dn(u8, n) {
  const o = {};
  for (const set of kids(u8, n)) for (const atv of kids(u8, set)) {
    const [k, v] = kids(u8, atv), key = named(u8, k), s = dec.decode(val(u8, v));
    o[key] = o[key] ? o[key] + ', ' + s : s;
  }
  return o;
}
function time(u8, n) {
  const m = dec.decode(val(u8, n)).match(/^(\d\d|\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)Z$/);
  if (!m) throw new Error('bad time');
  const y = m[1].length === 2 ? (+m[1] < 50 ? 2000 : 1900) + +m[1] : +m[1]; // UTCTime: 50–99 means 19xx (RFC 5280)
  return new Date(Date.UTC(y, m[2] - 1, m[3], m[4], m[5], m[6]));
}

function parseCert(text) {
  text = String(text);
  if (/PRIVATE KEY/.test(text)) throw new Error('That is a private key, not a certificate. Never paste a private key into any website. Sentinel did not read it.');
  const m = text.match(/-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/);
  let u8 = null; try { u8 = Uint8Array.from(atob((m ? m[1] : text).replace(/\s+/g, '')), c => c.charCodeAt(0)); } catch (e) { /* not Base64 */ }
  if (!u8 || u8[0] !== 0x30) throw new Error('That doesn’t look like a certificate. Paste the whole PEM block, from -----BEGIN CERTIFICATE----- to -----END CERTIFICATE-----.');
  try {
    const [tbs, sigAlg] = kids(u8, tlv(u8, 0)), f = kids(u8, tbs), v3 = f[0].tag === 0xa0; // [0] version is absent on v1 certificates
    const [serialN, , issuerN, validity, subjectN, spki, ...rest] = f.slice(v3 ? 1 : 0);
    const [nb, na] = kids(u8, validity), [keyAlgN, keyBits] = kids(u8, spki), [keyOid, keyParam] = kids(u8, keyAlgN);
    const keyAlg = named(u8, keyOid);
    let keySize = '';
    if (keyAlg === 'RSA' || keyAlg === 'RSA-PSS') { // BIT STRING = 1 unused-bits byte, then RSAPublicKey { modulus, exponent }
      const mod = val(u8, kids(u8, tlv(u8, keyBits.off + 1))[0]), i = mod[0] ? 0 : 1;
      keySize = (mod.length - i - 1) * 8 + Math.floor(Math.log2(mod[i])) + 1 + '-bit';
    } else if (keyParam && keyParam.tag === 6) keySize = named(u8, keyParam);
    const exts = {}, x = rest.find(n => n.tag === 0xa3);
    if (x) for (const e of kids(u8, kids(u8, x)[0])) { const p = kids(u8, e); exts[oid(val(u8, p[0]))] = tlv(u8, p[p.length - 1].off); } // extnValue is an OCTET STRING wrapping more DER
    const bc = exts['2.5.29.19'] ? kids(u8, exts['2.5.29.19']) : [];
    let serial = val(u8, serialN); if (serial.length > 1 && serial[0] === 0) serial = serial.subarray(1);
    const raw = n => u8.subarray(n.start, n.end).join();
    return {
      version: v3 ? val(u8, kids(u8, f[0])[0])[0] + 1 : 1,
      serial: Array.from(serial, b => b.toString(16).padStart(2, '0')).join(':'),
      subject: dn(u8, subjectN), issuer: dn(u8, issuerN), notBefore: time(u8, nb), notAfter: time(u8, na),
      san: exts['2.5.29.17'] ? kids(u8, exts['2.5.29.17']).filter(g => g.tag === 0x82).map(g => dec.decode(val(u8, g))) : [], // [2] dNSName only
      keyAlg, keySize, sigAlg: named(u8, kids(u8, sigAlg)[0]),
      // Limit: issuer == subject by name only; proving the self-signature needs WebCrypto import + DER-to-raw ECDSA conversion
      selfSigned: raw(subjectN) === raw(issuerN),
      isCA: bc[0] && bc[0].tag === 1 ? u8[bc[0].off] !== 0 : false,
    };
  } catch (e) { throw new Error('Couldn’t read this certificate: the data looks cut off or isn’t X.509. Copy the whole PEM block again.'); }
}
function certStatus(c, now = Date.now()) {
  const days = Math.floor((c.notAfter - now) / 864e5);
  const kind = now < c.notBefore ? 'future' : days < 0 ? 'expired' : days < 30 ? 'expiring' : c.selfSigned ? (c.isCA ? 'root' : 'self') : 'valid';
  return { kind, days, cls: { future: 'warn', expired: 'danger', expiring: 'warn', root: '', self: 'warn', valid: 'safe' }[kind] };
}
Object.assign(S.lib, { parseCert, certStatus });

/* ---------- UI ---------- */
const ISRG = `-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----`;
const ndays = n => `${Math.abs(n).toLocaleString('en-US')} day${Math.abs(n) === 1 ? '' : 's'}`;
const day = d => d.toISOString().slice(0, 10), stamp = d => d.toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
const LABEL = { CN: t('Common Name', 'Common Name (CN)'), O: 'Organization (O)', OU: 'Unit (OU)', C: 'Country (C)', ST: 'State (ST)', L: 'Locality (L)' };
const nameKv = o => Object.entries(o).map(([k, v]) => `<div class="k">${LABEL[k] || esc(k)}</div><div class="v">${esc(v)}</div>`).join('') || '<div class="k">Name</div><div class="v mut">empty</div>';

function renderCert(c, now = Date.now()) {
  const s = certStatus(c, now), on = day(c.notAfter);
  const [icon, big, sub] = {
    future: ['alert', 'Not valid yet', `It only becomes valid on ${day(c.notBefore)}. Until then browsers reject it, so check the server’s clock.`],
    expired: ['x', `Expired ${ndays(s.days)} ago`, `It stopped being valid on ${on}. Browsers block sites that use it; the owner has to renew it.`],
    expiring: ['alert', `Expires in ${ndays(s.days)}`, `Valid until ${on}. Renew it now: most certificate outages are simply missed renewals.`],
    root: ['cert', 'Self-signed root certificate', `Valid until ${on}. Roots are ${t('self-signed')} by design: nothing sits above them. A ${t('root certificate')} is trusted because your operating system or browser ships it pre-installed, not because of its signature.`],
    self: ['alert', 'Self-signed certificate', `Valid until ${on}, but no ${t('certificate authority')} vouches for it, so browsers will show a warning. Fine for testing; public sites need a CA-signed certificate.`],
    valid: ['check', `Valid for ${ndays(s.days)} more`, `Signed by ${esc(c.issuer.O || c.issuer.CN || 'an unnamed issuer')}, valid until ${on}. Your browser still checks the chain of signatures up to a trusted root.`],
  }[s.kind];
  const life = c.notAfter - c.notBefore, pct = Math.min(100, Math.max(0, (now - c.notBefore) / life * 100));
  const color = { safe: 'var(--ok)', warn: 'var(--warn)', danger: 'var(--bad)' }[s.cls] || 'var(--info)';
  const weak = [/MD5|SHA-1/.test(c.sigAlg) && 'Weak signature algorithm: SHA-1 and MD5 signatures can be forged, and browsers stopped accepting them years ago.',
    /^RSA/.test(c.keyAlg) && parseInt(c.keySize) < 2048 && 'Short RSA key: under 2048 bits can be factored with enough computing power.'].filter(Boolean);
  return `<div class="card verdict ${s.cls} full"><h2 class="big">${svg(icon)}${big}</h2><div class="sub">${sub}</div></div>
    <div class="card"><h2>Subject: who it is for</h2><div class="kv">${nameKv(c.subject)}</div></div>
    <div class="card"><h2>Issuer: who signed it</h2><div class="kv">${nameKv(c.issuer)}</div></div>
    <div class="card full"><h2>Validity</h2>
      <div class="meter" role="img" aria-label="${Math.round(pct)}% of the validity period has passed"><i style="width:${pct.toFixed(1)}%;background:${color}"></i></div>
      <div class="kv"><div class="k">Not before</div><div class="v">${stamp(c.notBefore)}</div><div class="k">Not after</div><div class="v">${stamp(c.notAfter)}</div>
        <div class="k">Lifetime</div><div class="v">${ndays(Math.round(life / 864e5))}, ${Math.round(pct)}% used, ${s.days >= 0 ? ndays(s.days) + ' left' : 'expired'}</div></div></div>
    <div class="card"><h2>Key and signature</h2><div class="kv">
      <div class="k">${t('public key', 'Public key')}</div><div class="v">${esc(c.keyAlg)} ${esc(c.keySize)}</div>
      <div class="k">Signature</div><div class="v">${esc(c.sigAlg)}</div>
      <div class="k">Serial number</div><div class="v">${esc(c.serial)}</div>
      <div class="k">Version</div><div class="v">v${c.version}</div>
      <div class="k">CA certificate</div><div class="v">${c.isCA ? 'Yes: it can sign other certificates' : 'No'}</div></div>
      ${weak.map(w => `<div class="note warn">${svg('alert')}<div><b>Warning.</b> ${w}</div></div>`).join('')}</div>
    <div class="card"><h2>Names it covers (${t('SAN')})</h2>${c.san.length
      ? `<div class="bar">${c.san.map(n => `<span class="badge b-mut">${esc(n)}</span>`).join('')}</div>`
      : `<p class="mut">None. ${c.isCA ? 'CA certificates don’t name websites; they sign the certificates that do.' : 'Browsers will reject it for every website.'}</p>`}</div>`;
}

S.register({ id: 'certdecode', name: 'Certificate Decoder', group: 'Crypto', icon: 'cert', tag: 'local',
  tile: 'Paste a PEM certificate to read who it is for, who signed it, the names it covers and when it expires.',
  blurb: 'Decode a PEM certificate: subject, issuer, validity, covered names, key and signature. Runs entirely in your browser.',
  why: `A ${t('TLS certificate')} is an ${t('X.509')} document: a subject (who it is for), an issuer (the ${t('certificate authority')} that signed it), a validity window, the ${t('SAN')} list of names it covers, and a ${t('public key')}. It is stored as ${t('DER')} binary and pasted as ${t('PEM')} text. This decoder walks the DER bytes itself, so you can see there is no magic inside.`,
  render(mount) {
    mount.innerHTML = `<div class="field"><label for="pem">PEM certificate</label>
        <textarea id="pem" rows="8" spellcheck="false" placeholder="-----BEGIN CERTIFICATE-----&#10;MIIF…&#10;-----END CERTIFICATE-----"></textarea></div>
      <p class="mut" style="font-size:var(--text-sm)">Get one from any site: click the padlock in your browser and export the certificate, or run <code>openssl s_client -connect example.com:443 -showcerts</code>.</p>
      <div id="status" role="status" aria-live="polite"></div><div id="out" class="grid two"></div>`;
    const ta = $('#pem', mount), out = $('#out', mount);
    const run = () => {
      S.say('');
      if (!ta.value.trim()) { out.innerHTML = '<div class="card full empty"><b>Paste a certificate to decode it</b>Or press Run example to decode Let’s Encrypt’s root certificate.</div>'; return; }
      try { out.innerHTML = renderCert(parseCert(ta.value)); } catch (e) { out.innerHTML = ''; S.say(e.message, true); }
    };
    ta.addEventListener('input', run); run();
    demoButton(() => { ta.value = ISRG; run(); S.toast('Decoding ISRG Root X1, the Let’s Encrypt root that browsers trust. Roots sign themselves, by design.'); });
  } });
})();
