/* Sentinel tool file: Password Generator and Hash Identifier. Randomness comes from crypto.getRandomValues only. */
(() => {
const S = Sentinel, esc = S.esc, svg = S.svg, t = S.t, $ = S.helpers.$;
const { searchTool, demoButton } = S.ui;

S.addIcons({
  'c-dice': 'M5 3h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2zM8 8h.01M16 8h.01M12 12h.01M8 16h.01M16 16h.01',
  'c-hash': 'M5 9h14M5 15h14M10 3L8 21M16 3l-2 18',
});
S.addTerms({
  'entropy': 'How unpredictable a secret is, measured in bits. Each extra bit doubles the number of guesses an attacker needs.',
  'passphrase': 'A password made of several random words. Easy to remember and type, and hard to guess when the words are picked at random.',
  'rejection sampling': 'Throwing away random draws that would land unevenly and drawing again, so every outcome is exactly equally likely.',
  'modulo bias': 'A subtle flaw: squeezing a random number into a range with % makes some results slightly more likely than others.',
  'bcrypt': 'A password hash from 1999 with a cost factor: each +1 doubles the work, so it stays slow as computers get faster.',
  'Argon2': 'The winner of the 2015 Password Hashing Competition. Slow and memory-hungry on purpose, which blunts cracking on graphics cards.',
  'MD5': 'An old 128-bit hash. Broken for security and far too fast for passwords, but still common as a file checksum.',
  'NTLM': 'The hash Windows uses for account passwords: one unsalted MD4 pass, so it cracks very fast.',
});

/* ---------- pure helpers (tested in tests/cryptolab.test.mjs) ---------- */
/* Uniform integer in [0, n). Plain x % n favors small results whenever n doesn't divide 2^32 (modulo bias),
   so draws at or above the last whole multiple of n are thrown away and redrawn (rejection sampling). */
function secureRandInt(n, next = () => crypto.getRandomValues(new Uint32Array(1))[0]) {
  const limit = 2 ** 32 - (2 ** 32 % n);
  for (;;) { const x = next(); if (x < limit) return x % n; }
}
const makePassword = (len, pool) => Array.from({ length: len }, () => pool[secureRandInt(pool.length)]).join('');
const makePassphrase = (words, count) => Array.from({ length: count }, () => words[secureRandInt(words.length)]).join('-');
// a word line is five dice digits, a tab, then the word; the license header lines don't match
const parseEffWordlist = txt => txt.split('\n').map(l => l.match(/^[1-6]{5}\t(\S+)/)).filter(Boolean).map(m => m[1]);
const plural = (v, unit) => { const r = Math.round(v); return `${r.toLocaleString('en-US')} ${unit}${r === 1 ? '' : 's'}`; };
function crackTimeText(bits) {
  let v = 2 ** (bits - 1) / 1e11; // on average half the space is searched; 1e11 guesses/s is one high-end GPU against MD5
  if (v < 1) return 'under a second';
  for (const [unit, next] of [['second', 60], ['minute', 60], ['hour', 24], ['day', 365]]) { if (v < next) return plural(v, unit); v /= next; }
  return v >= 1.38e10 ? 'longer than the age of the universe' : plural(v, 'year');
}

const HASHES = [
  { re: /^\$2[abxy]?\$(\d\d)\$[./A-Za-z0-9]{53}$/, name: 'bcrypt', kind: 'slow', detail: m => `cost ${+m[1]}: 2^${+m[1]} = ${(2 ** m[1]).toLocaleString('en-US')} rounds` },
  { re: /^\$argon2(id|i|d)\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$/, name: 'Argon2', kind: 'slow', detail: m => `Argon2${m[1]}: ${(+m[2]).toLocaleString('en-US')} KiB of memory, ${m[3]} passes, ${m[4]} lanes` },
  { re: /^\$6\$(?:rounds=(\d+)\$)?[^$]{1,16}\$[./A-Za-z0-9]{86}$/, name: 'sha512crypt', kind: 'slow', detail: m => `${(+m[1] || 5000).toLocaleString('en-US')} rounds of SHA-512` },
  { re: /^\$1\$[^$]{0,8}\$[./A-Za-z0-9]{22}$/, name: 'md5crypt', kind: 'legacy', detail: () => '1,000 rounds of MD5' },
  { re: /^pbkdf2_sha256\$(\d+)\$[^$]+\$[A-Za-z0-9+/]+=*$/, name: 'Django PBKDF2-SHA256', kind: 'slow', detail: m => `${(+m[1]).toLocaleString('en-US')} iterations` },
  { re: /^eyJ[\w-]*\.[\w-]*\.[\w-]*$/, name: 'JWT', kind: 'token' },
  { re: /^[a-f0-9]{32}$/i, name: 'MD5 or NTLM', kind: 'fast', alt: 'MD4, LM' },
  { re: /^[a-f0-9]{40}$/i, name: 'SHA-1', kind: 'fast', alt: 'RIPEMD-160' },
  { re: /^[a-f0-9]{64}$/i, name: 'SHA-256', kind: 'fast', alt: 'SHA3-256, BLAKE2s' },
  { re: /^[a-f0-9]{128}$/i, name: 'SHA-512', kind: 'fast', alt: 'SHA3-512, Whirlpool' },
];
function identifyHash(s) {
  s = String(s).trim();
  for (const h of HASHES) { const m = s.match(h.re); if (m) return { name: h.name, kind: h.kind, alt: h.alt || '', detail: h.detail ? h.detail(m) : '' }; }
  return null;
}
Object.assign(S.lib, { secureRandInt, makePassword, makePassphrase, parseEffWordlist, crackTimeText, identifyHash });

/* ---------- Password Generator ---------- */
const SETS = { 'a–z': 'abcdefghijklmnopqrstuvwxyz', 'A–Z': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', '0–9': '0123456789', 'Symbols': '!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~' };
let wordsP = null;
const loadWords = () => wordsP || (wordsP = fetch('data/eff_large_wordlist.txt')
  .then(r => { if (!r.ok) throw new Error(); return r.text(); }).then(parseEffWordlist)
  .then(w => { if (w.length !== 7776) throw new Error(); return w; })
  .catch(() => { wordsP = null; throw new Error('Couldn’t load the word list (data/eff_large_wordlist.txt). Serve Sentinel over http, for example with python3 -m http.server, and try again. Or pick Random characters.'); }));
const grade = bits => bits >= 100 ? ['safe', 'check', 'Very strong'] : bits >= 64 ? ['safe', 'check', 'Strong'] : bits >= 45 ? ['warn', 'alert', 'Fair'] : ['danger', 'x', 'Weak'];
const copy = s => Promise.resolve().then(() => navigator.clipboard.writeText(s)).then(() => S.toast('Copied to clipboard'), () => S.toast('Copy failed: select the text and copy it yourself'));

S.register({ id: 'passgen', name: 'Password Generator', group: 'Credentials', icon: 'c-dice', tag: 'local',
  tile: 'Generate random passwords or EFF word passphrases, with their entropy and how long cracking would take.',
  blurb: 'Generate a truly random password or passphrase and see exactly how strong it is. Runs entirely in your browser.',
  why: `Strength comes from ${t('entropy')}, not cleverness: how many equally likely options the generator could have picked. Every character or word here comes from <code>crypto.getRandomValues</code>, with ${t('rejection sampling')} to avoid ${t('modulo bias')}. A ${t('passphrase')} of six random words from the EFF list carries about 77 bits, enough to defeat offline cracking, and is far easier to remember than random symbols.`,
  render(mount) {
    mount.innerHTML = `<div class="grid two" style="margin-top:0">
        <div class="field"><label for="pmode">Kind</label><select id="pmode"><option value="words">Passphrase (random words)</option><option value="chars">Random characters</option></select></div>
        <div class="field"><label for="pn" id="pnl">Number of words</label><input id="pn" type="text" inputmode="numeric" autocomplete="off" value="6"></div></div>
      <div id="psets" hidden><fieldset class="field" style="border:0;padding:0;margin:0 0 8px">
        <legend style="font-size:var(--text-sm);font-weight:600;padding:0;margin-bottom:6px">Characters to use</legend>
        <div class="bar">${Object.keys(SETS).map(k => `<label style="display:inline-flex;align-items:center;gap:6px;min-height:32px"><input type="checkbox" value="${k}" checked>${k}</label>`).join('')}</div></fieldset></div>
      <div class="bar"><button class="btn secondary" id="pgo">Generate</button></div>
      <p class="mut" style="font-size:var(--text-sm);margin-top:10px">Passphrase words come from the <a href="https://www.eff.org/dice" target="_blank" rel="noopener">EFF Large Wordlist</a> by the Electronic Frontier Foundation, licensed <a href="https://creativecommons.org/licenses/by/3.0/us/" target="_blank" rel="noopener">CC BY 3.0 US</a>.</p>
      <div id="status" role="status" aria-live="polite"></div>
      <div id="out" class="grid"><div class="card full empty"><b>Nothing generated yet</b>Pick a kind and press Generate. Or press Run example.</div></div>`;
    const mode = $('#pmode', mount), pn = $('#pn', mount), go = $('#pgo', mount), out = $('#out', mount);
    mode.onchange = () => { const w = mode.value === 'words'; $('#pnl', mount).textContent = w ? 'Number of words' : 'Length'; pn.value = w ? 6 : 20; $('#psets', mount).hidden = w; };
    const gen = async () => {
      go.disabled = true; go.setAttribute('aria-busy', 'true'); S.say('');
      try {
        const words = mode.value === 'words', n = Number(pn.value), [lo, hi] = words ? [2, 12] : [4, 128];
        if (!(Number.isInteger(n) && n >= lo && n <= hi)) { pn.focus(); throw new Error(`Choose ${words ? 'a number of words' : 'a length'} from ${lo} to ${hi}.`); }
        let pw, pool, unit;
        if (words) { S.say('Loading the word list…'); const w = await loadWords(); pw = makePassphrase(w, n); pool = w.length; unit = 'words'; }
        else {
          const chars = [...mount.querySelectorAll('#psets input:checked')].map(i => SETS[i.value]).join('');
          if (!chars) throw new Error('Tick at least one set of characters.');
          // Limit: uniform over the pool, so a ticked set can be missing by chance; force one of each if sites keep rejecting
          pw = makePassword(n, chars); pool = chars.length; unit = 'characters';
        }
        const per = Math.log2(pool), bits = n * per, [cls, icon, word] = grade(bits);
        out.innerHTML = `<div class="card verdict ${cls} full"><h2 class="big">${svg(icon)}${word}: ${Math.round(bits)} bits of entropy</h2>
            <div class="sub">At 100 billion guesses a second (one high-end graphics card against a fast hash like ${t('MD5')}), finding it would take ${crackTimeText(bits)} on average.
              ${bits < 64 ? `Add more ${unit} to get past 64 bits.` : `A slow password hash like ${t('bcrypt')} on the server stretches that much further.`}</div></div>
          <div class="card full"><h2>Your ${words ? 'passphrase' : 'password'}</h2><pre class="out-pre" style="font-size:var(--text-xl)">${esc(pw)}</pre>
            <div class="bar" style="margin-top:10px"><button class="btn secondary" id="pcopy">Copy</button><button class="btn secondary" id="pagain">Generate another</button></div></div>
          <div class="card full"><h2>How the ${t('entropy')} adds up</h2><div class="kv">
            <div class="k">Choices per pick</div><div class="v">${pool.toLocaleString('en-US')} ${unit}</div>
            <div class="k">Bits per pick</div><div class="v">log2(${pool.toLocaleString('en-US')}) = ${per.toFixed(2)}</div>
            <div class="k">Total</div><div class="v">${n} × ${per.toFixed(2)} = ${bits.toFixed(1)} bits</div></div>
            <p class="mut" style="margin-top:10px;font-size:var(--text-sm)">The math only holds because every pick is truly random and equally likely. A password you invent yourself has far less entropy than its length suggests, because people choose predictably.</p></div>`;
        $('#pcopy', out).onclick = () => copy(pw); $('#pagain', out).onclick = gen;
        S.say('');
      } catch (e) { out.innerHTML = ''; S.say(e.message, true); }
      finally { go.disabled = false; go.removeAttribute('aria-busy'); }
    };
    go.onclick = gen;
    pn.addEventListener('keydown', e => { if (e.key === 'Enter') gen(); });
    demoButton(() => { mode.value = 'words'; mode.onchange(); S.toast('Picking 6 random words from the 7,776-word EFF list: about 77 bits.'); gen(); });
  } });

/* ---------- Hash Identifier ---------- */
const BCRYPT_DEMO = '$2y$12$CqWpfYGmS8l3dhc7GtMdu.11jj0OES2P8BqnvHNIbCLOjAA7ax7ki'; // bcrypt of "correct horse battery staple", made with htpasswd -B
const KIND = { slow: 'Password hash', legacy: 'Old password hash', fast: 'Fast hash', token: 'Signed token' };
function renderHash(v) {
  const h = identifyHash(v);
  const [cls, icon, big, sub] = !h
    ? ['', 'info', 'Unknown format', 'Not a format this tool knows. Check for spaces or line breaks copied by accident, and that the whole value is there.']
    : {
      slow: ['safe', 'check', `${h.name}: a password hash`, `Built for storing passwords: salted, so identical passwords hash differently, and deliberately slow, so every guess costs an attacker real time.`],
      legacy: ['warn', 'alert', `${h.name}: an outdated password hash`, 'Salted, but only 1,000 rounds of fast MD5, so modern graphics cards crack it quickly. Rehash with bcrypt or Argon2 the next time each user logs in.'],
      fast: ['warn', 'alert', `Looks like ${h.name}`, 'A fast hash. Fine as a file checksum, but if it stores a password, one graphics card tests billions of guesses a second and lookup tables crack common passwords instantly.'],
      token: ['', 'info', 'A JWT, not a hash', `A signed token (header.payload.signature) whose payload anyone can read. Decode it in <a href="#/toolkit">Hash &amp; Encode</a>.`],
    }[h.kind];
  return `<div class="card verdict ${cls} full"><h2 class="big">${svg(icon)}${esc(big)}</h2><div class="sub">${sub}</div></div>
    <div class="card"><h2>Details</h2><div class="kv">
      <div class="k">Format</div><div class="v">${h ? esc(h.name) : 'unknown'}</div>
      <div class="k">Kind</div><div class="v">${h ? KIND[h.kind] : '—'}</div>
      <div class="k">Length</div><div class="v">${v.length} characters</div>
      ${h && h.detail ? `<div class="k">Settings</div><div class="v">${esc(h.detail)}</div>` : ''}
      ${h && h.alt ? `<div class="k">Could also be</div><div class="v">${esc(h.alt)}</div>` : ''}</div></div>
    <div class="card"><h2>Fast hashes vs password hashes</h2><ul class="signals">
      <li>${svg('x')}<span>${t('MD5')}, ${t('NTLM')}, SHA-1, SHA-256: built for speed. No salt, so one precomputed table cracks every user who shares a password.</span></li>
      <li>${svg('check')}<span>${t('bcrypt')}, ${t('Argon2')}, PBKDF2: a per-user ${t('salt')} and a tunable cost, so each guess takes real time.</span></li>
      <li>${svg('info')}<span>The format gives away the length, not the algorithm: 32 hex characters could be MD5, NTLM or MD4.</span></li></ul></div>`;
}

S.register({ id: 'hashid', name: 'Hash Identifier', group: 'Credentials', icon: 'c-hash', tag: 'local',
  tile: 'Paste a hash to learn what made it (MD5, SHA, bcrypt, Argon2…) and whether it is safe for passwords.',
  blurb: 'Identify a hash from its format, and learn whether it is fit for storing passwords. Runs entirely in your browser.',
  why: `Stolen password databases hold hashes, not passwords, and the format tells you how much trouble the attacker is in. Fast hashes like ${t('MD5')}, SHA-1 and ${t('SHA-256')} were built for speed: a graphics card tries billions per second. ${t('bcrypt')}, ${t('Argon2')} and PBKDF2 were built for passwords: salted and deliberately slow, so each guess costs real time. Same-length hex hashes, like MD5 and ${t('NTLM')}, can’t be told apart by format alone.`,
  render(mount) {
    searchTool(mount, { label: 'Hash', secret: true, placeholder: '$2b$12$… or 5f4dcc3b…', cta: 'Identify',
      examples: ['5f4dcc3b5aa765d61d8327deb882cf99', '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8'],
      demo: { input: BCRYPT_DEMO, narrate: 'Identifying a real bcrypt hash: $2y$ names the algorithm and 12 is the cost factor.' },
      run: async (v, out) => { out.innerHTML = renderHash(v); } });
  } });
})();
