/* Sentinel tool file: Crypto lab (AES-GCM, signatures, HMAC). WebCrypto only: nothing leaves the browser. */
(() => {
const S = Sentinel, esc = S.esc, svg = S.svg, t = S.t, $ = S.helpers.$;
const { demoButton } = S.ui;
const enc = new TextEncoder(), dec = new TextDecoder();

S.addIcons({
  'c-lock': 'M6 11h12v10H6zM8 11V7a4 4 0 0 1 8 0v4',
  'c-sign': 'M3 21h18M14 4l4 4-9 9H5v-4z',
  'c-seal': 'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18M8 12l3 3 5-6',
});
S.addTerms({
  'encryption': 'Scrambling data with a key so only someone holding the key can read it. Unlike a hash, it can be reversed, but only with the key.',
  'AES-GCM': 'AES, the cipher behind HTTPS, Wi-Fi and disk encryption, in Galois/Counter Mode: it encrypts and adds a 16-byte tag that detects any change.',
  'authenticated encryption': 'Encryption that also proves the data was not changed. A wrong key or one flipped bit makes decryption fail instead of returning garbage.',
  'PBKDF2': 'Password-Based Key Derivation Function 2. It runs a hash hundreds of thousands of times to turn a passphrase into a key, so every guess costs an attacker real time.',
  'salt': 'Random bytes mixed in before hashing or deriving a key, so the same password gives a different result every time and precomputed tables are useless.',
  'IV': 'Initialization vector, also called a nonce: random bytes that make encrypting the same message twice give different output. Never reuse one with the same key.',
  'ciphertext': 'The scrambled output of encryption. Without the key it looks like random bytes.',
  'public key': 'The half of a keypair you share. Others use it to check your signatures or to encrypt messages only you can read.',
  'private key': 'The secret half of a keypair. It makes signatures, so anyone who gets it can impersonate you. It should never leave your device.',
  'digital signature': 'A value made with a private key that proves who signed a message and that it has not changed since. Anyone can check it with the public key.',
  'ECDSA': 'Elliptic Curve Digital Signature Algorithm. Small, fast keys; the P-256 curve is what most HTTPS sites use.',
  'RSA': 'The classic public-key algorithm, safe because factoring huge numbers is hard. Keys need at least 2048 bits today.',
  'PEM': 'A text wrapper for keys and certificates: Base64 between -----BEGIN …----- and -----END …----- lines.',
  'HMAC': 'Hash-based Message Authentication Code: a hash of a message mixed with a shared secret. Only someone who knows the secret can make the right tag.',
});

/* ---------- pure helpers (tested in tests/cryptolab.test.mjs) ---------- */
const b64 = u8 => { let s = ''; for (const b of u8) s += String.fromCharCode(b); return btoa(s); };
const unb64 = s => Uint8Array.from(atob(s.replace(/\s+/g, '')), c => c.charCodeAt(0));
const hex = u8 => Array.from(u8, b => b.toString(16).padStart(2, '0')).join('');

const ITER = 600000; // OWASP's figure for PBKDF2-HMAC-SHA256 (the spec floor is 210,000)
async function deriveKey(pass, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
/* blob = Base64( salt[16] ‖ iv[12] ‖ ciphertext with its 16-byte tag at the end ) */
async function aesEncrypt(text, pass) {
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, await deriveKey(pass, salt), enc.encode(text)));
  const out = new Uint8Array(28 + ct.length); out.set(salt); out.set(iv, 16); out.set(ct, 28);
  return b64(out);
}
function splitBlob(blob) {
  let u8 = null; try { u8 = unb64(blob); } catch (e) { /* not Base64 */ }
  if (!u8 || u8.length < 44) throw new Error('That isn’t an encrypted blob from this tool. Paste the whole Base64 blob, or type text and press Encrypt.');
  return { salt: u8.slice(0, 16), iv: u8.slice(16, 28), ct: u8.slice(28) };
}
async function aesDecrypt(blob, pass) {
  const { salt, iv, ct } = splitBlob(blob), key = await deriveKey(pass, salt);
  try { return dec.decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct)); }
  catch (e) { throw new Error('Decryption failed: wrong passphrase or the data was changed.'); }
}

const ALGS = {
  ecdsa: { label: 'ECDSA P-256', gen: { name: 'ECDSA', namedCurve: 'P-256' }, use: { name: 'ECDSA', hash: 'SHA-256' } },
  rsa: { label: 'RSA-PSS 2048', gen: { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, use: { name: 'RSA-PSS', saltLength: 32 } },
};
// extractable=false: the private key can sign but can never be read out. The public half is always exportable.
const makeKeypair = alg => crypto.subtle.generateKey(ALGS[alg].gen, false, ['sign', 'verify']);
async function publicKeyPem(key) {
  const der = new Uint8Array(await crypto.subtle.exportKey('spki', key));
  return `-----BEGIN PUBLIC KEY-----\n${b64(der).match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
}
const signText = async (alg, key, msg) => b64(new Uint8Array(await crypto.subtle.sign(ALGS[alg].use, key, enc.encode(msg))));
async function verifyText(alg, key, msg, sig) {
  let bytes; try { bytes = unb64(sig); } catch (e) { return false; }
  return crypto.subtle.verify(ALGS[alg].use, key, bytes, enc.encode(msg));
}
/* change one character: the first digit if there is one, else the first character */
const tamperOneChar = s => { const i = Math.max(s.search(/\d/), 0); return s.slice(0, i) + (s[i] === '9' ? '0' : String.fromCharCode(s.charCodeAt(i) + 1)) + s.slice(i + 1); };

const hmacKey = (secret, use) => crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, [use]);
const hmacSha256 = async (secret, msg) => hex(new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(secret, 'sign'), enc.encode(msg))));
// subtle.verify compares in constant time; a plain === can leak how many leading characters matched
async function hmacVerify(secret, msg, tagHex) {
  const h = tagHex.replace(/\s+/g, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(h)) throw new Error('An HMAC-SHA256 tag is 64 hex characters (0–9, a–f). Paste the whole tag.');
  return crypto.subtle.verify('HMAC', await hmacKey(secret, 'verify'), Uint8Array.from(h.match(/../g), x => parseInt(x, 16)), enc.encode(msg));
}
Object.assign(S.lib, { aesEncrypt, aesDecrypt, makeKeypair, publicKeyPem, signText, verifyText, tamperOneChar, hmacSha256, hmacVerify });

/* ---------- UI ---------- */
const STATUS = '<div id="status" role="status" aria-live="polite"></div>';
const empty = (b, s) => `<div class="card full empty"><b>${b}</b>${s}</div>`;
const verdict = (cls, icon, label, big, sub) => `<div class="card verdict ${cls} full"><h2 class="big">${svg(icon)}${big}</h2><div class="sub">${sub}</div></div>`;
const copy = s => Promise.resolve().then(() => navigator.clipboard.writeText(s)).then(() => S.toast('Copied to clipboard'), () => S.toast('Copy failed: select the text and copy it yourself'));
async function busy(btn, fn) {
  btn.disabled = true; btn.setAttribute('aria-busy', 'true'); S.say('');
  try { await fn(); }
  catch (e) { $('#out').innerHTML = ''; S.say(crypto.subtle ? e.message : 'WebCrypto is unavailable on this page. Open Sentinel over https or http://localhost.', true); }
  finally { btn.disabled = false; btn.removeAttribute('aria-busy'); }
}

const anatomy = p => `<div class="card full"><h2>Inside the blob</h2><div class="kv">
  <div class="k">${t('salt', 'Salt')}</div><div class="v">${hex(p.salt)} <span class="mut">(16 random bytes)</span></div>
  <div class="k">${t('IV')}</div><div class="v">${hex(p.iv)} <span class="mut">(12 random bytes)</span></div>
  <div class="k">${t('ciphertext', 'Ciphertext')}</div><div class="v">${p.ct.length - 16} bytes <span class="mut">(as long as the text)</span></div>
  <div class="k">Auth tag</div><div class="v">${hex(p.ct.slice(-16))} <span class="mut">(16 bytes, checked before anything is revealed)</span></div>
  <div class="k">Key</div><div class="v">${t('PBKDF2')}-SHA256, ${ITER.toLocaleString('en-US')} rounds → AES-256</div></div></div>`;

S.register({ id: 'aes', name: 'Encrypt / Decrypt', group: 'Crypto', icon: 'c-lock', tag: 'local',
  tile: 'Lock text with a passphrase using AES-256-GCM, unlock it again, and see the salt, IV and tag inside.',
  blurb: 'Encrypt a message with a passphrase and decrypt it again. Runs entirely in your browser.',
  why: `Passphrase ${t('encryption')} takes two steps. ${t('PBKDF2')} stretches your passphrase into a 256-bit key, mixing in a random ${t('salt')} so the same passphrase never gives the same key twice. Then ${t('AES-GCM')} scrambles the text with that key and a random ${t('IV')}. It is ${t('authenticated encryption')}: change one character of the ${t('ciphertext')}, or use the wrong passphrase, and decryption refuses instead of returning garbage.`,
  render(mount) {
    mount.innerHTML = `<div class="field"><label for="ain">Text to encrypt, or a blob to decrypt</label>
        <textarea id="ain" rows="4" spellcheck="false" placeholder="Type a message, or paste a blob this tool made"></textarea></div>
      <div class="field"><label for="apw">Passphrase</label><div class="bar">
        <input id="apw" type="password" autocomplete="off" placeholder="a long passphrase you share another way">
        <button class="btn secondary" id="aenc">Encrypt</button><button class="btn secondary" id="adec">Decrypt</button></div></div>
      ${STATUS}<div id="out" class="grid">${empty('Nothing encrypted yet', 'Type a message and a passphrase, then press Encrypt. Or press Run example.')}</div>`;
    const ain = $('#ain', mount), apw = $('#apw', mount), out = $('#out', mount);
    const need = what => {
      if (!ain.value.trim()) { ain.focus(); throw new Error(what === 'enc' ? 'Type a message to encrypt.' : 'Paste the blob you want to decrypt.'); }
      if (!apw.value) { apw.focus(); throw new Error('Enter a passphrase.'); }
    };
    const doEnc = () => busy($('#aenc', mount), async () => {
      need('enc'); S.say(`Stretching the passphrase (${ITER.toLocaleString('en-US')} rounds)…`);
      const blob = await aesEncrypt(ain.value, apw.value);
      out.innerHTML = verdict('safe', 'c-lock', 'Encryption', 'Encrypted with AES-256-GCM',
        'Only someone with the passphrase can read this, and any change to the blob will be detected. Send the blob any way you like; share the passphrase by a different route.')
        + `<div class="card full"><h2>Encrypted blob (Base64)</h2><pre class="out-pre">${esc(blob)}</pre>
          <div class="bar" style="margin-top:10px"><button class="btn secondary" id="acopy">Copy blob</button><button class="btn secondary" id="around">Decrypt this blob</button></div></div>`
        + anatomy(splitBlob(blob));
      $('#acopy', out).onclick = () => copy(blob);
      $('#around', out).onclick = () => { ain.value = blob; doDec(); };
      S.say('');
    });
    const doDec = () => busy($('#adec', mount), async () => {
      need('dec'); const blob = ain.value.trim(), parts = splitBlob(blob);
      S.say(`Stretching the passphrase (${ITER.toLocaleString('en-US')} rounds)…`);
      let plain = null;
      try { plain = await aesDecrypt(blob, apw.value); } catch (e) { if (!/^Decryption failed/.test(e.message)) throw e; }
      out.innerHTML = (plain === null
        ? verdict('danger', 'x', 'Decryption', 'Decryption failed',
          `Wrong passphrase, or the blob was changed. ${t('AES-GCM')} checks its tag before revealing anything, so a wrong key or one altered character gives an error, never garbage. Check the passphrase and that you copied the whole blob.`)
        : verdict('safe', 'check', 'Decryption', 'Decrypted and verified', 'The authentication tag matched: this is exactly the text that was encrypted, unchanged.')
          + `<div class="card full"><h2>Decrypted text</h2><pre class="out-pre">${esc(plain)}</pre></div>`) + anatomy(parts);
      S.say('');
    });
    $('#aenc', mount).onclick = doEnc; $('#adec', mount).onclick = doDec;
    demoButton(() => {
      ain.value = 'Meet me at the library at 6pm.'; apw.value = 'correct horse battery staple';
      S.toast('Encrypting with the passphrase “correct horse battery staple”. Then press Decrypt this blob.'); doEnc();
    });
  } });

S.register({ id: 'keys', name: 'Keys & Signatures', group: 'Crypto', icon: 'c-sign', tag: 'local',
  tile: 'Generate an ECDSA or RSA keypair, sign a message, and watch one changed character break the signature.',
  blurb: 'Make a keypair, sign a message with the private key, and verify it with the public key. Runs entirely in your browser.',
  why: `A keypair is two linked keys. The ${t('private key')} signs; the ${t('public key')} lets anyone check the signature. A ${t('digital signature')} proves who signed a message and that not one character has changed since, which is how software updates, TLS certificates and Git commits are trusted. Compare ${t('ECDSA')} P-256 (small and fast) with ${t('RSA')}-PSS 2048 (the classic). The private key is created non-exportable and disappears when you leave the page.`,
  render(mount) {
    mount.innerHTML = `<div class="field"><label for="kalg">Algorithm</label><div class="bar">
        <select id="kalg"><option value="ecdsa">ECDSA P-256 with SHA-256</option><option value="rsa">RSA-PSS 2048 with SHA-256</option></select>
        <button class="btn secondary" id="kgen">Generate keypair</button></div></div>
      <div class="field"><label for="kmsg">Message</label><textarea id="kmsg" rows="3" spellcheck="false">I, Sam, owe Alex $20.</textarea></div>
      <div class="field"><label for="ksig">Signature (Base64)</label><textarea id="ksig" rows="3" spellcheck="false" placeholder="Press Sign, or paste a signature to check"></textarea></div>
      <div class="bar"><button class="btn secondary" id="ksign">Sign</button><button class="btn secondary" id="kver">Verify</button><button class="btn secondary" id="ktam">Tamper one character</button></div>
      ${STATUS}<div id="out" class="grid">${empty('No keypair yet', 'Pick an algorithm and press Generate keypair. Or press Run example.')}</div>`;
    const sel = $('#kalg', mount), msg = $('#kmsg', mount), sig = $('#ksig', mount), out = $('#out', mount);
    let keys = null, alg = 'ecdsa', pem = '';
    const show = v => {
      out.innerHTML = v + (keys ? `<div class="card full"><h2>Your ${t('public key')} (${t('PEM')}, safe to share)</h2><pre class="out-pre">${esc(pem)}</pre>
        <div class="kv" style="margin-top:12px"><div class="k">Algorithm</div><div class="v">${ALGS[alg].label}</div>
          <div class="k">${t('private key', 'Private key')}</div><div class="v">In this tab’s memory only. Created non-exportable: it can sign, but nothing can read it out. Gone when you leave the page.</div></div></div>` : '');
    };
    const needKeys = () => { if (!keys) throw new Error('Generate a keypair first.'); };
    const gen = () => busy($('#kgen', mount), async () => {
      alg = sel.value; S.say(alg === 'rsa' ? 'Finding two large primes…' : 'Generating…');
      keys = await makeKeypair(alg); pem = await publicKeyPem(keys.publicKey); sig.value = '';
      show(verdict('', 'c-sign', 'Keypair', `New ${ALGS[alg].label} keypair`, 'The private key stays here and signs. The public key below lets anyone check those signatures. Next: press Sign.'));
      S.say('');
    });
    const sign = () => busy($('#ksign', mount), async () => {
      needKeys(); sig.value = await signText(alg, keys.privateKey, msg.value);
      show(verdict('safe', 'c-sign', 'Signature', 'Message signed',
        `A ${unb64(sig.value).length}-byte signature. Anyone with your public key can check that this exact message came from you. Sign again and the signature changes, because signing mixes in fresh randomness, yet every version verifies.`));
    });
    const check = (note = '') => busy($('#kver', mount), async () => {
      needKeys(); if (!sig.value.trim()) { sig.focus(); throw new Error('Press Sign first, or paste a signature to check.'); }
      show(await verifyText(alg, keys.publicKey, msg.value, sig.value.trim())
        ? verdict('safe', 'check', 'Signature', 'Valid signature', 'This exact message was signed by the private key that matches this public key. Not one character has changed.')
        : verdict('danger', 'x', 'Signature', 'Invalid signature', `${note}The message or signature changed after signing, or a different key signed it. Even one character breaks the match.`));
    });
    const tamper = () => {
      if (!msg.value) { msg.focus(); S.say('Type a message first.', true); return; }
      const before = msg.value; msg.value = tamperOneChar(before);
      let i = 0; while (before[i] === msg.value[i]) i++;
      return check(`Changed “${esc(before[i])}” to “${esc(msg.value[i])}”. `);
    };
    sel.onchange = () => { keys = null; sig.value = ''; out.innerHTML = empty('Algorithm changed', 'Press Generate keypair to make a new pair.'); };
    $('#kgen', mount).onclick = gen; $('#ksign', mount).onclick = sign; $('#kver', mount).onclick = () => check(); $('#ktam', mount).onclick = tamper;
    demoButton(async () => {
      sel.value = 'ecdsa'; msg.value = 'I, Sam, owe Alex $20.';
      S.toast('Generating an ECDSA P-256 keypair, signing the message and verifying it. Then press Tamper one character.');
      await gen(); await sign(); await check();
    });
  } });

S.register({ id: 'hmac', name: 'HMAC', group: 'Crypto', icon: 'c-seal', tag: 'local',
  tile: 'Compute and verify HMAC-SHA256 tags: the shared-secret check behind signed webhooks and API requests.',
  blurb: 'Tag a message with a shared secret, then verify the tag. Runs entirely in your browser.',
  why: `An ${t('HMAC')} is a ${t('hash')} of a message mixed with a secret key both sides share. A plain hash proves nothing, because anyone can compute it; an HMAC tag can only be made by someone who knows the secret. GitHub and Stripe sign every webhook this way, and the receiver recomputes the tag to reject forgeries.`,
  render(mount) {
    mount.innerHTML = `<div class="field"><label for="hmsg">Message</label><textarea id="hmsg" rows="3" spellcheck="false">{"order":1042,"amount":"20.00","status":"paid"}</textarea></div>
      <div class="field"><label for="hkey">Shared secret key</label><input id="hkey" type="text" autocomplete="off" spellcheck="false" placeholder="a secret both sides know"></div>
      <div class="field"><label for="htag">Tag to verify <span class="mut">(optional)</span></label><input id="htag" type="text" autocomplete="off" spellcheck="false" placeholder="64 hex characters"></div>
      <div class="bar"><button class="btn secondary" id="hcomp">Compute tag</button><button class="btn secondary" id="hver">Verify tag</button></div>
      ${STATUS}<div id="out" class="grid">${empty('No tag yet', 'Enter a message and a secret key, then press Compute tag. Or press Run example.')}</div>`;
    const msg = $('#hmsg', mount), key = $('#hkey', mount), tagIn = $('#htag', mount), out = $('#out', mount);
    const needKey = () => { if (!key.value) { key.focus(); throw new Error('Enter a secret key: an HMAC needs one.'); } };
    const cards = async () => `<div class="card full"><h2>HMAC-SHA256 tag</h2><pre class="out-pre">${await hmacSha256(key.value, msg.value)}</pre></div>
      <div class="card full"><h2>Compare: plain SHA-256 of the message, no key</h2><pre class="out-pre">${await S.sha('SHA-256', msg.value)}</pre>
        <p class="mut" style="margin-top:8px;font-size:var(--text-sm)">Anyone can compute this one, so it proves nothing about who sent the message. The HMAC above needs the secret.</p></div>`;
    const compute = () => busy($('#hcomp', mount), async () => {
      needKey();
      out.innerHTML = verdict('', 'c-seal', 'HMAC', 'Tag computed', 'Send this tag with the message. The receiver recomputes it with the same secret; if one character differs, the tags won’t match.') + await cards();
    });
    const verify = () => busy($('#hver', mount), async () => {
      needKey(); if (!tagIn.value.trim()) { tagIn.focus(); throw new Error('Paste the tag you received into “Tag to verify”, or press Compute tag first.'); }
      out.innerHTML = (await hmacVerify(key.value, msg.value, tagIn.value)
        ? verdict('safe', 'check', 'HMAC', 'Tag matches: authentic', 'Whoever made this tag knew the secret, and the message has not changed since.')
        : verdict('danger', 'x', 'HMAC', 'Tag doesn’t match', 'The message changed, the secret is different, or the tag was forged. Reject the message.')) + await cards();
    });
    $('#hcomp', mount).onclick = compute; $('#hver', mount).onclick = verify;
    demoButton(async () => {
      msg.value = '{"order":1042,"amount":"20.00","status":"paid"}'; key.value = 'demo shared secret';
      S.toast('Computed the tag, then verified it. Now change one character of the message and press Verify tag.');
      tagIn.value = await hmacSha256(key.value, msg.value); await verify();
    });
  } });
})();
