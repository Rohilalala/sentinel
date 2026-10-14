/* Sentinel tool file: Forensics (File Inspector, Photo Metadata, Executable Inspector).
   Every tool reads bytes the user already has in the browser. Files are never uploaded. */
(() => {
const S = Sentinel, esc = S.esc, svg = S.svg, t = S.t, $ = S.helpers.$;
const { loading, demoButton, badge } = S.ui;

S.addIcons({ // Lucide (ISC): camera, cpu
  'd-camera': 'M14.5 4h-5L7 7H4a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2V9a2 2 0 0 0-2-2h-3zM12 10a3 3 0 1 0 0 6 3 3 0 0 0 0-6',
  'd-cpu': 'M6 4h12a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zM9 9h6v6H9zM15 2v2M15 20v2M2 15h2M2 9h2M20 15h2M20 9h2M9 2v2M9 20v2',
});
S.addTerms({
  'magic bytes': 'The first few bytes of a file, which identify its real format. Every PNG starts with 89 50 4E 47; renaming a file changes its extension, not these bytes.',
  'Shannon entropy': 'How unpredictable data is, from 0 to 8 bits per byte. Text sits around 4 to 5; compressed or encrypted data is close to 8.',
  'packed executable': 'A program that is compressed or encrypted and unpacks itself when it runs. Legitimate software does it to save space; malware does it to hide from scanners.',
  'IOC': 'Indicator of compromise: a clue such as a URL, IP address or file hash that links a file or machine to known malicious activity.',
  'VirusTotal': 'A free service that checks files against dozens of antivirus engines. Searching by hash reveals nothing new; uploading a file shares it with security companies.',
  'EXIF': 'Metadata a camera or phone writes inside a photo: the device, its settings, the date and time, and often the GPS position where it was taken.',
  'geotag': 'GPS coordinates stored in a photo\'s EXIF data. Anyone with the original file can see where it was taken.',
  'PE file': 'Portable Executable, the format of Windows programs (.exe) and libraries (.dll). It starts with the letters MZ and a header describing its sections.',
  'ELF': 'Executable and Linkable Format, the format of programs and libraries on Linux, Android and most Unix systems. It starts with the bytes 7F 45 4C 46 (".ELF").',
  'executable section': 'A named block inside a program file, such as .text for code or .data for variables. Each one is marked readable, writable and/or executable.',
  'compile timestamp': 'The build time a compiler stamps into a Windows program. Malware authors often fake it, and reproducible builds replace it with a hash.',
});

/* ---------- pure logic (tested in tests/forensics.test.mjs) ---------- */
const hex = (b, n) => [...b.subarray(0, n)].map(x => x.toString(16).padStart(2, '0')).join('');
// [hex prefixes, type, extensions ('' = no extension is normal), x = executable / z = already compressed]
const MAGIC = [
  ['4d5a', 'Windows executable (PE)', 'exe dll sys scr com cpl ocx efi drv', 'x'],
  ['7f454c46', 'Linux executable (ELF)', ' so o ko elf bin out axf run', 'x'],
  ['feedface feedfacf cefaedfe cffaedfe', 'macOS executable (Mach-O)', ' dylib bundle o', 'x'],
  ['cafebabe', 'Mach-O universal binary or Java class', ' class dylib', 'x'],
  ['504b0304 504b0506 504b0708', 'ZIP archive', 'zip jar apk aab docx xlsx pptx odt ods odp epub ipa xpi vsix whl nupkg', 'z'],
  ['25504446', 'PDF document', 'pdf', 'z'],
  ['89504e470d0a1a0a', 'PNG image', 'png', 'z'],
  ['ffd8ff', 'JPEG image', 'jpg jpeg jpe jfif', 'z'],
  ['474946383761 474946383961', 'GIF image', 'gif', 'z'],
  ['d0cf11e0a1b11ae1', 'Microsoft OLE file (old Office, MSI)', 'doc xls ppt msi msg vsd pub', ''],
  ['526172211a07', 'RAR archive', 'rar', 'z'],
  ['377abcaf271c', '7-Zip archive', '7z', 'z'],
  ['1f8b', 'GZIP archive', 'gz tgz', 'z'],
];
function sniffMagic(b) {
  const h = hex(b, 8), m = MAGIC.find(([sig]) => sig.split(' ').some(s => h.startsWith(s)));
  return m ? { type: m[1], exts: m[2].split(' '), exec: m[3] === 'x', compressed: m[3] === 'z' } : null;
}
function byteEntropy(b) {
  if (!b.length) return 0;
  const c = new Uint32Array(256); for (let i = 0; i < b.length; i++) c[b[i]]++;
  let h = 0; for (const n of c) if (n) { const p = n / b.length; h -= p * Math.log2(p); }
  return h;
}
function printableStrings(b, min = 5, limit = 20000) {
  const out = []; let s = '';
  for (let i = 0; i <= b.length && out.length < limit; i++) {
    const c = b[i];
    if ((c >= 0x20 && c < 0x7f) || c === 9) s += String.fromCharCode(c);
    else { if (s.length >= min) out.push(s); s = ''; }
  }
  return out;
}
// Limit: naive patterns; version strings like 1.0.0.0 count as IPs. Add an allow/deny list if it gets noisy.
function findIocs(strs) {
  const urls = new Set(), ips = new Set();
  for (const s of strs) {
    for (const u of s.match(/\b(?:https?|ftp):\/\/[^\s"'<>`]+/gi) || []) urls.add(u);
    for (const ip of s.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []) if (S.isIP(ip)) ips.add(ip);
  }
  return { urls: [...urls], ips: [...ips] };
}

/* EXIF: JPEG APP1 "Exif" segment → TIFF header → IFD0, Exif and GPS IFDs. Hostile input: every read is bounds-checked by DataView. */
// Limit: JPEG only. HEIC/PNG keep EXIF in other containers; add them if users bring those files.
function parseExif(b) {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let tiff = -1;
  try {
    if (dv.getUint16(0) !== 0xffd8) return null;
    for (let p = 2; p + 10 <= b.length; p += 2 + dv.getUint16(p + 2)) {
      const mk = dv.getUint16(p);
      if (mk === 0xffe1 && dv.getUint32(p + 4) === 0x45786966) { tiff = p + 10; break; } // "Exif"
      if (mk === 0xffda || mk >> 8 !== 0xff) return null; // image data started: no EXIF
    }
  } catch (e) { return null; }
  if (tiff < 0) return null;
  const le = b[tiff] === 0x49, u16 = o => dv.getUint16(tiff + o, le), u32 = o => dv.getUint32(tiff + o, le);
  const SIZE = [0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8];
  const val = (type, cnt, at) => type === 2 ? new TextDecoder().decode(b.subarray(tiff + at, tiff + at + Math.min(cnt, 256))).split('\0')[0].trim()
    : type === 3 ? u16(at) : type === 4 ? u32(at) : type === 1 ? b[tiff + at]
    : type === 5 ? Array.from({ length: Math.min(cnt, 3) }, (_, k) => u32(at + 8 * k) / (u32(at + 8 * k + 4) || 1)) : undefined;
  const ifd = off => {
    const tags = {};
    try {
      for (let i = 0, n = u16(off); i < n; i++) {
        const e = off + 2 + i * 12, type = u16(e + 2), cnt = u32(e + 4);
        try { tags[u16(e)] = val(type, cnt, (SIZE[type] || 1) * cnt > 4 ? u32(e + 8) : e + 8); } catch (x) { /* entry points outside the file: skip it */ }
      }
    } catch (x) { /* IFD offset outside the file */ }
    return tags;
  };
  const d0 = ifd(u32(4)), ex = d0[0x8769] ? ifd(d0[0x8769]) : {}, g = d0[0x8825] ? ifd(d0[0x8825]) : {};
  const dms = (v, ref) => Array.isArray(v) && v.length === 3 ? (v[0] + v[1] / 60 + v[2] / 3600) * (/^[SW]/i.test(ref || '') ? -1 : 1) : NaN;
  const lat = dms(g[2], g[1]), lon = dms(g[4], g[3]);
  const gps = Math.abs(lat) <= 90 && Math.abs(lon) <= 180 && (lat || lon)
    ? { lat, lon, alt: Array.isArray(g[6]) ? g[6][0] * (g[5] === 1 ? -1 : 1) : null } : null;
  return { make: d0[0x10f], model: d0[0x110], software: d0[0x131], orientation: d0[0x112], taken: ex[0x9003], modified: d0[0x132],
    artist: d0[0x13b], copyright: d0[0x8298], lens: ex[0xa434], serial: ex[0xa431], gps };
}

/* Executables: minimal PE (Windows) and ELF (Linux) header readers. */
const PE_MACH = { 0x14c: 'x86 (32-bit)', 0x8664: 'x86-64', 0x1c0: 'ARM', 0x1c4: 'ARM Thumb-2', 0xaa64: 'ARM64', 0x200: 'Itanium' };
const PE_SUB = { 1: 'Native (driver)', 2: 'Windows GUI', 3: 'Windows console', 10: 'EFI application', 11: 'EFI boot driver', 12: 'EFI runtime driver', 16: 'Windows boot application' };
const ELF_MACH = { 3: 'x86 (32-bit)', 62: 'x86-64', 40: 'ARM', 183: 'ARM64 (AArch64)', 243: 'RISC-V', 8: 'MIPS', 20: 'PowerPC', 21: 'PowerPC64', 22: 'IBM s390' };
const ELF_TYPE = { 1: 'Relocatable object', 2: 'Executable', 3: 'Shared library or PIE executable', 4: 'Core dump' };
const ELF_ABI = { 0: 'System V', 3: 'Linux', 6: 'Solaris', 9: 'FreeBSD', 12: 'OpenBSD' };
const PACKER = /^(UPX\d|\.aspack|\.MPRESS\d|\.petite|\.themida|\.vmp\d)$/i;
const named = (map, k) => map[k] || `Unknown (0x${k.toString(16)})`;
const iso = ts => new Date(ts * 1000).toISOString().slice(0, 19).replace('T', ' ') + ' UTC';
function parseExe(b, now = Date.now()) {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const fmt = hex(b, 2) === '4d5a' ? 'PE' : hex(b, 4) === '7f454c46' ? 'ELF' : null;
  if (!fmt) return null;
  try { return fmt === 'PE' ? readPE(dv, b, now) : readELF(dv, b); }
  catch (e) { throw new Error(e instanceof RangeError ? `The ${fmt} header points past the end of the file: it is truncated or corrupt.` : e.message); }
}
function readPE(dv, b, now) {
  const u16 = o => dv.getUint16(o, true), u32 = o => dv.getUint32(o, true), o = u32(0x3c);
  if (dv.getUint32(o) !== 0x50450000) throw new Error('This file starts with MZ but has no PE header: an old DOS program or a damaged file.');
  const n = u16(o + 6), ts = u32(o + 8), optSize = u16(o + 20), opt = o + 24, sections = [], signals = [];
  for (let i = 0; i < Math.min(n, 96); i++) { // Limit: first 96 sections (the classic Windows limit); raise if real files need more
    const s = opt + optSize + i * 40, raw = u32(s + 16), ptr = u32(s + 20), f = u32(s + 36);
    sections.push({ name: String.fromCharCode(...b.subarray(s, s + 8)).split('\0')[0], vsize: u32(s + 8), raw,
      entropy: byteEntropy(b.subarray(ptr, ptr + raw)), r: !!(f & 0x40000000), w: !!(f & 0x80000000), x: !!(f & 0x20000000) });
  }
  if (!n) signals.push(['warn', 'There is no section table: the file is hand-crafted or heavily packed.']);
  for (const s of sections) {
    if (s.w && s.x) signals.push(['bad', `Section "${s.name}" is both writable and executable. Compilers keep code read-only; unpackers and injected code need this.`]);
    if (s.entropy > 7.2) signals.push(['warn', `Section "${s.name}" has entropy ${s.entropy.toFixed(2)} of 8: its contents are likely compressed or encrypted (packed).`]);
    if (PACKER.test(s.name)) signals.push(['warn', `The section name "${s.name}" belongs to a known packer.`]);
  }
  if (ts * 1000 > now) signals.push(['warn', `The compile timestamp (${iso(ts)}) is in the future: forged, or a reproducible-build hash stored where a date should be.`]);
  return { format: 'PE', bits: u16(opt) === 0x20b ? 64 : 32, machine: named(PE_MACH, u16(o + 4)), kind: u16(o + 22) & 0x2000 ? 'Library (DLL)' : 'Program (EXE)',
    subsystem: optSize >= 70 ? named(PE_SUB, u16(opt + 68)) : 'None', timestamp: ts, entry: '0x' + (optSize >= 20 ? u32(opt + 16) : 0).toString(16), sections, signals };
}
function readELF(dv, b) {
  const is64 = b[4] === 2, le = b[5] === 1;
  return { format: 'ELF', bits: is64 ? 64 : 32, endian: le ? 'Little-endian' : 'Big-endian', abi: named(ELF_ABI, b[7]),
    kind: named(ELF_TYPE, dv.getUint16(16, le)), machine: named(ELF_MACH, dv.getUint16(18, le)),
    entry: '0x' + (is64 ? dv.getBigUint64(24, le) : dv.getUint32(24, le)).toString(16), sections: [], signals: [] };
}
Object.assign(S.lib, { sniffMagic, byteEntropy, printableStrings, findIocs, parseExif, parseExe });

/* ---------- shared UI ---------- */
const MAX = 256 << 20; // Limit: reads the whole file into memory; stream it in chunks if bigger files matter
const size = n => n < 1024 ? `${n} bytes` : `${(n / (n < 1048576 ? 1024 : 1048576)).toFixed(1)} ${n < 1048576 ? 'KB' : 'MB'} (${n.toLocaleString()} bytes)`;
const kv = rows => `<div class="kv">${rows.filter(r => r[1] != null && r[1] !== '').map(([k, v]) => `<div class="k">${k}</div><div class="v">${v}</div>`).join('')}</div>`;
const vtLink = h => `<a href="https://www.virustotal.com/gui/file/${esc(h)}" target="_blank" rel="noopener noreferrer">Look up this hash on VirusTotal</a> <span class="mut">(sends the hash only, never the file)</span>`;
const verdict = (cls, ic, big, sub) => `<div class="card verdict ${cls} full"><h2 class="big">${svg(ic)}${big}</h2><div class="sub">${sub}</div></div>`;
const record = (tool, input, out) => { const v = out.querySelector('.verdict');
  if (v) S.record({ tool, input, cls: ['danger', 'warn', 'safe'].find(c => v.classList.contains(c)) || 'info', title: v.querySelector('.big').textContent.trim().slice(0, 80) }); };

// A native file input with a visible label (keyboard and screen-reader friendly); dropping a file on the card works too.
function filePicker(mount, { tool, label, accept, run, demo }) {
  mount.innerHTML = `<div class="card drop"><div class="field"><label for="fin">${label}</label>
      <input type="file" id="fin"${accept ? ` accept="${accept}"` : ''}></div>
      <p class="mut">Or drop a file on this box. It is read here, in your browser, and never uploaded.</p></div>
    <div id="status" role="status" aria-live="polite"></div><div id="out" class="grid two"></div>`;
  const zone = $('.drop', mount), inp = $('#fin', mount), out = $('#out', mount);
  const go = async f => {
    if (!f) return;
    if (!f.size) return S.say(`${f.name} is empty (0 bytes). Choose a file with something in it.`, true);
    if (f.size > MAX) return S.say(`${f.name} is ${size(f.size)}. This tool reads files up to 256 MB; choose a smaller one.`, true);
    loading(out); S.say(`Reading ${f.name} locally…`);
    try { await run(new Uint8Array(await f.arrayBuffer()), f, out); S.say(''); record(tool, f.name, out); }
    catch (e) { out.innerHTML = ''; S.say(e.message, true); }
  };
  inp.onchange = () => go(inp.files[0]);
  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('over'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('over'));
  zone.addEventListener('drop', e => { e.preventDefault(); zone.classList.remove('over'); go(e.dataTransfer.files[0]); });
  demoButton(async () => {
    S.toast(demo.narrate); loading(out); S.say('Downloading the example file…');
    try { const r = await fetch(demo.url); if (!r.ok) throw new Error(`HTTP ${r.status}`); await go(new File([await r.blob()], demo.name)); }
    catch (e) { out.innerHTML = ''; S.say(`Couldn't download the example (${e.message}). Check your connection, or choose a file of your own.`, true); }
  });
}

/* ---------- File Inspector ---------- */
S.register({ id: 'fileinspect', name: 'File Inspector', group: 'Forensics', icon: 'file', tag: 'local',
  tile: 'Find a file\'s true type from its magic bytes, plus its hashes, entropy and hidden strings, without uploading it.',
  blurb: 'Drop any file to see what it really is, its fingerprints and the readable text inside it. The file never leaves your browser.',
  why: `A file's extension is only part of its name; its ${t('magic bytes')} say what it really is. Attackers rename programs to <i>invoice.pdf</i> and hope you double-click. ${t('hash', 'Hashes')} fingerprint the file so you can look it up on ${t('VirusTotal')} without uploading it, ${t('Shannon entropy', 'entropy')} hints at compression or encryption, and readable strings often expose URLs and IP addresses, the first ${t('IOC', 'indicators of compromise')} an analyst checks.`,
  render(mount) {
    filePicker(mount, { tool: 'fileinspect', label: 'File to inspect', run: runFile,
      demo: { url: 'icons/icon-192.png', name: 'icon-192.png', narrate: 'Inspecting Sentinel\'s own app icon: do the magic bytes agree with the .png extension?' } });
  } });
async function runFile(b, f, out) {
  const [h256, h1] = await Promise.all([S.sha('SHA-256', b), S.sha('SHA-1', b)]);
  const m = sniffMagic(b), ext = (f.name.match(/\.([^.]+)$/) || ['', ''])[1].toLowerCase(), dot = '.' + esc(ext), ent = byteEntropy(b);
  const strs = printableStrings(b.subarray(0, 16 << 20)), ioc = findIocs(strs); // Limit: strings from the first 16 MB only
  const mismatch = m && !m.exts.includes(ext), packed = ent > 7.2 && !(m && m.compressed);
  const v = m && m.exec && mismatch ? verdict('danger', 'x', `A program disguised as ${ext ? dot : 'a plain file'}`, `The ${t('magic bytes')} say this is a <b>${m.type}</b>${ext ? `, not a ${dot} file` : ''}. Opening it would run code. Don't, unless you know exactly where it came from.`)
    : mismatch ? verdict('warn', 'alert', 'Extension doesn\'t match the content', `The ${t('magic bytes')} say <b>${m.type}</b>, but the name ${ext ? `ends in ${dot}` : 'has no extension'}. Sometimes harmless (a renamed download), sometimes a trick to slip past filters.`)
    : m && m.exec ? verdict('warn', 'alert', `A real ${m.type}`, 'The name matches the content, and this is a program. Only run it if you trust where it came from, and check its hash on VirusTotal first.')
    : packed ? verdict('warn', 'alert', 'Looks packed or encrypted', `Entropy is ${ent.toFixed(2)} of 8 bits per byte, which is unusual for this kind of file. The contents may be compressed or encrypted to hide what's inside.`)
    : m ? verdict('safe', 'check', `${m.type}, as the name says`, `The ${t('magic bytes')} agree with the ${dot} extension. That says the file is what it claims to be, not that its contents are safe.`)
    : verdict('', 'info', 'No known file signature', 'Probably plain text, or a format Sentinel doesn\'t recognise. Read the strings below to see what\'s inside.');
  const iocRows = [...ioc.urls.map(u => ['URL', esc(u)]), ...ioc.ips.map(ip => ['IP address', `<a href="#/blocklist?q=${encodeURIComponent(ip)}">${esc(ip)}</a>`])];
  out.innerHTML = v + `
    <div class="card"><h2>File</h2>${kv([['Name', esc(f.name)], ['Size', size(b.length)], ['Extension', ext ? '.' + esc(ext) : '<span class="mut">none</span>'],
      [t('magic bytes', 'True type'), m ? `${esc(m.type)} ${mismatch ? badge('b-warn', 'alert', 'mismatch') : badge('b-safe', 'check', 'matches')}` : '<span class="mut">unknown</span>'],
      ['First 16 bytes', hex(b, 16).replace(/(..)(?!$)/g, '$1 ')]])}</div>
    <div class="card"><h2>Fingerprints</h2>${kv([[t('SHA-256'), h256], ['SHA-1', h1]])}<p style="margin-top:12px">${vtLink(h256)}</p></div>
    <div class="card full"><h2>${t('Shannon entropy', 'Entropy')}</h2>
      <div class="meter"><i style="width:${(ent / 8 * 100).toFixed(1)}%;background:var(${packed ? '--warn' : '--info'})"></i></div>
      <p>${ent.toFixed(2)} of 8 bits per byte ${packed ? badge('b-warn', 'alert', 'high') : badge('b-mut', 'info', 'normal for this type')}
        <span class="mut">Text sits around 4 to 5. Compressed formats (ZIP, PNG, JPEG) and encrypted data sit near 8.</span></p></div>
    <div class="card full"><h2>Readable strings <span class="mut">(${strs.length > 50 ? `first 50 of ${strs.length.toLocaleString()}` : `all ${strs.length}`}, 5+ characters)</span></h2>
      ${strs.length ? `<pre class="out-pre">${esc(strs.slice(0, 50).join('\n'))}</pre>` : '<p class="mut">No readable strings of 5 or more characters.</p>'}</div>
    <div class="card full"><h2>URLs and IP addresses in the strings</h2>
      ${iocRows.length ? `<div class="table-wrap"><table><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>${iocRows.slice(0, 100).map(([k, x]) => `<tr><td>${k}</td><td class="mono">${x}</td></tr>`).join('')}</tbody></table></div>
        <div class="note">${svg('info')}<div>A URL inside a file isn't proof of anything: installers and documents contain them too. Unknown hosts are worth checking. Click an IP to check its reputation.</div></div>`
        : '<p class="mut">None found.</p>'}</div>`;
}

/* ---------- Photo Metadata (EXIF) ---------- */
const ORIENT = { 1: 'Normal', 2: 'Mirrored', 3: 'Rotated 180°', 4: 'Mirrored and rotated 180°', 5: 'Mirrored and rotated 90°', 6: 'Rotated 90° clockwise', 7: 'Mirrored and rotated 270°', 8: 'Rotated 90° counter-clockwise' };
S.register({ id: 'exif', name: 'Photo Metadata', group: 'Forensics', icon: 'd-camera', tag: 'local',
  tile: 'Read the hidden EXIF data in a photo: camera, time and the GPS location where it was taken.',
  blurb: 'Open a JPEG photo to see what it reveals about you before you share it. Nothing is uploaded.',
  why: `Phones write ${t('EXIF')} metadata into every photo: the device, the exact time and often a ${t('geotag')} accurate to a few meters. Share the original file and anyone can see where you live, work or study. Many social networks strip it on upload, but email attachments, cloud links and files sent as documents usually keep it.`,
  render(mount) {
    // Demo photo: ianare/exif-samples (MIT). Verified 2026-10-14: HTTP 200, access-control-allow-origin: *, GPS present.
    filePicker(mount, { tool: 'exif', label: 'Photo (JPEG)', accept: 'image/jpeg', run: runExif,
      demo: { url: 'https://raw.githubusercontent.com/ianare/exif-samples/master/jpg/gps/DSCN0010.jpg', name: 'DSCN0010.jpg',
        narrate: 'Reading a public sample photo from a Nikon camera. Watch the GPS block: it pins where the picture was taken.' } });
  } });
function runExif(b, f, out) {
  const m = sniffMagic(b);
  if (!m || m.type !== 'JPEG image') throw new Error(`${f.name} is ${m ? 'a ' + m.type : 'not a JPEG'}. This tool reads JPEG photos: export or convert the photo to JPEG first, or choose another file.`);
  const x = parseExif(b), g = x && x.gps;
  const fields = x ? [['Camera make', x.make], ['Camera model', x.model], ['Lens', x.lens], ['Serial number', x.serial], ['Software', x.software],
    ['Taken', x.taken], ['Last modified', x.modified], ['Orientation', ORIENT[x.orientation]], ['Artist', x.artist], ['Copyright', x.copyright]].filter(r => r[1]) : [];
  const pos = g && `${g.lat.toFixed(5)}, ${g.lon.toFixed(5)}`;
  out.innerHTML = (g ? verdict('danger', 'alert', 'This photo reveals your location', `Its ${t('geotag')} says it was taken at <b class="mono">${pos}</b>. Anyone you send the original file to can see that spot on a map. Remove location before sharing.`)
    : fields.length ? verdict('', 'info', 'Camera details, no location', `It carries ${t('EXIF')} data (${fields.length} field${fields.length > 1 ? 's' : ''}, below) but no GPS position.`)
    : verdict('safe', 'check', 'No metadata found', `This photo has no ${t('EXIF')} block, so it reveals no camera, time or location. Many apps strip it when you share.`)) + `
    <div class="card${g ? '' : ' full'}"><h2>Camera and software</h2>${fields.length ? kv(fields.map(([k, v]) => [k, esc(v)])) : '<p class="mut">No camera fields.</p>'}</div>
    ${g ? `<div class="card"><h2>Location</h2>${kv([['Latitude', g.lat.toFixed(6)], ['Longitude', g.lon.toFixed(6)], ['Altitude', g.alt == null ? null : g.alt.toFixed(1) + ' m']])}
      <div class="bar" style="margin-top:14px"><button class="btn secondary" id="showmap">Show on map</button>
        <a class="btn secondary" href="https://www.openstreetmap.org/?mlat=${g.lat}&mlon=${g.lon}#map=16/${g.lat}/${g.lon}" target="_blank" rel="noopener noreferrer">Open in OpenStreetMap</a></div>
      <p class="mut" style="margin-top:8px">The map loads tiles for this area from OpenStreetMap; the photo itself stays here.</p></div>
      <div class="card full" id="mapcard" hidden><h2>Where it was taken</h2><div id="map"></div></div>` : ''}
    <div class="card full"><h2>Before you share a photo</h2><p>Turn off location in your camera app's settings, or remove it when sharing (iPhone: Share → Options → Location off).
      On a computer, <span class="mono">exiftool -all= photo.jpg</span> strips everything. A screenshot of a photo carries none of the original metadata.</p></div>`;
  if (g) $('#showmap', out).onclick = e => { e.currentTarget.disabled = true; showMap(g.lat, g.lon); };
}
function showMap(lat, lon) {
  const card = $('#mapcard'), el = $('#map'); card.hidden = false;
  if (typeof L === 'undefined') { el.outerHTML = '<p class="mut">The map library didn\'t load (offline?). Use the OpenStreetMap link instead.</p>'; return; }
  const bm = window.SENTINEL_BASEMAP, col = getComputedStyle(document.documentElement).getPropertyValue('--bad').trim();
  const map = L.map(el).setView([lat, lon], 15);
  L.tileLayer(bm && bm.url || 'https://tile.openstreetmap.org/{z}/{x}/{y}.png',
    { maxZoom: (bm && bm.maxZoom) || 19, subdomains: (bm && bm.subdomains) || 'abc', attribution: (bm && bm.attribution) || '© OpenStreetMap' }).addTo(map);
  L.circleMarker([lat, lon], { radius: 9, color: col, fillColor: col, fillOpacity: .4, weight: 3 }).addTo(map);
  card.scrollIntoView({ block: 'nearest' });
}

/* ---------- Executable Inspector ---------- */
S.register({ id: 'exe', name: 'Executable Inspector', group: 'Forensics', icon: 'd-cpu', tag: 'local',
  tile: 'Look inside a Windows .exe/.dll or Linux ELF program: CPU, build time, sections and red flags.',
  blurb: 'Open a program file to read its headers and spot signs of packing or tampering, without ever running it.',
  why: `Programs aren't opaque blobs. A Windows ${t('PE file')} or a Linux ${t('ELF')} file starts with a header saying which CPU it targets, when it was built and how it is laid out in ${t('executable section', 'sections')}. Malware analysts read these first: a section that is both writable and executable, very high ${t('Shannon entropy', 'entropy')} (a sign of a ${t('packed executable')}) or a ${t('compile timestamp')} in the future are classic red flags.`,
  render(mount) {
    // Demo: corkami/pocs "compiled.exe", a tiny benign 32-bit console program (Ange Albertini's PE corpus).
    // Verified 2026-10-14: HTTP 200, access-control-allow-origin: *, 2,560 bytes.
    filePicker(mount, { tool: 'exe', label: 'Program file (.exe, .dll, ELF)', run: runExe,
      demo: { url: 'https://raw.githubusercontent.com/corkami/pocs/master/PE/bin/compiled.exe', name: 'compiled.exe',
        narrate: 'Reading a tiny, harmless Windows program from a public research corpus. Nothing runs: we only read its headers.' } });
  } });
async function runExe(b, f, out) {
  const x = parseExe(b);
  if (!x) { const m = sniffMagic(b);
    throw new Error(`${f.name} ${m ? `is a ${m.type}` : 'has no PE (MZ) or ELF header'}. This tool reads Windows .exe/.dll and Linux ELF programs${m && /Mach-O/.test(m.type) ? '; macOS Mach-O files aren\'t supported yet' : ''}.`); }
  const h256 = await S.sha('SHA-256', b), bad = x.signals.filter(s => s[0] === 'bad').length, n = x.signals.length;
  const desc = `${x.format} ${x.bits}-bit ${x.machine} ${x.kind.toLowerCase()}`;
  const v = x.format === 'ELF' ? verdict('', 'info', esc(desc), `Header read. Section checks currently cover Windows ${t('PE file', 'PE files')} only, so look up the hash before running it.`)
    : bad ? verdict('danger', 'x', 'Suspicious structure', `${n} red flag${n > 1 ? 's' : ''} below. Structure alone doesn't prove malware, but don't run this until the hash checks out on ${t('VirusTotal')}.`)
    : n ? verdict('warn', 'alert', 'Worth a closer look', `${n} warning sign${n > 1 ? 's' : ''} below, often caused by a ${t('packed executable', 'packer')}. Packers are legal, but malware leans on them to hide.`)
    : verdict('safe', 'check', 'No structural red flags', `A normal-looking ${esc(desc)}. That isn't proof it's safe: check the hash on ${t('VirusTotal')} and only run software you trust.`);
  out.innerHTML = v + `
    <div class="card"><h2>Header</h2>${kv([['Format', x.format === 'PE' ? t('PE file', 'PE (Windows)') : t('ELF', 'ELF (Linux/Unix)')], ['Architecture', `${esc(x.machine)}, ${x.bits}-bit`], ['Kind', esc(x.kind)],
      ['Subsystem', x.subsystem && esc(x.subsystem)], ['Operating system ABI', x.abi && esc(x.abi)], ['Byte order', x.endian],
      [t('compile timestamp', 'Built'), x.timestamp != null ? esc(iso(x.timestamp)) : null], ['Entry point', esc(x.entry)]])}</div>
    <div class="card"><h2>Fingerprint</h2>${kv([[t('SHA-256'), h256], ['Size', size(b.length)]])}<p style="margin-top:12px">${vtLink(h256)}</p></div>
    ${x.format === 'PE' ? `<div class="card full"><h2>${t('executable section', 'Sections')} <span class="mut">(${x.sections.length})</span></h2>${x.sections.length ? `<div class="table-wrap"><table>
      <thead><tr><th>Name</th><th class="num">Virtual size</th><th class="num">Size on disk</th><th>Permissions</th><th class="num">${t('Shannon entropy', 'Entropy')}</th></tr></thead><tbody>${x.sections.map(s => `<tr>
        <td class="mono">${esc(s.name) || '<span class="mut">(blank)</span>'}</td><td class="num">${s.vsize.toLocaleString()}</td><td class="num">${s.raw.toLocaleString()}</td>
        <td class="mono">${s.r ? 'R' : '-'}${s.w ? 'W' : '-'}${s.x ? 'X' : '-'} ${s.w && s.x ? badge('b-danger', 'x', 'W+X') : ''}</td>
        <td class="num">${s.entropy.toFixed(2)} ${s.entropy > 7.2 ? badge('b-warn', 'alert', 'high') : ''}</td></tr>`).join('')}</tbody></table></div>`
      : '<p class="mut">No sections.</p>'}</div>
    <div class="card full"><h2>Red flags</h2>${n ? `<ul class="signals">${x.signals.map(([sev, txt]) => `<li>${svg(sev === 'bad' ? 'x' : 'alert')}<span>${badge(sev === 'bad' ? 'b-danger' : 'b-warn', sev === 'bad' ? 'x' : 'alert', sev === 'bad' ? 'red flag' : 'warning')} ${esc(txt)}</span></li>`).join('')}</ul>`
      : `<ul class="signals"><li>${svg('check')}<span>No writable+executable sections, no packed sections, and a build time in the past.</span></li></ul>`}</div>` : ''}`;
}

})();
