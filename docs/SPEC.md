# Sentinel — Build Specification

> This is the single source of truth for building Sentinel end to end. Read it top
> to bottom before touching code. When this file and your instincts disagree, this file wins; when this
> file and `PRODUCT.md` disagree on product truth, `PRODUCT.md` wins.

---

## 0. What you are building

**Sentinel** is an all-in-one cybersecurity console for beginners and CS students.
It gathers the scattered security toolbox (recon, routing, DNS, certificates,
reputation, credentials, crypto, forensics, privacy, native network tools) into one
app where **every tool runs on real, live data and explains itself while it runs**.

- Every jargon term is a hover/tap glossary definition.
- Every tool has a one-click **Run example** on real data with a plain-English verdict.
- No login, no API keys, no backend for the web tier.
- Installable as a PWA. A local **companion** (one Node file, zero dependencies) adds
  native tools a browser cannot run: ping, traceroute, port scan, dig, whois, and
  server-side HTTP fetches (header grading, tech detection, link unshortening).

Read these before writing code:

| File | What it owns |
|---|---|
| `PRODUCT.md` | Users, purpose, positioning, pinned brand commitments. Product truth. |
| `DESIGN.md` | The built visual system (written from the finished build). |
| `docs/SPEC.md` | This file: architecture, contracts, catalog, process. |
| `docs/TUTORIALS.md` | Narration scripts per tool (record your own walkthrough videos). |

---

## 1. Non-negotiables

### 1.1 Pinned product decisions (do not relitigate)

- **Shell layout is pinned** to the Remotify admin structure: 56px top bar (wordmark,
  centered tool search, theme switch), grouped collapsible left sidebar with tags,
  breadcrumbs, a heading + primary-action row, KPI cards on Home. **No Remotify colors.**
- **Cleanliness bar is pinned** to cal.com, Linear and Vercel. Clean SaaS console,
  played straight. Convention is the commitment; no smuggled quirks.
- **Three themes**: light (default), dark, and an opt-in **Hacker Mode**.
- **Must never read as**: a generic SaaS template, cold corporate enterprise software,
  or a hacker-movie terminal (outside Hacker Mode).

### 1.2 Safety rules (product + legal)

- Recon is **passive and read-only by default**: it reads public records only.
- **Active** tools (port scans) run **only** through the companion, **only** after the
  user ticks "I own this target or have written permission to test it", and the
  companion re-checks that flag server-side.
- Offensive frameworks (Metasploit, Sliver, BeEF, Cobalt Strike, Hydra…) are
  **explained and linked in the Tool Library, never embedded or wrapped**.
- Passwords never leave the browser (HIBP k-anonymity sends 5 hash characters).
- No user data in URLs or query strings except the lookup target itself.

### 1.3 Code rules

- Vanilla HTML/CSS/JS. No framework, no bundler, no build step for the app.
- Third-party runtime libraries only when hand-rolling is unreasonable, and then
  **vendored** into `vendor/` with license and a pinned version (offline PWA), or CDN
  with a **computed** SRI hash (`curl -s URL | openssl dgst -sha512 -binary | openssl base64 -A`).
  Never type an SRI hash from memory.
- Every dynamic string inserted into HTML goes through `S.esc()`. Only static author
  copy (`blurb`, `why`) may contain raw HTML.
- No raw colors, radii or fonts in components. Use tokens from `css/tokens.css`.
- Non-trivial pure logic leaves **one runnable check**: put the function on
  `Sentinel.lib` and test it in `tests/<bundle>.test.mjs`.
- Git identity: `Aditya <205600203+Rohilalala@users.noreply.github.com>`.

---

## 2. Architecture

```
sentinel/
├─ index.html              shell: top bar, sidebar, main; loads css + js in order
├─ manifest.webmanifest    PWA manifest
├─ sw.js                   service worker: stale-while-revalidate for same-origin files
├─ companion.js            static stub: window.SENTINEL_COMPANION = null
├─ config.js               optional basemap tile URL (keyless OSM by default)
├─ icons/                  icon.svg, icon-192.png, icon-512.png, icon-maskable-512.png
├─ css/
│  ├─ tokens.css           ALL design tokens; [data-theme=light|dark|hacker]
│  └─ app.css              shell + components (tokens only)
├─ js/
│  ├─ core.js              Sentinel namespace: registry, router, shell, API, teaching layer, history
│  ├─ glossary.js          base glossary terms
│  ├─ home.js              Home: KPIs from history, recent checks, grouped tool list
│  └─ tools/<bundle>.js    one file per tool bundle; each registers its own tools, icons, terms
├─ data/                   static datasets (ATT&CK, Tool Library, wordlists) with licenses
├─ vendor/                 pinned third-party libraries, if any, with LICENSE files
├─ companion/server.mjs    zero-dependency Node companion (native tools)
├─ scripts/                one-off data builders (e.g. build-attack.mjs)
├─ tests/                  node:test files; _load.mjs loads the real browser files
└─ docs/                   SPEC.md, TUTORIALS.md
```

### 2.1 Load order (index.html)

`config.js` → `companion.js` → `js/core.js` → `js/glossary.js` → `js/tools/*.js` → `js/home.js` → `Sentinel.start()`.
Registration order inside a sidebar group = script order.

### 2.2 How a page renders

`location.hash` → `route()` → Home or `toolShell(mod)` (breadcrumb, H1, lede,
hidden **Run example** button, "What this is and why it matters" disclosure) →
`mod.render(mount)`. Route change closes the mobile drawer, hides tooltips, sets the
document title and moves focus to the H1.

### 2.3 Core API (`Sentinel`, aliased `S`)

| API | Use |
|---|---|
| `S.register(mod)` | Register a tool. Fields below. |
| `S.addIcons({name: 'svg path d'})` | Add icons from your own file (24×24 grid, 1.6 stroke, round caps). Lucide paths (ISC) are fine. |
| `S.addTerms({term: 'definition'})` | Add glossary terms from your own file. |
| `S.t(term, label?)` | Inline glossary term (dashed underline, hover/tap/focus shows definition). |
| `S.svg(name, cls='ico')` | Inline icon. |
| `S.esc(str)` | HTML-escape. Mandatory for dynamic data. |
| `S.ui.searchTool(mount, cfg)` | Standard input → run → results scaffold. Returns `{q, out, run}`. |
| `S.ui.loading(out)` | Skeleton placeholder. |
| `S.ui.badge(cls, icon, text)` | Badge. `cls`: `b-safe` `b-warn` `b-danger` `b-info` `b-mut`. |
| `S.ui.demoButton(fn)` | Show the header **Run example** for custom (non-searchTool) UIs. |
| `S.say(msg, isErr?)` | Status line under the input (`role=status`). |
| `S.toast(msg)` | Transient narration toast (used by Run example). |
| `S.api.*` | `jget, doh, prefixOverview, rpki, lookingGlass, asOverview, announced, geo, rdapDomain, rdapIp, certspotter, hibpRange, resolveA`. |
| `S.isIP`, `S.isASN`, `S.cleanHost`, `S.sha(algo, strOrBytes)` | Helpers. |
| `S.native(path, body)` | POST to the companion with the session token. Throws a helpful error when not running. |
| `S.companion()` | `null` or `{token, tools}` when served by the companion. |
| `S.record({tool, input, cls, title})` | Add to local check history. `searchTool` does this automatically when a `.verdict` card renders. |
| `S.lib` | Put pure, testable functions here. |
| `#/<id>?q=<value>` | Deep link: opens a `searchTool` tool and runs it on `value` (e.g. `#/cve?q=CVE-2021-44228`). Use it to link one tool's result into another. `native` tools, and every tool while the companion runs, only prefill: a link alone never makes the companion act. |

**`S.register(mod)` fields**

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | URL slug, unique (`#/<id>`). |
| `name` | yes | Sidebar + H1 label. Short. |
| `group` | yes | One of `Learn, Recon, Threat intel, Web & email, Credentials, Crypto, Forensics, Privacy, Native, Reference`. |
| `icon` | yes | Icon name (core or added via `addIcons`). |
| `blurb` | yes | One-sentence lede under the H1. |
| `tile` | yes | One-line description for Home lists. |
| `why` | yes | "What this is and why it matters": 2–4 sentences, glossary terms via `t()`. |
| `tag` | no | `'live'` (default; queries the network), `'local'` (never leaves the browser), `'native'` (needs the companion), `''` (none). |
| `render(mount)` | yes | Builds the tool UI inside `mount`. |

**`S.ui.searchTool(mount, cfg)` config**

| Key | Meaning |
|---|---|
| `label` | Visible input label (required for accessibility; defaults to "Target"). |
| `placeholder` | Example format, never the only label. |
| `type` | `'password'` for secrets (history stores `••••••`). |
| `secret` | `true` = keep the input visible but store `••••••` in history (hashes, tokens). |
| `cta` | Submit button text (default "Check"). |
| `examples` | Array shown as "Try:" links. |
| `demo` | `{input, narrate}` — powers the header **Run example** and its toast. |
| `wide` | `true` = single-column results. Default two columns. |
| `run(value, out)` | Async. Render into `out`. Throw or `S.say(msg, true)` on errors. |

### 2.4 Result markup contract

Every tool's first result is a **verdict card**. `searchTool` reads it to record history.

```html
<div class="card verdict safe|warn|danger full">
  <h2>Verdict</h2>                       <!-- renders as a colored status pill -->
  <div class="big">${svg('check')}Plain-English headline</div>
  <div class="sub">One or two sentences: what it means and what to do.</div>
</div>
```

Then detail cards: `.card` (+ `.full` to span), `<h2>` label, `.kv` key/value grid,
`<div class="table-wrap"><table>`, `ul.signals`, `.note`, `.out-pre` for raw output,
`.meter > i` for bars. Never color alone: every state pairs color with an icon and a word.

### 2.5 Tool file template

```js
/* Sentinel tool file: <Bundle name>. */
(() => {
const S = Sentinel, api = S.api, esc = S.esc, svg = S.svg, t = S.t;
const { searchTool, loading, demoButton, badge } = S.ui;

S.addTerms({ 'example term': 'Plain-English definition a first-year student understands.' });

function pureLogic(x) { /* no DOM, no network */ }
S.lib.pureLogic = pureLogic;

S.register({ id: 'example', name: 'Example', group: 'Recon', icon: 'globe',
  tile: 'One line for the Home list.',
  blurb: 'One sentence lede.',
  why: `Why it matters, with ${t('example term')} defined inline.`,
  render(mount) {
    searchTool(mount, { label: 'Domain', placeholder: 'example.com', examples: ['github.com'],
      demo: { input: 'github.com', narrate: 'What the Run example is doing, in one line.' },
      run: async (v, out) => {
        loading(out); S.say('Looking up…');
        const data = await api.jget(`https://…${encodeURIComponent(v)}`);
        out.innerHTML = `<div class="card verdict safe full"><h2>Verdict</h2><div class="big">${svg('check')}${esc(data.x)}</div>
          <div class="sub">…</div></div>`;
        S.say('');
      } });
  } });
})();
```

---

## 3. Design system and UI process

### 3.1 The committed world

- **THESIS:** the cal.com / Linear / Vercel console played straight for learning
  security on live data. Refuses the generic dashboard look (gradient hero, icon-tile
  grid, Inter).
- **OWN-WORLD:** white ground, ink `#0a0a0a`, neutral grays, **black primary buttons**,
  1px hairlines, 8px controls / 12px cards, native system UI stack plus system mono,
  color only for verdicts. Dark: neutral `#0a0a0a`. Hacker Mode: `#050505` + phosphor
  `#33ff00`, all mono, square corners, `[ BRACKET ]` buttons, faint scanlines,
  blinking cursor on the H1.
- **FIRST VIEWPORT:** 56px top bar; 240px grouped sidebar; main: breadcrumb, H1 + lede
  left, black **Run example** right; the verdict card leads results.

### 3.2 Tokens

All in `css/tokens.css`: `--bg --surface --surface-2 --surface-3 --border
--border-strong --fg --fg-2 --muted --primary --primary-hover --primary-fg --ring`,
semantic `--ok/--ok-bg --warn/--warn-bg --bad/--bad-bg --info/--info-bg`,
`--font-ui --font-mono`, `--text-xs…--text-3xl`, `--r-ctl --r-card`, `--ease --dur`.
Hacker Mode is square everywhere via one scoped rule.

### 3.3 Craft floor (hard rules)

- **Banned:** an eyebrow/kicker above a heading; gradient text; colored
  `border-left`/`border-right` above 1px on cards, notes or alerts; same-size
  icon+heading+text card grids as page structure; glass/blur as decoration; hard
  offset shadows; monospace as a costume (mono is for code, data and measurement only;
  Hacker Mode is the explicit exception); emoji or Unicode glyphs as icons.
- **Theme the browser surfaces:** `::selection`, caret, scrollbars, focus rings,
  underline offset, tabular numerals. Already done globally; don't regress it.
- **States:** every interactive element has hover, focus-visible, active, disabled and
  loading (`aria-busy`). Every tool has empty, loading, error and success states.
  Errors name the problem and the recovery.
- **Copy:** controls name their action ("Check", "Generate", "Decode"). Plain
  language. No hype.

### 3.4 Accessibility (WCAG 2.2 AA, all three themes)

Visible labels on every input (`<label for>`), keyboard operable everything (Enter
submits), visible focus, ≥4.5:1 text contrast, ≥24px targets (≥44px on touch),
`aria-live` status, focus moves to H1 on route change, `prefers-reduced-motion`
honored, color never the only signal.

### 3.5 How to fix or extend UI

1. Read PRODUCT.md and DESIGN.md first; the built world is the reference.
2. **Extending a surface** (new tool, new card): inherit the world. Use existing
   classes; add CSS only if a genuinely new component is needed, in `css/app.css`,
   tokens only.
3. Check accessibility, touch targets and performance before delivery (section 3.4).
4. Inspect once in a batched round: desktop (1440) and mobile (390), light, dark and
   Hacker Mode. Fix everything in one batch, confirm once more, stop.
5. Update DESIGN.md when the visual system changes.

---

## 4. API verification protocol (do this before building any live tool)

Browsers block cross-origin responses without CORS headers. Before writing a tool:

```bash
curl -s -D - -o /tmp/body "<endpoint with a real example>" | grep -iE 'HTTP/|access-control-allow-origin'
head -c 600 /tmp/body
```

- `access-control-allow-origin: *` (or your origin) and a 200 → build it client-side.
- No CORS header → route it through the companion (`/api/http`) and tag the tool
  `native`, or drop it. Never ship a tool that fails in the browser.
- Record the verified response shape in a comment above the fetcher.

**Known results (verified 2026-10-13/14):**

| Source | Status |
|---|---|
| Cloudflare DoH `cloudflare-dns.com/dns-query` (JSON) | ✅ CORS |
| RIPEstat `stat.ripe.net/data/*` | ✅ |
| RDAP `rdap.org/domain|ip/*` (redirects; final server has CORS) | ✅ |
| certspotter `api.certspotter.com/v1/issuances` | ✅ (crt.sh returned 502) |
| HIBP Pwned Passwords range API | ✅ |
| ipwho.is | ✅ (ipapi.co is rate-limited/paid) |
| DNSBLs via DoH: barracuda, spamcop, uceprotect, dronebl | ✅ |
| Spamhaus zen via public DoH | ❌ returns 127.255.255.254 for everything (blocked) |
| allorigins `api.allorigins.win/raw?url=` (text proxy) | ✅ |
| Mozilla HTTP Observatory v2 | ❌ async scan, no result within 20s |
| Carto basemaps | ❌ now require a key; use OSM tiles |

---

## 5. Tool catalog (build all of it)

Legend for **Status**: ✔ built · ▢ to build. **Tag**: live / local / native.
Bundle = the file it lives in.

**Build status (2026-10-14):** every tool in 5.2–5.7 is built (45 registered tools), except:
- **Scanner Check** (5.2): dropped. GreyNoise's community API answers any request that carries an
  `Origin` header with 403 and no CORS header, so it can never work from a browser.
- **Tool Library** and **Practice Labs** (5.7): not built.
- **Security Headers (live)** (5.7) lives in `js/tools/webtools.js` next to the Header Analyzer grader it shares.
- **OWASP Top 10** (5.3) uses the 2025 edition, final as of this build, instead of 2021.
- **URL Inspector** is `#/urlinspect`; all other ids are as registered in each bundle file.

### 5.1 Already built (keep working; regressions are failures)

| Tool | Bundle | Group | Tag | Source |
|---|---|---|---|---|
| Guided Recon (5-step mission) | learn.js | Learn | — | DoH, RDAP, certspotter, RIPEstat, DNSBL |
| How it works (5 animated explainers) | learn.js | Learn | — | static SVG |
| Routing & RPKI (+ ASN mode, live AS paths, map) | routing.js | Recon | live | RIPEstat, DoH, ipwho.is, Leaflet+OSM |
| DNS & Email (records, DNSSEC, SPF/DMARC) | dns.js | Recon | live | DoH |
| Domain / IP Intel (RDAP) | whois.js | Recon | live | RDAP |
| Cert Transparency (subdomains) | ct.js | Recon | live | certspotter |
| IP Reputation (4 DNSBLs) | reputation.js | Threat intel | live | DoH |
| Typosquat Finder | typosquat.js | Web & email | live | DoH |
| Email Headers analyzer | email.js | Web & email | local | — |
| Site Files (robots.txt, security.txt) | sitefiles.js | Web & email | live | allorigins |
| Password Exposure (k-anonymity) | credentials.js | Credentials | live | HIBP |
| Hash & Encode (SHA, Base64, hex, URL, ROT13, CIDR, JWT) | crypto.js | Crypto | local | WebCrypto |

### 5.2 Bundle A — DNS+ and passive intel (`js/tools/dnsplus.js`, `js/tools/intel.js`)

| ▢ Tool | Group | Tag | Spec |
|---|---|---|---|
| **Reverse DNS** | Recon | live | IPv4 → `d.c.b.a.in-addr.arpa` PTR via DoH. Verdict: has PTR / none. Teach: PTR, forward-confirmed reverse DNS (resolve the PTR name back and compare). |
| **DNS Propagation** | Recon | live | Query the same name/type from Cloudflare DoH and Google DoH (`dns.google/resolve`, verify CORS). Table per resolver: answers, TTL, DNSSEC AD. Verdict: consistent / differs (explain caching + TTL). Types: A, AAAA, MX, NS, TXT, CNAME. |
| **Email Auth Deep Check** | Web & email | live | DKIM: probe common selectors (`google, selector1, selector2, k1, default, s1, s2, mail, dkim`) at `<sel>._domainkey.<domain>` TXT; parse `p=` key length estimate. MTA-STS: `_mta-sts.<domain>` TXT. TLS-RPT: `_smtp._tls.<domain>`. BIMI: `default._bimi.<domain>`. Verdict grades the stack. |
| **Exposed Services** | Threat intel | live | Shodan InternetDB `https://internetdb.shodan.io/<ip>` (keyless; verify CORS). Show open ports, hostnames, CPEs, tags, CVEs (link each CVE to the CVE tool). Verdict: none known / N open ports / known CVEs. Passive: reads Shodan's existing scan, never scans. |
| **Scanner Check** | Threat intel | live | GreyNoise community `https://api.greynoise.io/v3/community/<ip>` (verify CORS + keyless). "Is this IP a mass internet scanner or a benign service?" If CORS fails, drop it and say so in the report. |

### 5.3 Bundle B — Vulnerabilities and reference (`js/tools/vuln.js`, `js/tools/reference.js`, `scripts/build-attack.mjs`, `data/attack.json`)

| ▢ Tool | Group | Tag | Spec |
|---|---|---|---|
| **CVE Lookup** | Threat intel | live | Input `CVE-YYYY-NNNN`. NVD API 2.0 `services.nvd.nist.gov/rest/json/cves/2.0?cveId=` (verify CORS; keyless rate limit 5 req/30s) for description, CVSS v3.1 base score/vector, CWE, references, dates. EPSS `api.first.org/data/v1/epss?cve=` for exploit probability + percentile. CISA KEV from the GitHub mirror (`raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json`, cache in memory) → "known exploited in the wild" + due date. Verdict: severity × exploited. Explain CVSS vector components in plain English. |
| **Package Vulns** | Threat intel | live | OSV.dev `POST https://api.osv.dev/v1/query` `{package:{name, ecosystem}, version}` (verify CORS). Ecosystems: npm, PyPI, Go, Maven, crates.io, RubyGems. List advisories with severity, fixed versions. Verdict: N known vulns / clean. |
| **MITRE ATT&CK** | Reference | — | `scripts/build-attack.mjs` downloads MITRE CTI `enterprise-attack.json`, writes compact `data/attack.json` `[{id, name, tactics[], desc (first sentence, ≤240 chars), url, sub (bool)}]`. UI: search box + tactic filter + result list; click → detail with link to attack.mitre.org. Include the MITRE copyright/permission notice. |
| **OWASP Top 10** | Reference | — | 2021 list, one card per risk: **own-words** explanation (OWASP text is CC BY-SA; do not copy it), a beginner example, how to spot it, link to owasp.org. |

### 5.4 Bundle C — Crypto lab and credentials (`js/tools/cryptolab.js`, `js/tools/x509.js`, `js/tools/passgen.js`, `data/eff_large_wordlist.txt`)

| ▢ Tool | Group | Tag | Spec |
|---|---|---|---|
| **Encrypt / Decrypt (AES-GCM)** | Crypto | local | Passphrase → PBKDF2-SHA256 (≥210,000 iterations, random 16-byte salt) → AES-256-GCM with random 12-byte IV. Output one Base64 blob `salt‖iv‖ciphertext`. Decrypt reverses it; wrong passphrase → clear error. Explain salt, IV, authenticated encryption. |
| **Keys & Signatures** | Crypto | local | Generate ECDSA P-256 and RSA-PSS 2048 keypairs (WebCrypto), export public key as PEM, sign a message, verify a signature (tamper one character → shows invalid). Explain public vs private keys. Never persist private keys. |
| **HMAC** | Crypto | local | HMAC-SHA256 of message + secret; verify mode. Explain message authentication. |
| **Certificate Decoder** | Crypto | local | Paste a PEM certificate. Minimal DER/ASN.1 walker (`S.lib.parseCert`) extracting subject CN/O, issuer CN/O, serial, notBefore/notAfter, SAN DNS names, public key algorithm, signature algorithm (OID → name map). Validity drawn as a proportional bar with days remaining. Verdict: valid / expiring <30d / expired / self-signed. Test against a real public certificate PEM fixture (e.g. ISRG Root X1) in `tests/`. |
| **Password Generator** | Credentials | local | `crypto.getRandomValues` only. Random mode (length, character sets, unbiased via rejection sampling) and passphrase mode (EFF large wordlist, 7,776 words, CC BY 3.0 US, attribution in the UI and file header). Show entropy in bits and the crack-time framing. |
| **Hash Identifier** | Credentials | local | Guess hash type from format: MD5/NTLM (32 hex), SHA-1 (40), SHA-256 (64), SHA-512 (128), bcrypt `$2[aby]$`, Argon2 `$argon2id$`, sha512crypt `$6$`, md5crypt `$1$`, Django `pbkdf2_sha256$`, JWT. Explain why bcrypt/Argon2 are for passwords and SHA is not. |

### 5.5 Bundle D — Forensics and code security (`js/tools/forensics.js`, `js/tools/codesec.js`)

| ▢ Tool | Group | Tag | Spec |
|---|---|---|---|
| **File Inspector** | Forensics | local | Drop any file (stays in the browser). SHA-256 + SHA-1, size, true type from **magic bytes** vs the extension (mismatch = warning; PE/ELF/Mach-O/ZIP/PDF/PNG/JPEG/GIF/OLE/RAR/7z/GZIP), Shannon entropy (>7.2 bits/byte suggests packed/encrypted), first 50 printable strings ≥5 chars, URLs/IPs found in strings. Link SHA-256 to VirusTotal search (link only, no upload). |
| **Photo Metadata (EXIF)** | Forensics | local | JPEG EXIF parser (`S.lib.parseExif`, own minimal TIFF/IFD walker): camera make/model, software, timestamps, **GPS** (convert DMS → decimal, show on map), orientation. Verdict: "This photo reveals your location" when GPS present. Teach: strip metadata before sharing. |
| **Executable Inspector** | Forensics | local | Minimal PE parser: MZ → PE header → machine, timestamp, subsystem, number of sections, section table (name, size, entropy), suspicious signs (writable+executable sections, high entropy, timestamp in the future). ELF basic header too. |
| **Secrets Scanner** | Forensics | local | Paste code/config. Regex rules with names + severity: AWS access key `AKIA[0-9A-Z]{16}`, GitHub tokens `gh[pousr]_…`, Slack `xox[baprs]-`, Stripe `sk_live_`, Google API `AIza…`, private key blocks, JWTs, generic `password=`/`secret=` assignments, plus high-entropy string detection. Output line numbers with the secret **masked**. Teach rotation + git history. |
| **IAM Policy Analyzer** | Forensics | local | Paste an AWS IAM policy JSON. Flag `Action: "*"`, `Resource: "*"`, `NotAction`, `iam:PassRole` with `*`, `s3:*` on `*`, missing `Condition` on sensitive actions, `Principal: "*"` in resource policies. Verdict + plain-English fix per finding. |

### 5.6 Bundle E — Privacy and web (`js/tools/privacy.js`, `js/tools/webtools.js`)

| ▢ Tool | Group | Tag | Spec |
|---|---|---|---|
| **What Sites See** | Privacy | live | Your public IP + network + city (ipwho.is self lookup), user agent parsed, languages, timezone, screen, Do-Not-Track, cookies enabled, touch support. Teach: every site sees this without asking. |
| **WebRTC Leak Test** | Privacy | local | `RTCPeerConnection` with a public STUN server; collect ICE candidates; show host (mDNS-masked or local IP), server-reflexive (public IP). Verdict: leak if a non-mDNS private IP or a public IP differing from your HTTP IP (VPN leak). |
| **Browser Fingerprint** | Privacy | local | Combine canvas hash, WebGL vendor/renderer, fonts available (measure a fixed list), screen, timezone, languages, hardware concurrency, device memory into a SHA-256 fingerprint; show each component's contribution. Honest framing: an estimate, not a global uniqueness claim. |
| **CSP Evaluator** | Web & email | local | Paste a Content-Security-Policy. Parse directives; flag `'unsafe-inline'`, `'unsafe-eval'`, `*`, `data:`/`blob:` in `script-src`, missing `object-src 'none'`, missing `base-uri`, missing `frame-ancestors`, no nonces/hashes with `strict-dynamic`. Grade A–F with fixes. |
| **Header Analyzer** | Web & email | local | Paste raw HTTP response headers (or, when the companion runs, fetch a URL). Grade HSTS (max-age ≥ 1 year, includeSubDomains, preload), CSP (reuse the evaluator), X-Frame-Options / frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/COEP/CORP, cookie flags (Secure, HttpOnly, SameSite). Grade A–F. |
| **URL Inspector** | Web & email | local | Parse a URL into parts; **defang/refang** (`hxxps://example[.]com`); decode percent-encoding; detect IDN/punycode and **homographs** (mixed scripts, e.g. Cyrillic `а` in `аpple.com`) using `URL` to get the punycode form; flag `@` userinfo tricks and IP-literal hosts. |

### 5.7 Bundle F — Companion, native tools, Tool Library (`companion/server.mjs`, `js/tools/native.js`, `js/tools/library.js`, `data/library.json`)

| ▢ Tool | Group | Tag | Spec |
|---|---|---|---|
| **Ping** | Native | native | Companion `/api/run {tool:'ping', target}` → `ping -c 4`. Parse min/avg/max/loss. |
| **Traceroute** | Native | native | `traceroute -m 20 -w 2 -q 1` (or `tracert` on Windows). Parse hops; draw latency bars at true length. |
| **Port Scan** | Native | native | Companion `/api/scan {target, profile:'top100', authorized:true}`. Uses `nmap -sT -Pn --top-ports 100 -T4 --open` when installed, otherwise a built-in Node TCP-connect scanner (top 100 ports, concurrency 64, 800ms timeout). Requires the authorization checkbox. Teach: open/closed/filtered, why scanning others is illegal; suggest `scanme.nmap.org` (Nmap's sanctioned test host). |
| **DNS (dig)** | Native | native | `dig +noall +answer <name> <type>`; side-by-side with the browser DoH answer. |
| **WHOIS (CLI)** | Native | native | `whois <domain>`; raw text, compare to RDAP. |
| **Security Headers (live)** | Native | native | Companion `/api/http {url}` fetches server-side; feeds the Header Analyzer grader. |
| **Tech Detector** | Native | native | Same fetch; match a small signature set (server/x-powered-by headers, cookies, meta generator, script paths: WordPress, Drupal, Joomla, Shopify, Next.js, Nuxt, React, Vue, Angular, jQuery, Cloudflare, nginx, Apache, IIS, Express, PHP, Laravel, Django, Rails). |
| **Link Unshortener** | Native | native | `/api/http` with manual redirects; show every hop and the final URL before you click. |
| **Tool Library** | Reference | — | `data/library.json`: ~45 desktop/CLI tools (nmap, masscan, Wireshark, tcpdump, Zeek, Suricata, Burp Suite, OWASP ZAP, Nikto, Nuclei, sqlmap, ffuf, gobuster, Metasploit, Hashcat, John the Ripper, Hydra, Aircrack-ng, Kismet, Bettercap, Ghidra, radare2, x64dbg, Volatility, Autopsy, Sleuth Kit, YARA, binwalk, ExifTool, Maltego, SpiderFoot, theHarvester, Amass, Subfinder, Trivy, Semgrep, gitleaks, TruffleHog, Prowler, ScoutSuite, Tor Browser, KeePassXC, VeraCrypt, MobSF, Frida, GoPhish, Garak). Each: `{name, category, what, why, install:{mac, linux, windows}, homepage, practice:[{name,url}], offensive:bool}`. Own-words descriptions. Offensive tools carry a legal note. Searchable, filterable by category. |
| **Practice Labs** | Reference | — | Directory: TryHackMe, HackTheBox, PortSwigger Web Security Academy, OverTheWire, picoCTF, CyberDefenders, LetsDefend, Root-Me, PentesterLab, VulnHub, OWASP Juice Shop, DVWA. Each: what it teaches, cost, best first room/level. |

---

## 6. The companion (`companion/server.mjs`)

Run: `node companion/server.mjs [--port 7777]` → open `http://127.0.0.1:7777`.
It **serves the app itself** (same origin, so no CORS) and adds `/api/*`.

### 6.1 Security model (never simplify any of this away)

1. **Bind `127.0.0.1` only.** Never `0.0.0.0`.
2. **Host check:** reject any request whose `Host` is not `127.0.0.1:<port>` or
   `localhost:<port>` (defeats DNS rebinding).
3. **Origin check:** every `/api/*` request must carry `Origin` equal to the app origin.
4. **Session token:** `crypto.randomBytes(24).toString('hex')` at startup. Served only
   through `GET /companion.js` as `window.SENTINEL_COMPANION = {token, version, tools}`,
   and only when `Sec-Fetch-Site` is `same-origin` or `none`; otherwise serve the `null`
   stub (stops other sites stealing it with `<script src>`). Every `/api/*` call must
   send `x-sentinel-token`; compare with `crypto.timingSafeEqual`.
5. **POST + `content-type: application/json` only** for `/api/*`. No CORS headers, ever.
6. **No shell.** `child_process.execFile` with argument arrays from an allowlist:
   `ping, traceroute/tracert, dig, whois, nmap`. Never interpolate into a command string.
7. **Input validation:** targets must match a hostname (`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$`, ≤253 chars) or a valid IPv4/IPv6 literal. Reject anything starting with `-` (argument injection). DNS types from a fixed list.
8. **Limits:** per-tool timeouts (ping 15s, traceroute 60s, dig 10s, whois 20s,
   scan 120s), output capped at 256KB, one scan at a time.
9. **Active scans** require `authorized: true` in the body; reject otherwise.
10. **`/api/http`:** `http:`/`https:` only, URL ≤2,048 chars, manual redirects (max 10),
    10s timeout, body sample capped at 64KB, refuse link-local `169.254.0.0/16`.
11. Log one line per request (method, path, tool, status). Never log tokens.

### 6.2 Endpoints

| Endpoint | Body | Returns |
|---|---|---|
| `GET /` and static files | — | The app, from the repo root (no directory listing, no `..`). |
| `GET /companion.js` | — | Token script (see 6.1.4). |
| `POST /api/health` | `{}` | `{ok, version, tools:{ping,traceroute,dig,whois,nmap}}` (which binaries exist). |
| `POST /api/run` | `{tool, target, type?}` | `{tool, code, stdout, stderr, ms}` |
| `POST /api/scan` | `{target, profile, authorized}` | `{method:'nmap'|'tcp-connect', open:[{port, service}], ms}` |
| `POST /api/http` | `{url}` | `{chain:[{url,status,location}], status, headers, finalUrl, bodySample, ms}` |

---

## 7. PWA (done; keep it working)

- `manifest.webmanifest`: standalone, SVG + 192/512 + maskable icons.
- `sw.js`: stale-while-revalidate for same-origin files and the Leaflet CDN; never
  caches `/api/*` or third-party APIs. Bump `CACHE` when changing caching behavior.
- Install from Chrome/Edge (address-bar install icon) or Safari (Share → Add to Dock).

**Native app?** Not required. The PWA is the app; the companion is the native layer.
If a single double-click app is ever wanted, wrap `index.html` + `companion/server.mjs`
in Electron (main process starts the companion and opens a window at it). Do not
start that unless asked.

---

## 8. Testing and verification

### 8.1 Unit (Node, no network)

```bash
npm test          # node --test tests/*.test.mjs
```

`tests/_load.mjs` loads the real `js/core.js`, `js/glossary.js` and every
`js/tools/*.js` into a sandbox. Add `tests/<bundle>.test.mjs` importing `{ S, L }`.
Every tool must register with all required fields (enforced by `logic.test.mjs`).

### 8.2 Live API checks

Each live tool's fetcher was curl-verified (section 4). Re-verify when a source changes.

### 8.3 Browser (one batched pass at integration, not per tool)

Serve (`python3 -m http.server 8777` or the companion), then for every tool: open it,
click **Run example**, confirm a verdict renders with no console errors, in light,
dark and Hacker Mode, at 1440px and 390px.

### 8.4 Companion

Start it on a spare port, then `curl` every endpoint: health; `ping 1.1.1.1`;
traceroute `1.1.1.1`; scan **`127.0.0.1` only** with `authorized:true`; scan without
`authorized` → 400; bad `Origin` → 403; bad token → 401; target `-oX` → 400;
`/api/http` on `https://github.com`.

### 8.5 Definition of done (per tool)

- [ ] Registered with every required field; appears in the sidebar and Home list.
- [ ] Run example works on real data and renders a verdict card first.
- [ ] Empty, loading, error and success states; errors name the recovery.
- [ ] Every term a beginner might not know is a glossary term.
- [ ] All dynamic strings escaped; no secrets in logs or URLs.
- [ ] Pure logic on `S.lib` with a passing test.
- [ ] Works in all three themes and at 390px.

---

## 9. Build plan

| Phase | Work |
|---|---|
| 0 | PRODUCT.md, design system, core, shell, PWA, migrate existing tools, test harness (baseline commit) |
| 1 | Bundles A–F, each on its own branch, touching only its own files; verify every API with curl (section 4) first |
| 2 | Integrate: merge branches, add `<script>` tags in `index.html`, run `npm test` |
| 3 | Browser verification pass (8.3), companion checks (8.4) |
| 4 | Design finish pass and DESIGN.md |
| 5 | README, LICENSE, secret scan, publish to GitHub |

---

## 10. Publishing

1. `npm test` green; browser pass clean.
2. Secret scan the full history before the first push:
   `git log -p | grep -nE 'AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,}|sk_live_|AIza[0-9A-Za-z_-]{35}|BEGIN [A-Z ]*PRIVATE KEY'`.
   `config.js` must contain no key.
3. `gh repo create Rohilalala/sentinel --public --source . --remote origin --push`
   with a one-line description; add topics (`cybersecurity`, `education`, `pwa`, `osint`, `networking`).
4. Changes land through pull requests.
