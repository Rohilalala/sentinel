# Sentinel

A beginner's cybersecurity console. 45 tools that run on live internet data or on your own input, with every term explained as you use them. No login, no API keys, no backend.

Security tools are scattered across dozens of sites, and most of them assume you already know what an ASN, a ROA or a DMARC policy is. Sentinel puts them in one place. Every result opens with a plain-English verdict, and every piece of jargon has a definition on hover.

## Run it

```bash
git clone https://github.com/Rohilalala/sentinel.git
cd sentinel
python3 -m http.server 8777     # or any static server
# open http://localhost:8777
```

It's installable as an app (PWA). In Chrome or Edge use the install icon in the address bar; in Safari use Share → Add to Dock. After one visit, the local tools also work offline.

### Native tools (optional companion)

A browser tab can't run `ping`, `traceroute`, `dig` or a port scan. The companion is one Node file with no dependencies that serves Sentinel on your own machine and adds those tools:

```bash
node companion/server.mjs        # Node 18+
# open http://127.0.0.1:7777
```

It listens on 127.0.0.1 only, accepts calls only from the page it served (session token, Origin and Host checks), runs commands from a fixed allowlist without a shell, and refuses to scan anything until you confirm you own the target or have permission. Details in [`docs/SPEC.md`](docs/SPEC.md) section 6.

## Tools

Tags: **live** queries public sources from your browser; **local** never leaves your browser; **native** needs the companion.

| Group | Tool | Tag | Data source |
|---|---|---|---|
| Learn | Guided Recon: one domain through five checks | | DoH, RDAP, certspotter, RIPEstat, DNSBLs |
| Learn | How it works: animated explainers | | static |
| Recon | Routing & RPKI: origin AS, RPKI verdict, live AS paths, map | live | RIPEstat, Cloudflare DoH, ipwho.is, OpenStreetMap |
| Recon | DNS & Email: records, DNSSEC, SPF/DMARC spoofability | live | Cloudflare DoH |
| Recon | Domain / IP Intel: registrar, dates, locks | live | RDAP |
| Recon | Cert Transparency: subdomains from certificate logs | live | certspotter |
| Recon | Reverse DNS: PTR lookup, forward-confirmed | live | Cloudflare DoH |
| Recon | DNS Propagation: two resolvers compared | live | Cloudflare and Google DoH |
| Threat intel | IP Reputation: four DNS blocklists | live | DNSBLs over DoH |
| Threat intel | Exposed Services: known open ports and CVEs, no scanning | live | Shodan InternetDB |
| Threat intel | CVE Lookup: CVSS explained, exploit odds, known exploited | live | NVD, FIRST EPSS, CISA KEV |
| Threat intel | Package Vulns: npm, PyPI, Go, Maven, crates.io, RubyGems | live | OSV.dev |
| Web & email | Typosquat Finder: registered lookalike domains | live | DoH |
| Web & email | Email Headers: delivery path + SPF/DKIM/DMARC results | local | |
| Web & email | Site Files: robots.txt and security.txt | live | public proxy, or the companion |
| Web & email | Email Auth Deep Check: SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI graded | live | Cloudflare DoH |
| Web & email | CSP Evaluator: A–F grade with fixes | local | |
| Web & email | Header Analyzer: HSTS, CSP, framing, cookies graded | local | |
| Web & email | URL Inspector: lookalike letters, @ tricks, defang/refang | local | |
| Credentials | Password Exposure: breached-password check via k-anonymity | live | Have I Been Pwned |
| Credentials | Password Generator: random or EFF passphrases, entropy | local | EFF wordlist (bundled) |
| Credentials | Hash Identifier: MD5 to Argon2, and which are safe | local | |
| Crypto | Hash & Encode: SHA, Base64, hex, URL, ROT13, CIDR, JWT | local | |
| Crypto | Encrypt / Decrypt: AES-256-GCM with PBKDF2 | local | WebCrypto |
| Crypto | Keys & Signatures: ECDSA / RSA-PSS sign and verify | local | WebCrypto |
| Crypto | HMAC: SHA-256 tags, compute and verify | local | WebCrypto |
| Crypto | Certificate Decoder: subject, issuer, SANs, validity | local | |
| Forensics | File Inspector: magic bytes, hashes, entropy, strings | local | |
| Forensics | Photo Metadata: EXIF camera, time and GPS | local | |
| Forensics | Executable Inspector: PE and ELF headers, sections, red flags | local | |
| Forensics | Secrets Scanner: leaked keys and tokens, masked | local | |
| Forensics | IAM Policy Analyzer: AWS wildcards and escalation paths | local | |
| Privacy | What Sites See: IP, provider, device facts | live | ipwho.is, ipify |
| Privacy | WebRTC Leak Test: local and VPN-bypassing IPs | live | public STUN server |
| Privacy | Browser Fingerprint: how recognizable your browser is | local | |
| Native | Ping, Traceroute, DNS (dig), WHOIS (CLI) | native | your computer |
| Native | Port Scan: top 100 ports, consent required | native | your computer (nmap if installed) |
| Native | Tech Detector, Link Unshortener, Security Headers (live) | native | server-side fetch from your computer |
| Reference | MITRE ATT&CK: searchable techniques by tactic | | MITRE ATT&CK v20 (bundled) |
| Reference | OWASP Top 10 (2025), in plain words | | own words, after owasp.org |

Password Exposure sends only the first five characters of a SHA-1 hash, never the password. Files you inspect and text you paste into local tools never leave the browser.

## Themes

Light (default), Dark, and **Hacker Mode**: an opt-in terminal theme. The switch is in the top right.

## Develop

```bash
npm test        # Node unit tests; loads the real browser files in a sandbox, no network
```

- `js/core.js` holds the registry, router, shell, API helpers, the glossary engine and check history.
- `js/tools/<bundle>.js` holds one bundle of tools. Each file registers its own tools, icons and glossary terms.
- `css/tokens.css` holds every design token for all three themes; `css/app.css` holds the components.
- `companion/server.mjs` is the native-tools companion; `data/` holds bundled datasets; `scripts/build-attack.mjs` rebuilds `data/attack.json`.
- Deep links: `#/<tool>?q=<value>` opens a tool and runs it on a value, e.g. `#/cve?q=CVE-2021-44228`. Native tools, and every tool while the companion runs, only prefill.

[`docs/SPEC.md`](docs/SPEC.md) is the full build spec: architecture, the tool contract, the design rules, the catalog, and the companion security model. [`PRODUCT.md`](PRODUCT.md) records who it's for and the commitments behind it.

## Ground rule

Reading public records (DNS, WHOIS, routing tables, certificate logs) is fine for any domain. Scanning or testing systems you don't own, or don't have permission to test, can be illegal. Practise on your own machines, the built-in examples, and `scanme.nmap.org`, which the Nmap project runs for exactly this.

## Credits

- EFF Large Wordlist by the Electronic Frontier Foundation, CC BY 3.0 US.
- MITRE ATT&CK®: © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.
- OWASP Top 10 category names and ranking from the OWASP Foundation; the explanations are Sentinel's own.
- Icons drawn on the Lucide grid (ISC).

## License

MIT
