# Sentinel

A beginner's cybersecurity console. Real recon tools running on live internet data, with every term explained as you use them. No login, no API keys, no backend.

Security tools are scattered across dozens of sites, and most of them assume you already know what an ASN, a ROA or a DMARC policy is. Sentinel puts them in one place. Every result comes with a plain-English verdict, and every piece of jargon has a definition on hover.

## Run it

```bash
git clone https://github.com/Rohilalala/sentinel.git
cd sentinel
python3 -m http.server 8777     # or any static server
# open http://localhost:8777
```

It's installable as an app (PWA). In Chrome or Edge use the install icon in the address bar; in Safari use Share → Add to Dock. After one visit, the local tools also work offline.

## Tools

| Group | Tool | Data source |
|---|---|---|
| Learn | Guided Recon: one domain run through five checks | DoH, RDAP, certspotter, RIPEstat, DNSBLs |
| Learn | How it works: animated explainers | static |
| Recon | Routing & RPKI: origin AS, RPKI verdict, live AS paths, map | RIPEstat, Cloudflare DoH, ipwho.is, OpenStreetMap |
| Recon | DNS & Email: records, DNSSEC, SPF/DMARC spoofability | Cloudflare DNS-over-HTTPS |
| Recon | Domain / IP Intel: registrar, dates, locks (modern WHOIS) | RDAP |
| Recon | Cert Transparency: subdomains from public certificate logs | certspotter |
| Threat intel | IP Reputation: four DNS blocklists | DNS-over-HTTPS |
| Web & email | Typosquat Finder: registered lookalike domains | DNS-over-HTTPS |
| Web & email | Email Headers: delivery path + SPF/DKIM/DMARC results | local |
| Web & email | Site Files: robots.txt and security.txt | public proxy |
| Credentials | Password Exposure: breached-password check via k-anonymity | Have I Been Pwned |
| Crypto | Hash & Encode: SHA, Base64, hex, URL, ROT13, CIDR, JWT | local |

Tools tagged **local** never send anything over the network. Password Exposure sends only the first five characters of a SHA-1 hash, never the password itself.

## Themes

Light (default), Dark, and **Hacker Mode**: an opt-in terminal theme. The switch is in the top right.

## Develop

```bash
npm test        # Node unit tests; loads the real browser files in a sandbox
```

- `js/core.js` holds the registry, router, shell, API helpers, the glossary engine and check history.
- `js/tools/<bundle>.js` holds one bundle of tools. Each file registers its own tools, icons and glossary terms.
- `css/tokens.css` holds every design token for all three themes; `css/app.css` holds the components.

[`docs/SPEC.md`](docs/SPEC.md) is the full build spec: architecture, the tool contract, the design rules, the planned catalog, and the companion security model. [`PRODUCT.md`](PRODUCT.md) records who it's for and the commitments behind it.

## Ground rule

Reading public records (DNS, WHOIS, routing tables, certificate logs) is fine for any domain. Scanning or testing systems you don't own, or don't have permission to test, can be illegal. Practise on your own domains and the built-in examples.

## License

MIT
