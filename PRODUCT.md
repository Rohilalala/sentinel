# Product

## Platform

web

## Stack

Existing codebase: static HTML/CSS/vanilla JS, no framework, no build step. Ships as an installable PWA (manifest + service worker). A local companion (single-file Node, zero dependencies, runs with one command) unlocks native tools the browser cannot run (ping, traceroute, nmap, dig, whois, server-side HTTP header fetch). User-chosen 2026-10-14 over Electron and web-only.

## Users

Beginners and computer-science students starting out in cybersecurity. They know they should understand DNS, BGP, certificates, and email authentication, but every existing tool assumes they already do. Typical scene: a student at a laptop, coursework or self-study, day or late night, poking at real domains to learn how the internet actually works.

## Product Purpose

Sentinel puts the scattered cybersecurity toolbox (recon, routing, DNS, certificates, reputation, credentials, crypto, forensics, privacy) into one console where every tool explains itself while it runs on real, live data. Success: a beginner can investigate a real domain end to end and understand every result without opening another tab.

## Positioning

Existing options are either powerful but opaque (MXToolbox, SecurityTrails, Shodan: jargon-first, assume expertise) or educational but sandboxed (TryHackMe, HackTheBox: labs and VMs, not real lookups). Sentinel is real, aggregated, and self-teaching at zero friction: no login, no API keys, no VM.

## Operating Context

- Runs in a browser tab or installed as a PWA; works offline for local tools.
- Live tools call free, keyless, CORS-friendly public APIs directly from the browser (RIPEstat, Cloudflare DoH, RDAP, certspotter, Have I Been Pwned k-anonymity, DNS blocklists).
- When the companion is running, the app is served from it at 127.0.0.1 and gains native tools.
- Built as a computer-networks course project; must demo well live.

## Capabilities and Constraints

- Teaching layer is core: every jargon term is a hover/tap glossary definition; every tool has a one-click "Run example" on real data with a narrated result.
- Recon tools are passive/read-only by default. Active tools (port scans) run only through the companion and only after the user confirms they own or are authorized to test the target.
- Offensive frameworks (Metasploit etc.) are explained and linked, never embedded.
- No backend required for the web tier; no API keys required anywhere in the default build.
- Undecided: optional free-key integrations (VirusTotal, AbuseIPDB, Shodan full).

## Brand Commitments

- Name: Sentinel.
- Shell structure is pinned to the Remotify admin layout: top bar with centered search, grouped left sidebar with badges and collapsible groups, breadcrumbs, heading plus primary-action row, KPI cards. Remotify's colors are explicitly excluded.
- Cleanliness bar is pinned to cal.com: as clean as cal.com, with modern SaaS polish.
- Three themes: light (default), dark, and an opt-in Hacker Mode with a proper hacker/terminal theme.
- Must never read as: a generic SaaS template, cold corporate enterprise software, or a hacker-movie terminal (outside the opt-in Hacker Mode).
- Visual direction (chosen 2026-10-14, safer register): the clean SaaS console played straight, at the craft level of cal.com, Linear and Vercel. Convention is the commitment; execute it at full fidelity, no smuggled quirks.

## Evidence on Hand

- Working tools verified against live data (2026-10-13/14): RPKI-invalid detection on invalid.rpki.cloudflare.com, HIBP k-anonymity ("password123" seen 2,266,543 times), 22 of 26 paypal.com typosquats resolving, full 5-step guided recon on github.com.
- Companion BGP hijack lab in ~/Documents/bgp-hijack-lab (FRRouting + Routinator in Docker).
- No users, testimonials, metrics, or press exist. Do not invent any.

## Product Principles

1. Real data over demos: every result comes from the live internet or the user's own input.
2. Explain while doing: no result appears without the meaning of its terms one hover away.
3. Zero friction: no login, no keys, no install for the web tier.
4. Safe by default: passive first; anything active is gated, local, and consented.
5. One place: a tool belongs in Sentinel if a beginner would otherwise open another site for it.

## Accessibility & Inclusion

WCAG 2.2 AA: keyboard operable, visible focus, 4.5:1 text contrast in all three themes, color never the only signal (verdicts always pair color with icon and word), respects prefers-reduced-motion.
