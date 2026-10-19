# Sentinel — Tutorials & narration scripts

There is no video file in this project — nothing here can render an MP4. What
this gives you instead is better for learning and lets you record your own
voice-over later: every tool has a **Run example** button that runs a real
example live, and below is the word-for-word narration for each one, timed to
what appears on screen. Read it aloud over a screen recording (QuickTime →
File → New Screen Recording) and you have your tutorial videos.

Each script is ~45–70 seconds. Jargon in **bold** is a term the UI also
explains on hover.

---

## 0. The hub — "why this exists" (60s)

> Security tools are scattered across a dozen different websites, each with its
> own jargon and no explanation. Sentinel puts six of them in one console, and
> every underlined word has a plain-English definition on hover. Nothing here is
> faked — it queries the live internet. The rule before we start: these are the
> same tools professionals use, so only run them against names and systems you
> own or have permission to test. Reading public records is fine; attacking
> things you don't control is not. Let's start with how the internet decides
> where your traffic goes.

---

## 1. Routing & RPKI — "the anatomy of a hijack" (70s)

> Every website lives inside a block of IP addresses called a **prefix**, and
> some network — an **ASN** — announces that prefix to the world using **BGP**.
> The problem: BGP believes whatever it's told. If I announce addresses I don't
> own, traffic starts flowing to me. That's a **prefix hijack**, and it took
> YouTube offline globally in 2008.
>
> Watch. I'll click Run example, which checks Cloudflare's deliberately-broken test
> host. The verdict comes back red: **RPKI INVALID**. RPKI is the fix — the real
> owner signs a statement saying "only my network may announce this prefix", and
> this route violates it.
>
> Below, these are real paths seen right now by 180-plus **route collectors**
> worldwide — each row is how a different network reaches this prefix, ending at
> the origin on the right. And here, Sentinel caught two different origins
> announcing the same prefix — a live **MOAS** event, the exact pattern a hijack
> produces. Try youtube.com next: green, valid, one origin. That's a healthy
> route.

**Demo input:** `invalid.rpki.cloudflare.com` (red), then `youtube.com` (green).

---

## 2. DNS & Email — "can someone send email as you?" (55s)

> **DNS** is the internet's phone book — it turns names into addresses. But it
> also tells you whether a domain's email can be forged. Click Run example on
> cloudflare.com.
>
> Up top: is the email **spoofable**? That depends on two DNS records. **SPF**
> lists who's allowed to send mail as this domain. **DMARC** says what to do with
> mail that fails the check. If either is missing, anyone can send phishing that
> looks like it came from this domain. Cloudflare has both, enforced — so it's
> protected.
>
> We also check **DNSSEC** — cryptographic signatures proving these answers
> weren't tampered with — and list every record. Run this on your own domain:
> if DMARC says "p=none" or is missing, that's your weekend project.

**Demo input:** `cloudflare.com`. Compare with a domain that has no DMARC.

---

## 3. Domain / IP Intel — "is this domain trustworthy?" (50s)

> Before trusting a link, analysts check **WHOIS** — who registered the domain,
> when, and through which **registrar**. Sentinel uses **RDAP**, the modern
> structured version. Click Run example on github.com.
>
> There's the registrar, the creation date, the expiry, and the status locks
> that stop the domain being transferred out from under them. The single most
> useful signal for spotting phishing is age: a domain registered three days ago
> that claims to be your bank is almost always fake. Sentinel flags anything
> under 90 days old in amber. You can paste an IP here too — it'll show who owns
> that block and in which country.

**Demo input:** `github.com`, then an IP like `8.8.8.8`.

---

## 4. Certificate Transparency — "mapping the attack surface" (55s)

> Here's a trick that surprises people. Every **TLS certificate** ever issued —
> the thing behind the padlock — is written to public, append-only logs called
> **Certificate Transparency** logs. That means you can search them to find
> every **subdomain** a company ever got a certificate for, including internal
> ones they forgot about: dev, staging, vpn, admin.
>
> Click Run example on github.com. Sentinel pulls their certificates and extracts
> every hostname. This is exactly step one of how a bug-bounty hunter — or an
> attacker — maps a target. Forgotten subdomains are where the old, unpatched
> software lives. Run it on your own domain and see what's exposed.

**Demo input:** `github.com`.

---

## 5. Password Exposure — "has your password already leaked?" (60s)

> Attackers don't guess passwords — they reuse ones already leaked in a
> **breach**. If your password is in the "Have I Been Pwned" dataset, it's
> already in every attacker's wordlist. But how do you check a password without
> sending it somewhere? **k-anonymity**.
>
> Click Run example. Sentinel hashes the password right here in your browser, and
> sends only the first five characters of that hash. The server replies with
> every leaked hash starting with those five characters — about two thousand of
> them — and the match happens locally. The server never learns your password.
> "password123" comes back seen over two million times. The strength meter and
> entropy estimate show why. The bottom card walks through exactly what left
> your browser: five characters. Nothing else.

**Demo input:** `password123` (breached), then a random 16-char string (clean).

---

## 6. Hash & Encode — "reading data in the wild" (50s)

> Half of practical security is recognizing encodings on sight. This bench runs
> entirely offline — nothing touches the network.
>
> Type into the hash box and watch the **SHA-256** fingerprint update live —
> that's how files are verified and passwords stored. **Base64** looks like
> encryption but isn't; it's just a text representation, fully reversible — you'll
> see it everywhere. And paste a **JWT** — the login token apps give you — into
> the decoder: its payload reads straight out, because it's only Base64, not
> secret. That's the lesson: never put anything sensitive in a JWT payload.

**Demo:** type `hello` in hash; decode a sample JWT.

---

## How it all fits together (the "big picture" script, 40s)

> Follow the flow of an investigation. You get a suspicious link. **Domain
> Intel** tells you it was registered last week — red flag. **DNS & Email** shows
> it has no DMARC, so it can spoof a real brand. **Cert Transparency** reveals a
> dozen hidden subdomains on it. **Routing & RPKI** shows which network really
> hosts it and whether that network is announcing stolen address space. If they
> leak a password dump, **Password Exposure** tells you if yours is in it. And
> the **Toolkit** decodes whatever encoded data you find along the way. Six
> tools, one investigation. That's security recon.

---

## Recording checklist
- QuickTime screen recording at 1280×800, Sentinel in a clean browser window.
- One tool per clip; click **Run example**; read the matching script above.
- The toast at the bottom narrates the action on screen — pause on it.
- Keep each clip under 75s. Six clips + the intro = a complete beginner course.
