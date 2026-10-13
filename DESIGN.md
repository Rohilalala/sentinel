# DESIGN.md — Sentinel (cybersecurity hub)

## Discovery
- **Artifact:** high-density security console / dashboard (multi-tool).
- **Who / why:** people new to cybersecurity who want to *do* real recon, not read theory. The tools exist but are scattered across a dozen sites; this puts them in one place with plain-English explanations.
- **Positioning:** technical but approachable. Credible enough to trust, friendly enough for a first-timer.
- **Adjectives:** approachable · trustworthy · hands-on · sharp · calm.
- **Aesthetic essence:** "SOC console you're allowed to touch."

## Aesthetic commitment (v2 — matched to Remotify admin)
Light "native app" console modeled on the Remotify admin UI: warm-stone background, white hairline cards, compact left sidebar, system font, dense 13–14px, 6–8px radius, very soft shadows. Traffic-light semantics for safe / warn / danger. **Accent is cobalt `#1a5fd0`, deliberately NOT Remotify's teal `#0a6b62`** — same shell language, distinct identity.

Earlier v1 was a dark SOC console (Space Grotesk, ink, teal). Superseded on request to resemble Remotify.

**Signature move:** *teaching is built into the surface.* Every jargon term is a dotted-underline glossary chip you hover/tap to learn; every tool has a one-tap **"Show me"** that runs a real example and narrates the result. The UI is the tutorial.

## Typography (v2)
- UI + headings: **native system stack** (`-apple-system, system-ui, "SF Pro Text", "Segoe UI"`) — matches Remotify, zero webfonts.
- Mono: **`ui-monospace` / SF Mono** — for all IPs, prefixes, hashes, AS paths. Also native.
- Base 14px, dense; headings 600 weight with tight tracking. No webfont download.

## Color (v2 — light, Remotify-like shell, cobalt accent)
| role | value | use |
|------|-------|-----|
| bg | `#f5f5f4` | warm-stone app background (Remotify) |
| surface | `#ffffff` | cards |
| surface-2 | `#ebebea` | sidebar, inputs, raised rows |
| fg | `#1d1d1f` | text (Apple ink) |
| muted | `#626267` | secondary text |
| border | `#e3e3e1` / strong `#d6d6d3` | hairlines |
| **accent** | **`#1a5fd0` cobalt** | primary action, links — NOT Remotify's teal |
| safe | `#1f9d57` green | valid / secure |
| warn | `#a8640a` amber | suspicious / needs review |
| danger | `#c0392b` red | invalid / exposed / hijack |
| info | `#3a63b5` | neutral facts |

Distribution ~60 neutral / 30 accent-structural / 10 semantic. Accent is for action and the single most important status only; the traffic-light trio carries meaning everywhere else, never color alone (always paired with an icon/word).

## Spacing / radius / shadow
- Base unit 4px; groups tight (8–12), sections generous (24–32).
- Radius: 10px cards, 7px controls. Two values, no blobs.
- Elevation: **defined edge** (1px border) is the default; soft shadow only on floating layers (tooltip, toast, tour). Never border+shadow on the same resting card.

## Craft
- **Layout:** fixed left rail (tool list, grouped Recon / Credentials / Toolbox) + content column with a bento result grid. Not a centered marketing column.
- **Components:** full state matrix on buttons/inputs (hover/active/focus/disabled/loading). Verdict cards carry a left status rail in the semantic color. Tables: left-align text, right-align tabular-nums.
- **Motion:** ease-out ≤180ms, opacity+transform only; tooltip/tour scale from origin; respects `prefers-reduced-motion`.
- **Icons:** one inline-SVG set, 1.6 stroke, 24px grid.
- **Accessibility:** visible focus ring (accent), keyboard-run on Enter, 24px+ targets, semantic color always doubled with icon+label, AA contrast on ink.

## Slop audit
- ✅ No Inter/Roboto; no indigo/violet; no glassmorphism; no blob radius; no gradient text; no hero+3-cards template (it's a console).
- ✅ Signature move present (teaching layer).
- ✅ Semantic color never alone.
- Changelog: v1 — security console, Space Grotesk/Plex/JetBrains, teal signal + traffic-light, teaching-surface signature.

- v3 — restructured to the Remotify admin shell (topbar + ⌘K search, grouped sidebar with badges, breadcrumb, heading+action row, KPI cards, Plus Jakarta Sans, 10px cards). Palette stays ours: orange accent + navy-slate ink, NOT Remotify blue/teal.
- v4 — added dark mode (toggle, persisted), removed profile avatar, redesigned home (animated hero), added "How it works" visual explainer (Learn group) + CIDR calculator. Keyless OSM basemap fallback (Carto now needs a key).
