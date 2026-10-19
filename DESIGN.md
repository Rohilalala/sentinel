---
name: Sentinel
description: A clean security console that explains every live result in plain English.
colors:
  canvas: "#fafafa"
  surface: "#ffffff"
  surface-2: "#f5f5f5"
  surface-3: "#ededed"
  hairline: "#eaeaea"
  hairline-strong: "#d4d4d4"
  ink: "#0a0a0a"
  ink-2: "#404040"
  muted: "#6b6b6b"
  primary: "#0a0a0a"
  primary-hover: "#262626"
  primary-fg: "#ffffff"
  ok: "#0f7b3f"
  ok-bg: "#edf7f0"
  warn: "#9a5b00"
  warn-bg: "#fbf3e3"
  bad: "#c2261e"
  bad-bg: "#fcedec"
  info-bg: "#f2f2f2"
  dark-canvas: "#0a0a0a"
  dark-surface: "#111111"
  dark-ink: "#ededed"
  dark-ok: "#4cc27a"
  dark-warn: "#e5a23b"
  dark-bad: "#f2645c"
  hacker-canvas: "#050505"
  hacker-surface: "#070b07"
  hacker-border: "#173317"
  hacker-phosphor: "#33ff00"
  hacker-warn: "#ffb000"
  hacker-bad: "#ff4433"
typography:
  display:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica Neue, Arial, sans-serif"
    fontSize: "30px"
    fontWeight: 650
    lineHeight: 1.15
    letterSpacing: "-0.025em"
  headline:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica Neue, Arial, sans-serif"
    fontSize: "24px"
    fontWeight: 650
    lineHeight: 1.2
    letterSpacing: "-0.02em"
  title:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica Neue, Arial, sans-serif"
    fontSize: "16px"
    fontWeight: 650
    lineHeight: 1.3
  body:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica Neue, Arial, sans-serif"
    fontSize: "14px"
    fontWeight: 400
    lineHeight: 1.55
  label:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica Neue, Arial, sans-serif"
    fontSize: "13px"
    fontWeight: 600
    lineHeight: 1.4
  caption:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica Neue, Arial, sans-serif"
    fontSize: "12px"
    fontWeight: 600
    lineHeight: 1.4
  mono:
    fontFamily: "ui-monospace, SF Mono, SFMono-Regular, Menlo, Consolas, Liberation Mono, monospace"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.55
rounded:
  ctl: "8px"
  card: "12px"
  pill: "999px"
spacing:
  xs: "6px"
  sm: "8px"
  md: "12px"
  lg: "16px"
  xl: "20px"
  2xl: "28px"
  page: "40px"
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.primary-fg}"
    typography: "{typography.label}"
    rounded: "{rounded.ctl}"
    padding: "0 16px"
    height: "38px"
  button-primary-hover:
    backgroundColor: "{colors.primary-hover}"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.ctl}"
    padding: "0 16px"
    height: "38px"
  button-secondary-hover:
    backgroundColor: "{colors.surface-2}"
  input:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    typography: "{typography.mono}"
    rounded: "{rounded.ctl}"
    padding: "0 12px"
    height: "38px"
  search-input:
    backgroundColor: "{colors.surface-2}"
    textColor: "{colors.ink}"
    rounded: "{rounded.ctl}"
    height: "36px"
  card:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.card}"
    padding: "18px 20px"
  nav-item:
    backgroundColor: "transparent"
    textColor: "{colors.ink-2}"
    rounded: "{rounded.ctl}"
    padding: "6px 10px"
  nav-item-active:
    backgroundColor: "{colors.surface-3}"
    textColor: "{colors.ink}"
  tag:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.muted}"
    rounded: "{rounded.pill}"
    padding: "0 7px"
    height: "20px"
  badge-ok:
    backgroundColor: "{colors.ok-bg}"
    textColor: "{colors.ok}"
    typography: "{typography.caption}"
    rounded: "6px"
    padding: "0 8px"
    height: "22px"
  badge-warn:
    backgroundColor: "{colors.warn-bg}"
    textColor: "{colors.warn}"
  badge-bad:
    backgroundColor: "{colors.bad-bg}"
    textColor: "{colors.bad}"
---

# Design System: Sentinel

## Overview

**Creative North Star: "The Quiet Console"**

Sentinel is the cal.com / Linear / Vercel console played straight, pointed at the live internet so beginners can learn security on real data. White ground, near-black ink, neutral grays, 1px hairlines and black primary buttons. Nothing in the chrome competes with the result: the only saturated color on any screen is a verdict's state (safe, warning, danger) and the badges inside results that carry it.

Density is a working tool's density: 14px body, 38px controls, a 240px grouped sidebar under a 56px top bar, cards on a pale canvas. The teaching layer stays out of the way too. Jargon gets a dashed underline and a popover definition, not a callout. Every tool page has the same shape: breadcrumb, H1 and lede, a black Run example button, a collapsible "What this is and why it matters" panel, the input, then a verdict card that leads the results.

There are three themes over one token set. Light is the default; Dark is a neutral #0A0A0A inversion with no blue tint; Hacker Mode is the opt-in terminal: phosphor green on near-black, everything mono, square corners, bracketed buttons, faint scanlines. Hacker Mode is a full world of its own, not decoration on top of the light theme. It uses the same components and differs only by token values and a short scoped block.

**Key Characteristics:**
- Neutral monochrome chrome; color means verdict state and nothing else.
- System UI plus system mono, no webfonts (offline PWA).
- Flat cards, separated by 1px hairlines; shadows only on floating layers.
- 8px controls and 12px cards; 0px everywhere in Hacker Mode.
- Values, inputs and identifiers set in mono; prose in UI sans.

## Colors

A grayscale console with three state hues held in reserve for verdicts.

### Primary
- **Console Ink** (primary, #0A0A0A): the Run example and submit buttons, focus ring, checkbox/radio accent. In Dark it flips to the light ink (#EDEDED) with dark text, and in Hacker Mode it is the phosphor with black text. It is never a brand hue.

### Neutral
- **Pale Canvas** (canvas): the page ground behind cards.
- **Paper** (surface): cards, top bar, sidebar, inputs, popovers.
- **Wash** (surface-2) and **Deep Wash** (surface-3): hover rows, search field at rest, code/pre blocks, notes, list group headers, meter tracks. The active nav item takes surface-3.
- **Hairline** (hairline) and **Strong Hairline** (hairline-strong): card and row borders, then input borders, secondary buttons and link underlines.
- **Ink** (ink), **Ink 2** (ink-2), **Muted** (muted): headings and values, then body prose in verdict subs and notes, then labels, ledes, card titles and table headers.

### State (verdict only)
- **Safe Green** (ok / ok-bg), **Caution Amber** (warn / warn-bg), **Alarm Red** (bad / bad-bg): verdict icons, result badges, meters, the error status line, and the warn note. Each theme retunes them to hold 4.5:1 (dark: #4CC27A / #E5A23B / #F2645C; hacker: phosphor / #FFB000 / #FF4433).
- **Info** (info-bg with ink-2 text): neutral informational badges. It is gray on purpose, so blue never enters the palette.

### Named Rules
**The Verdict-Only Color Rule.** Saturated color appears only where it tells you a state: the verdict icon, badges, meters and warnings inside results. Chrome, navigation, availability tags, headings and buttons stay neutral.

**The Pair-It Rule.** State color is never the only signal. Every verdict and badge pairs its color with an icon and a word.

**The Tokens-Only Rule.** Components read custom properties only. All raw colors live in the token file, so a theme is a value swap and not a fork.

## Typography

**Display Font:** System UI (-apple-system, Segoe UI, Roboto, Helvetica Neue, Arial)
**Body Font:** System UI, same stack
**Label/Mono Font:** System mono (ui-monospace, SF Mono, Menlo, Consolas)

**Character:** The platform's own sans at tight negative tracking and a 650 weight reads like a native console. Mono marks everything that is data: input values, key-value values, badges, try-examples, hashes, numbers in tables. Body uses tabular numerals throughout. In Hacker Mode the UI stack resolves to mono, so the entire interface is set in one monospace.

### Hierarchy
- **Display** (650, 30px, 1.15, -0.025em): the page H1 and KPI values only. Drops to 24px below 900px.
- **Headline** (650, 24px, 1.2, -0.02em): the verdict sentence, which is the verdict card's h2.
- **Title** (650, 16px): section heads on Home, explainer scene titles, the empty-state line, the lede (16px regular, muted, 62ch).
- **Body** (400, 14px, 1.55): prose, nav items, table cells. Max 70 to 75ch inside cards.
- **Label** (600, 13px): field labels, card titles (muted), breadcrumb, status line.
- **Caption** (600, 12px): table headers, sidebar group names, list group headers, badges (in mono).
- **Mono** (400, 13px): values in key-value grids, try-examples, pre blocks; inputs at 14px (16px below 900px to stop iOS zoom).

### Named Rules
**The Data-Is-Mono Rule.** If it was typed, returned by an API, or could be copied, set it in mono. If it explains, set it in sans.

**The Sentence-Case Rule.** Labels and card titles are sentence case in the light and dark themes. Uppercase with 0.08em tracking belongs to Hacker Mode only (card titles, group names, table headers).

## Layout

The shell is a fixed app frame. A sticky 56px top bar holds three columns: the wordmark in a 240px column aligned over the sidebar, a centered search capped at 520px, and the theme switch. Below it is a 240px sticky sidebar with its own scroll, then the main column, padded 28px top and 40px sides. Pages cap at 1040px and are left-aligned, not centered.

Tool page rhythm: breadcrumb (14px below), a head row with H1 and lede on the left and the primary action on the right (20px below), the About panel, the input bar, then a results grid with 12px gaps. Results use one column, or a 1.2fr / 0.8fr split from 880px. Full-width cards span both. Home is a KPI grid (auto-fit, min 190px), then grouped tool lists. Spacing steps observed: 6, 8, 12, 16, 20, 28, 40px.

Responsive:
- **Below 900px** the sidebar becomes an off-canvas drawer (max 300px or 86vw) that slides in over the content. When closed it is `visibility: hidden` as well as translated, so it leaves the tab order. A 36px menu button appears in the top bar, the head row stacks (action under the lede), main padding drops to 20/16px, and list rows hide their descriptions.
- **Below 560px** the search shortcut hint hides, key-value grids become a single column, and tables inside a table wrapper stack: the header row is hidden, cells flow inline per row, and the last (explanatory) cell takes its own line.

## Elevation & Depth

Flat by default. Depth comes from tone (canvas, then surface, then wash) and 1px hairlines. Resting cards, panels, notes and lists have a border and no shadow. Shadow is reserved for layers that float above the page.

### Shadow Vocabulary
- **Pop** (`--shadow-pop`; light `0 8px 24px -4px rgba(0,0,0,.12), 0 2px 6px -1px rgba(0,0,0,.06)`; dark is deeper; hacker is a 1px phosphor-dim ring plus a black drop): the search results list, the glossary tooltip, the toast, and the open mobile drawer.

### Named Rules
**The Floating-Only Shadow Rule.** Only popovers (search results, glossary tooltip, toast) and the open drawer get border plus shadow. A card that sits in the page flow never casts a shadow.

## Shapes

Two radii carry the system. Controls (buttons, inputs, search, nav items, notes, pre blocks, map) use 8px, and containers (cards, About panel, lists, KPIs, explainer scenes) use 12px. Small inner pieces use 6px (badges, search result rows, theme-switch segments). Availability tags and meters are full pills. Borders are always 1px solid, except the file drop zone (dashed, strong hairline) and glossary terms (dashed underline in muted).

Hacker Mode squares every corner with a single scoped override, including pills, badges, kbd and meters.

## Components

### Buttons
Black, compact and confident; one per head row.
- **Shape:** gently rounded (8px), 38px tall, 0 16px padding, 600 weight, optional 15px icon.
- **Primary:** ink fill, white text, ink border. Used for Run example and submits.
- **Hover / Active:** fill lightens to primary-hover over 160ms on the shared ease (cubic-bezier(.16,1,.3,1)); press scales to .98. Disabled and busy states drop to .55 opacity.
- **Secondary:** paper fill, ink text, strong-hairline border; hover goes to wash. Used for Look up next to inputs and for the file picker button.
- **Hacker Mode:** the label is wrapped as `[ Run example ]` and icons are hidden.

### Tags and Badges
- **Availability tag (live / local / native):** neutral bordered pill: 20px tall, 11px text, muted on paper, hairline border. It is not colored, whatever its value.
- **Result badge:** 22px, 6px radius, 12px mono 600, icon plus word. The fill and text come from the state pair (ok, warn, bad, info) or the muted wash.

### Cards / Containers
- **Corner Style:** 12px.
- **Background:** paper on the pale canvas.
- **Shadow Strategy:** none (see Elevation).
- **Border:** 1px hairline.
- **Internal Padding:** 18px by 20px; card title in label type, muted, 12px below.
- **Notes:** wash fill, hairline, 8px radius, icon plus text at 13px. The warn note takes warn-bg with a 25% warn border. There are no colored side rails.

### Verdict Card (signature)
The first card in every result. It has no label, pill or kicker. The verdict sentence is the card's h2 in headline type, led by a 22px state icon: check in ok, alert in warn, x in bad, muted when neutral. In light and dark the headline stays ink and only the icon carries color. In Hacker Mode warn and danger headlines take warn and bad, because body text and ok share the phosphor. Below it, a 70ch sub in ink-2 explains the result in plain English with glossary terms inline.

### Inputs / Fields
- **Style:** 38px, 8px radius, strong-hairline border, paper fill, mono 14px. Labels are 13px 600 ink above. A muted "Try:" row of underlined mono example buttons sits below.
- **Focus:** border goes to ink and gains a 3px selection-tint ring. Global focus-visible is a 2px ring-color outline at 2px offset.
- **Checkbox / Radio:** native, `accent-color` ink.
- **Error:** the status line under the bar turns bad and gains an alert icon.

### Navigation
- **Top bar:** paper, bottom hairline, wordmark (16px 650 with a 22px shield mark), search with a leading icon and a `/` kbd hint, and a segmented three-button theme switch (sun / moon / terminal) on wash.
- **Sidebar:** grouped `details` sections with 12px muted 600 summaries and a rotating chevron. Items are 34px, ink-2 at 500 with a muted 16px line icon and a trailing availability tag. Hover goes to wash. The active item takes deep wash, ink and 600.
- **Breadcrumb:** 13px muted links with chevrons; the current page is ink 500.

### Glossary Term and Tooltip
Jargon carries a dashed muted underline and a help cursor, and is focusable. The tooltip is a paper popover with a 300px max width, Pop shadow, the term in mono 12px bold, then the definition. It opens on hover, focus or tap and closes on Escape or scroll.

### Icons
One set, built from 24px grid paths with a 1.6 stroke, round caps, currentColor, at 16px by default. There are no icon tiles and no filled glyph icons.

## Do's and Don'ts

### Do:
- **Do** lead every result with the verdict card, its sentence as the h2 and a state-colored icon beside it.
- **Do** keep chrome neutral: availability tags, nav, headings and buttons are ink, gray or hairline.
- **Do** set data in system mono and prose in the system UI stack.
- **Do** use 8px for controls and 12px for containers, and 0px in Hacker Mode.
- **Do** separate surfaces with 1px hairlines and tone; save the Pop shadow for floating layers.
- **Do** pair every state color with an icon and a word, and keep 4.5:1 text contrast in all three themes.
- **Do** define every jargon term through the glossary underline and tooltip.

### Don't:
- **Don't** add a label pill, eyebrow or kicker above a verdict or a card title.
- **Don't** introduce an accent hue (blue, cobalt, orange, brand gradient) into the chrome.
- **Don't** load webfonts; the system stacks are the brand and keep the PWA offline.
- **Don't** put shadows on resting cards, or colored left borders on cards and notes.
- **Don't** use a gradient hero, an icon-tile grid, or glyph or emoji icons.
- **Don't** bring uppercase tracking, bracketed buttons, scanlines or phosphor into the light or dark themes; they belong to Hacker Mode.
