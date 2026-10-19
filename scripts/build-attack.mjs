#!/usr/bin/env node
/* Builds data/attack.json (compact MITRE ATT&CK Enterprise techniques) from the MITRE CTI STIX bundle.
   Run: node scripts/build-attack.mjs   (downloads ~50MB, writes ~200KB)

   © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.
   ATT&CK license (attack.mitre.org/resources/legal-and-branding/terms-of-use): The MITRE Corporation (MITRE) hereby
   grants you a non-exclusive, royalty-free license to use ATT&CK® for research, development, and commercial purposes.
   Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and
   this license in any such copy. */
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';

export const NOTICE = '© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.';
export const LICENSE = 'The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research, development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce MITRE\'s copyright designation and this license in any such copy.';

// First sentence of a STIX description, without citations, markdown links or HTML tags, at most 240 chars.
export function firstSentence(s) {
  const clean = String(s || '').replace(/\(Citation:[^)]*\)/g, '').replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
  const m = clean.match(/^.*?(?<!\b(?:e\.g|i\.e|etc|vs|al|Inc|Ltd|Corp))[.!?](?=\s+[A-Z("']|$)/);
  const one = m ? m[0] : clean;
  return one.length <= 240 ? one : one.slice(0, 239).replace(/\s+\S*$/, '') + '…';
}

// STIX bundle → {tactics, techniques}. Skips revoked and deprecated objects.
export function compact(bundle) {
  const objs = bundle.objects, live = o => !o.revoked && !o.x_mitre_deprecated;
  const ref = o => (o.external_references || []).find(r => r.source_name === 'mitre-attack') || {};
  const tacticById = new Map(objs.filter(o => o.type === 'x-mitre-tactic').map(o => [o.id, o]));
  const matrix = objs.find(o => o.type === 'x-mitre-matrix');
  const tactics = matrix.tactic_refs.map(r => tacticById.get(r)).filter(Boolean)
    .map(o => ({ id: ref(o).external_id, short: o.x_mitre_shortname, name: o.name }));
  const techniques = objs.filter(o => o.type === 'attack-pattern' && live(o)).map(o => ({
    id: ref(o).external_id, name: o.name,
    tactics: (o.kill_chain_phases || []).filter(k => k.kill_chain_name === 'mitre-attack').map(k => k.phase_name),
    desc: firstSentence(o.description), url: ref(o).url, sub: !!o.x_mitre_is_subtechnique,
  })).sort((a, b) => a.id.localeCompare(b.id, 'en', { numeric: true }));
  return { tactics, techniques };
}

async function main() {
  const rel = await fetch('https://api.github.com/repos/mitre/cti/releases/latest').then(r => r.json());
  const tag = rel.tag_name; // e.g. "ATT&CK-v20.0"
  const src = `https://raw.githubusercontent.com/mitre/cti/${encodeURIComponent(tag)}/enterprise-attack/enterprise-attack.json`;
  console.log('Downloading', src);
  const r = await fetch(src);
  if (!r.ok) throw new Error(`HTTP ${r.status} from ${src}`);
  const out = { version: tag.replace(/^ATT&CK-/, ''), built: new Date().toISOString().slice(0, 10), source: src,
    notice: NOTICE, license: LICENSE, ...compact(await r.json()) };
  const file = new URL('../data/attack.json', import.meta.url);
  fs.mkdirSync(new URL('.', file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(out));
  console.log(`Wrote data/attack.json: ${out.techniques.length} techniques, ${out.tactics.length} tactics, ${fs.statSync(file).size} bytes`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main().catch(e => { console.error(e.message); process.exit(1); });
