// Shared harness: loads the real browser files into a sandbox. Import { S } in any *.test.mjs.
import fs from 'node:fs';
import vm from 'node:vm';
export const ctx = vm.createContext({ console, TextEncoder, TextDecoder, crypto, atob, btoa, URL, setTimeout, clearTimeout,
  fetch: () => { throw new Error('no network in unit tests'); } });
const files = ['js/core.js', 'js/glossary.js', ...fs.readdirSync('js/tools').filter(f => f.endsWith('.js')).sort().map(f => 'js/tools/' + f)];
for (const f of files) vm.runInContext(fs.readFileSync(f, 'utf8'), ctx, { filename: f });
export const S = ctx.Sentinel;
export const L = S.lib;
