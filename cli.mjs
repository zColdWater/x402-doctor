#!/usr/bin/env node
// x402 Doctor CLI. Node >= 18, no dependencies, no network.
//
//   curl -si https://api.example.com/paid | node cli.mjs              # check a live 402 challenge
//   node cli.mjs challenge.txt payment.txt response.txt               # files with headers, base64 or JSON
//   node cli.mjs --payment 'eyJ4NDAy...' --challenge 'eyJ4NDAy...'    # values inline
//   options: --json (machine-readable), --now <unix seconds>, --all (include info notes)
//
// Exit code: 0 = no problems (warnings allowed), 1 = problems found, 2 = nothing x402 found / bad usage.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const D = require('./doctor.js');
const args = process.argv.slice(2);
const opt = (k) => { const i = args.indexOf(k); if (i < 0) return undefined; const v = args[i + 1]; args.splice(i, 2); return v; };
const flag = (k) => { const i = args.indexOf(k); if (i < 0) return false; args.splice(i, 1); return true; };
if (flag('--help') || flag('-h')) {
  console.log(readFileSync(new URL(import.meta.url), 'utf8').split('\n').slice(1, 10).map((l) => l.replace(/^\/\/ ?/, '')).join('\n'));
  process.exit(0);
}
const json = flag('--json');
const all = flag('--all');
const nowArg = opt('--now');
const texts = {};
for (const k of ['challenge', 'payment', 'response']) { const v = opt('--' + k); if (v !== undefined) texts[k] = v; }
args.forEach((f, i) => { texts['file' + i] = readFileSync(f, 'utf8'); });
if (!Object.keys(texts).length) {
  if (process.stdin.isTTY) { console.error('Nothing to check. Pipe curl -si output in, or pass files / --challenge / --payment / --response. See --help.'); process.exit(2); }
  const chunks = [];
  for await (const c of process.stdin) chunks.push(c);
  texts.stdin = Buffer.concat(chunks).toString('utf8');
}
const r = D.diagnose(texts, nowArg ? { now: Number(nowArg) } : {});
if (json) {
  console.log(JSON.stringify(r, null, 2));
} else {
  const mark = { fail: 'FAIL', warn: 'WARN', pass: ' ok ', info: 'info' };
  const order = { fail: 0, warn: 1, pass: 2, info: 3 };
  console.log(`x402 Doctor ${D.VERSION}: ${r.verdict.toUpperCase()} (${r.fails} fail, ${r.warns} warn) — found: ${r.found.join(', ') || 'nothing'}`);
  for (const c of r.checks.slice().sort((a, b) => order[a.level] - order[b.level])) {
    if (c.level === 'info' && !all) continue;
    console.log(`  [${mark[c.level]}] ${c.id}: ${c.message}${c.code ? `  (${c.code})` : ''}`);
  }
  if (r.codes.length) console.log(`\nError codes: ${r.codes.join(', ')}\nReference: https://zcoldwater.github.io/x402-doctor/errors/`);
}
process.exit(r.verdict === 'problems' ? 1 : r.verdict === 'nothing_found' ? 2 : 0);
