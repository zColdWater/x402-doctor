// Minimal DOM shim to smoke-test app.js without a browser: loads index.html ids, clicks every example,
// checks that results render, error-code links point at real pages, and tip addresses pass validation.
//   node test/ui-smoke.mjs
import { readFileSync, existsSync } from 'node:fs';
import vm from 'node:vm';
const here = (p) => new URL('../' + p, import.meta.url);
const html = readFileSync(here('index.html'), 'utf8');
class Node {
  constructor(tag, attrs = {}) { this.tagName = tag; this.attrs = { ...attrs }; this.children = []; this.listeners = {}; this._text = ''; this.hidden = 'hidden' in attrs; this.value = attrs.value ?? ''; this.checked = 'checked' in attrs; this.className = attrs.class || ''; }
  setAttribute(k, v) { this.attrs[k] = String(v); if (k === 'class') this.className = v; }
  getAttribute(k) { return this.attrs[k] ?? null; }
  append(...kids) { for (const k of kids) this.children.push(typeof k === 'string' ? new Text(k) : k); }
  addEventListener(t, f) { (this.listeners[t] ||= []).push(f); }
  async fire(t) { for (const f of this.listeners[t] || []) await f({ target: this }); }
  set textContent(v) { this.children = []; this._text = String(v); }
  get textContent() { return this._text + this.children.map((c) => c.textContent).join(''); }
  all() { return [this, ...this.children.flatMap((c) => (c.all ? c.all() : []))]; }
}
class Text { constructor(t) { this.t = t; } get textContent() { return this.t; } }
const byId = {};
const radios = [];
for (const m of html.matchAll(/<(\w+)([^>]*?)>/g)) {
  const attrs = {};
  for (const a of m[2].matchAll(/([\w-]+)(?:="([^"]*)")?/g)) attrs[a[1]] = a[2] ?? '';
  const n = new Node(m[1], attrs);
  if (attrs.id) byId[attrs.id] = n;
  if (m[1] === 'input' && attrs.name === 'clock') radios.push(n);
  if (attrs['data-copy'] || attrs['data-tip']) (byId.__data ||= []).push(n);
}
const document = {
  getElementById: (id) => byId[id] || null,
  createElement: (t) => new Node(t),
  querySelector: (sel) => { const m = /input\[name=clock\](?:\[value=(\w+)\])?(:checked)?/.exec(sel); if (!m) return null; return m[2] ? radios.find((r) => r.checked) : radios.find((r) => r.attrs.value === m[1]); },
  querySelectorAll: (sel) => (sel === 'input[name=clock]' ? radios : (byId.__data || []).filter((n) => (sel === '[data-copy]' ? n.attrs['data-copy'] : n.attrs['data-tip']))),
};
// radio exclusivity
for (const r of radios) Object.defineProperty(r, 'checked', { get() { return this._c; }, set(v) { if (v) radios.forEach((o) => { if (o !== this) o._c = false; }); this._c = v; } });
radios[0].checked = true;
const ctx = { document, window: {}, navigator: {}, setTimeout: (f) => 0, clearTimeout: () => {}, console, TextEncoder, TextDecoder, atob, BigInt, Date, JSON, Math, Number, String, Object, Array, Set, Map, RegExp, Error, Uint8Array, Uint32Array, Promise };
ctx.window = ctx; ctx.globalThis = ctx; ctx.window.addEventListener = () => {};
vm.createContext(ctx);
for (const f of ['doctor.js', 'examples.js', 'app.js']) vm.runInContext(readFileSync(here(f), 'utf8'), ctx, { filename: f });
let passed = 0, failed = 0;
const ok = (c, m) => { if (c) { passed++; console.log('  ✓ ' + m); } else { failed++; console.log('  ✗ ' + m); } };
const exButtons = byId.examples.children;
ok(exButtons.length === ctx.X402_EXAMPLES.length && exButtons.length >= 10, `${exButtons.length} example buttons rendered`);
for (const b of exButtons) {
  await b.fire('click');
  const out = byId.results;
  const nodes = out.all();
  const verdict = nodes.find((n) => /verdict v-/.test(n.className || ''));
  const links = nodes.filter((n) => n.tagName === 'a' && /^errors\//.test(n.attrs.href || ''));
  const badLinks = links.filter((n) => !existsSync(here(n.attrs.href)));
  const expectV = { ok: 'v-ok', 'v-zero': 'v-warnings', 'smart-wallet': 'v-warnings' }[ctx.X402_EXAMPLES[[...exButtons].indexOf(b)].id] || 'v-problems';
  ok(verdict && verdict.className.includes(expectV) && badLinks.length === 0 && nodes.some((n) => n.tagName === 'details'), `example "${b.textContent}": ${verdict && verdict.className.replace('verdict ', '')} (expected ${expectV}), ${links.length} code links (all exist), decoded panes shown`);
}
ok(byId['clock-custom'].value === String(ctx.X402_EXAMPLES.at(-1).now), 'loading an example switches the clock to the example time');
await byId.clear.fire('click');
ok(byId.results.children.length === 0 && byId['in-payment'].value === '', 'Clear empties inputs and results');
ok(byId['tip-box'].hidden === false && byId['tip-evm'].textContent === '0x73218b6438e15E75B115EA47837F2a7fde79f623', 'EVM tip address passes EIP-55 check and is shown');
ok(byId['tip-sol-row'].hidden === false && byId['tip-btc-row'].hidden === false, 'Solana (base58, 32 bytes) and Bitcoin (bech32 checksum) addresses validated and shown');
ok(byId['tip-buttons'].hidden === true, 'wallet tip buttons stay hidden without window.ethereum');
// Wallet tip flow with a mocked EIP-1193 provider (no real wallet, nothing is sent anywhere).
{
  const calls = [];
  ctx.window.ethereum = { request: async ({ method, params }) => { calls.push({ method, params }); if (method === 'eth_requestAccounts') return ['0x1111111111111111111111111111111111111111']; if (method === 'eth_chainId') return calls.some((c) => c.method === 'wallet_switchEthereumChain') ? '0x2105' : '0x1'; if (method === 'wallet_switchEthereumChain') return null; if (method === 'eth_sendTransaction') return '0x' + 'ef'.repeat(32); throw new Error('unexpected ' + method); } };
  ctx.window.confirm = () => true;
  const tipBtn = (byId.__data || []).find((n) => n.attrs['data-tip'] === '5');
  await tipBtn.fire('click');
  const send = calls.find((c) => c.method === 'eth_sendTransaction');
  const data = send && send.params[0].data;
  const expectData = '0xa9059cbb' + '73218b6438e15e75b115ea47837f2a7fde79f623'.padStart(64, '0') + (5n * 10n ** 6n).toString(16).padStart(64, '0');
  ok(calls.map((c) => c.method).join(',') === 'eth_requestAccounts,eth_chainId,wallet_switchEthereumChain,eth_chainId,eth_sendTransaction', 'tip: connects, switches to Base (0x2105), then sends');
  ok(send && send.params[0].to === '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' && data === expectData && send.params[0].value === '0x0', 'tip: USDC transfer(0x7321…f623, 5 USDC) on the Base USDC contract, no ETH value');
  ok(/Thank you/.test(byId['tip-status'].textContent), 'tip: thank-you message with the tx link');
  calls.length = 0;
  ctx.window.confirm = () => false;
  await tipBtn.fire('click');
  ok(calls.length === 0, 'tip: declining the confirm dialog makes no wallet request');
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
