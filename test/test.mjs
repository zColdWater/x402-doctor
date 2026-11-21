// Offline tests for x402 Doctor. Node >= 18, no dependencies, no network.
//   node test/test.mjs
import { readFileSync, readdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { signAuthorization, addressOf } from '../scripts/sign.mjs';

const require = createRequire(import.meta.url);
const D = require('../doctor.js');
const EX = require('../examples.js');
const F = JSON.parse(readFileSync(new URL('./fixtures.json', import.meta.url), 'utf8'));

let passed = 0; let failed = 0;
const ok = (cond, msg, extra) => { if (cond) { passed++; console.log('  ✓ ' + msg); } else { failed++; console.log('  ✗ ' + msg + (extra !== undefined ? '\n      ' + JSON.stringify(extra).slice(0, 600) : '')); } };
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64');

console.log('keccak-256');
ok(D.keccakHex(new Uint8Array(0)) === '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470', 'keccak256("")');
ok(D.keccakHex(new TextEncoder().encode('abc')) === '0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45', 'keccak256("abc")');
// Reference values computed with an independent keccak implementation, around the 136-byte rate boundary.
const ref = { 135: '0xcbdfd9dee5faad3818d6b06f95a219fd290b0e1706f6a82e5a595b9ce9faca62', 136: '0x7ce759f1ab7f9ce437719970c26b0a66ff11fe3e38e17df89cf5d29c7d7f807e', 137: '0xac73d4fae68b8453f764007c1a20ce95994187861f0c3227a3a8e99a73a3b1db', 272: '0xfdf2ec49e749960d3c8521a0219af8d03e30e2b3bf19bd16150ee0eaf133d66e' };
for (const [len, h] of Object.entries(ref)) ok(D.keccakHex(new Uint8Array(Number(len)).map((_, i) => i & 255)) === h, `keccak256 of ${len} bytes (rate boundary)`);
ok(D.keccakHex('TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)') === '0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267', 'EIP-3009 TransferWithAuthorization typehash');

console.log('EIP-55 (vectors from the EIP)');
for (const a of ['0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed', '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359', '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB', '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb']) {
  ok(D.toChecksum(a.toLowerCase()) === a && D.addressForm(a) === 'checksummed', a);
}
ok(D.addressForm('0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD') === 'bad_checksum', 'one flipped letter -> bad_checksum');
ok(D.addressForm('0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed') === 'lowercase' && D.addressForm('0x123') === 'invalid', 'lowercase / invalid forms');

console.log('EIP-712 reference example ("Ether Mail") and secp256k1 recovery');
{
  const types = { Person: [{ name: 'name', type: 'string' }, { name: 'wallet', type: 'address' }], Mail: [{ name: 'from', type: 'Person' }, { name: 'to', type: 'Person' }, { name: 'contents', type: 'string' }] };
  const domain = { name: 'Ether Mail', version: '1', chainId: 1, verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC' };
  const message = { from: { name: 'Cow', wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826' }, to: { name: 'Bob', wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB' }, contents: 'Hello, Bob!' };
  ok(D.encodeType('Mail', types) === 'Mail(Person from,Person to,string contents)Person(string name,address wallet)', 'encodeType with nested struct');
  ok(D.domainSeparator(domain) === '0xf2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f', 'domain separator');
  const digest = D.typedDataDigest({ domain, types, primaryType: 'Mail', message });
  ok(digest === '0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2', 'signing digest');
  const sig = '0x4355c47d63924e8a72e509b65029052eb6c299d53a04e167c5775fd466751c9d07299936d304c153f6443dfa05f40ff007d72911b6f72307f996231605b915621c';
  ok(D.recover(digest, sig) === '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826', 'recover() returns Cow from the spec signature (v = 28)');
  ok(D.recover(digest, sig.slice(0, -2) + '01') === '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826', 'recover() accepts v = 1 for the same signature');
  ok(addressOf(D.keccakHex('cow')) === '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826', 'test signer: address of keccak("cow")');
}

console.log('signer <-> recovery agreement on random keys');
for (let i = 0; i < 12; i++) {
  const key = D.keccakHex('random key ' + i);
  const from = addressOf(key);
  const domain = { name: 'USD Coin', version: '2', chainId: [8453, 84532, 1, 137][i % 4], verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' };
  const message = { from, to: addressOf(D.keccakHex('to ' + i)), value: String(10 ** (i % 7)), validAfter: '0', validBefore: String(2e9 + i), nonce: D.keccakHex('n' + i) };
  const sig = signAuthorization({ keyHex: key, domain, message, highS: i % 3 === 0 });
  const digest = D.typedDataDigest({ domain, types: D.EIP3009_TYPES, primaryType: 'TransferWithAuthorization', message });
  const ps = D.parseSignature(sig);
  ok(D.recover(digest, sig) === from && ps.highS === (i % 3 === 0), `key ${i}: recovered = signer${i % 3 === 0 ? ' (high-s detected)' : ''}`);
}

console.log('examples (generated by scripts/make-examples.mjs with the test signer)');
ok(Array.isArray(EX) && EX.length === F.examples.length && EX.every((e, i) => e.id === F.examples[i].id && JSON.stringify(e.texts) === JSON.stringify(F.examples[i].texts)), 'examples.js matches test/fixtures.json');
for (const e of F.examples) {
  const t0 = Date.now();
  const r = D.diagnose(e.texts, { now: e.now });
  const ms = Date.now() - t0;
  const x = e.expect;
  const msgs = r.checks.map((c) => c.id + ': ' + c.message).join('\n');
  const good = (!x.verdict || r.verdict === x.verdict)
    && (!x.signature || r.signature.status === x.signature)
    && (!x.codes || x.codes.every((c) => r.codes.includes(c)))
    && (!x.diff || msgs.includes(x.diff))
    && (!x.check || r.checks.some((c) => c.id.includes(x.check) && (c.level === 'fail' || c.level === 'warn')));
  ok(good, `${e.id}: ${e.title} -> ${r.verdict}, signature ${r.signature.status} (${ms} ms)`, { verdict: r.verdict, sig: r.signature.status, codes: r.codes, checks: r.checks.filter((c) => c.level !== 'info') });
}

console.log('signature search: no match');
{
  const ex = F.examples.find((e) => e.id === 'ok');
  const pay = D.extract({ payment: ex.texts.payment }).payment;
  const wrongKey = D.keccakHex('somebody else');
  pay.payload.signature = signAuthorization({ keyHex: wrongKey, domain: { name: 'USD Coin', version: '2', chainId: 8453, verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' }, message: pay.payload.authorization });
  const t0 = Date.now();
  const r = D.diagnose({ challenge: ex.texts.challenge, payment: b64(pay) }, { now: ex.now });
  const ms = Date.now() - t0;
  const cause = r.checks.find((c) => c.id === 'signature.cause');
  ok(r.signature.status === 'no_match' && cause && cause.message.includes(addressOf(wrongKey)) && r.signature.tried >= 200, `signed by another key -> no_match, names the recovered signer, searched ${r.signature.tried} variants`, cause);
  ok(ms < 8000, `full search finishes in ${ms} ms`);
  pay.payload.authorization.validBefore = String(Number(pay.payload.authorization.validBefore) + 1);
  pay.payload.signature = signAuthorization({ keyHex: D.keccakHex('x402-doctor example payer key - public, never fund it'), domain: { name: 'USD Coin', version: '2', chainId: 8453, verifyingContract: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' }, message: { ...pay.payload.authorization, validBefore: String(Number(pay.payload.authorization.validBefore) - 1) } });
  const r2 = D.diagnose({ payment: b64(pay) }, { now: ex.now });
  ok(r2.signature.status === 'no_match', 'authorization edited after signing (validBefore + 1) -> no_match', r2.signature);
}

console.log('decoding');
{
  const ex = F.examples.find((e) => e.id === 'ok');
  const payObj = D.extract({ payment: ex.texts.payment }).payment;
  const twice = Buffer.from(b64(payObj)).toString('base64');
  let r = D.diagnose({ payment: twice }, { now: ex.now });
  ok(r.found.includes('payment') && r.checks.some((c) => /base64-encoded twice/.test(c.message)), 'double base64 is decoded and flagged');
  const url = b64(payObj).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  r = D.diagnose({ payment: url }, { now: ex.now });
  ok(r.found.includes('payment') && r.signature.status === 'valid', 'base64url without padding is accepted');
  r = D.diagnose({ challenge: '< HTTP/2 402\n< payment-required: ' + ex.texts.challenge.match(/payment-required: (\S+)/)[1] + '\n< content-type: application/json\n<' }, { now: ex.now });
  ok(r.found.includes('challenge') && r.checks.some((c) => c.id === 'challenge.version' && c.level === 'pass'), 'curl -v style "< header: value" lines are parsed');
  r = D.diagnose({ payment: JSON.stringify(payObj) }, { now: ex.now });
  ok(r.checks.some((c) => c.id === 'payment.encoding'), 'raw JSON payment gets a "must be base64 on the wire" note');
  r = D.diagnose({ challenge: 'hello world' });
  ok(r.verdict === 'nothing_found' && r.checks.some((c) => c.level === 'warn'), 'garbage -> nothing_found with a decode warning');
  const v2c = D.extract({ challenge: ex.texts.challenge }).challenge;
  r = D.diagnose({ challenge: 'HTTP/2 402\ncontent-type: application/json\n\n' + JSON.stringify(v2c) });
  ok(r.checks.some((c) => c.id === 'challenge.header' && c.level === 'warn'), 'v2 challenge in body only -> warns that v2 clients read PAYMENT-REQUIRED');
}

console.log('challenge checks');
{
  const base = D.extract({ challenge: F.examples[0].texts.challenge }).challenge;
  const mk = (over) => ({ ...base, accepts: [{ ...base.accepts[0], ...over }] });
  let r = D.diagnose({ challenge: b64(mk({ network: 'base' })) });
  ok(r.checks.some((c) => c.id.endsWith('.network') && c.level === 'fail' && /eip155:8453/.test(c.message)), 'v2 with v1 network name -> fail, suggests eip155:8453');
  r = D.diagnose({ challenge: b64(mk({ amount: 0.01 })) });
  ok(r.checks.some((c) => c.id.endsWith('.amount') && c.level === 'fail'), 'amount as a JSON number -> fail');
  r = D.diagnose({ challenge: b64(mk({ asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e' })) });
  ok(r.checks.some((c) => c.id.endsWith('.asset') && c.level === 'fail' && /Base Sepolia/.test(c.message)), 'testnet USDC address on a mainnet network -> fail');
  r = D.diagnose({ challenge: b64(mk({ payTo: '0x2cca1e8BA78d0f8096EbDd5A00171daBB4A464DE' })) });
  ok(r.checks.some((c) => c.id.endsWith('.payTo') && c.level === 'fail' && /checksum/.test(c.message)), 'payTo with a broken EIP-55 checksum -> fail');
  r = D.diagnose({ challenge: b64(mk({ extra: { name: 'USD Coin', version: '1' } })) });
  ok(r.checks.some((c) => c.id.endsWith('.extra.version') && c.level === 'fail'), 'wrong extra.version for Base USDC -> fail');
  r = D.diagnose({ challenge: b64(mk({})) });
  ok(r.verdict === 'ok' && r.checks.some((c) => /Price: \$0\.01 USDC on Base/.test(c.message)), 'good challenge -> ok, price shown as $0.01 USDC on Base');
}

console.log('settlement / verify responses');
{
  let r = D.diagnose({ response: JSON.stringify({ success: true, transaction: '', network: 'eip155:8453' }) });
  ok(r.checks.some((c) => c.id === 'settlement.transaction' && c.level === 'warn'), 'success:true without a tx hash -> warn');
  r = D.diagnose({ response: JSON.stringify({ success: false, errorReason: 'settlement_pending', transaction: '', network: 'eip155:8453' }) });
  ok(r.checks.some((c) => c.id === 'settlement.pending' && c.level === 'fail') && r.codes.includes('settlement_pending'), 'settlement_pending without tx -> fail (cannot reconcile)');
  r = D.diagnose({ response: JSON.stringify({ isValid: false, invalidReason: 'insufficient_funds', payer: F.payer }) });
  ok(r.codes.includes('insufficient_funds') && r.verdict === 'problems', 'verify response isValid:false -> code surfaced');
  r = D.diagnose({ response: 'X-PAYMENT-RESPONSE: ' + b64({ success: true, transaction: '0x' + '12'.repeat(32), network: 'base' }) });
  ok(r.settlement.explorer === 'https://basescan.org/tx/0x' + '12'.repeat(32), 'v1 settlement header -> explorer link');
}

console.log('error code reference');
{
  const spec = ['insufficient_funds', 'invalid_exact_evm_payload_authorization_valid_after', 'invalid_exact_evm_payload_authorization_valid_before', 'invalid_exact_evm_payload_authorization_value_mismatch', 'invalid_exact_evm_payload_signature', 'invalid_exact_evm_payload_recipient_mismatch', 'invalid_network', 'invalid_payload', 'invalid_payment_requirements', 'invalid_scheme', 'unsupported_scheme', 'invalid_x402_version', 'invalid_transaction_state', 'unexpected_verify_error', 'unexpected_settle_error', 'settlement_pending'];
  ok(spec.every((c) => D.ERROR_CODES[c] && D.ERROR_CODES[c].spec && D.ERROR_CODES[c].causes.length && D.ERROR_CODES[c].fix), 'all 16 x402 v2 spec error codes documented');
  const all = F.examples.flatMap((e) => D.diagnose(e.texts, { now: e.now }).codes);
  ok(all.every((c) => D.ERROR_CODES[c]), 'every code the Doctor emits has a reference entry');
  let pages = [];
  try { pages = readdirSync(new URL('../errors/', import.meta.url)).filter((n) => n.endsWith('.html')); } catch (_) { /* not built */ }
  ok(pages.length === 0 || spec.every((c) => pages.includes(c + '.html')), pages.length ? `errors/ has a page per code (${pages.length} pages)` : 'errors/ not built yet (run scripts/build.mjs)');
}

console.log('privacy: the page code never talks to the network');
for (const f of ['doctor.js', 'app.js']) {
  let src = '';
  try { src = readFileSync(new URL('../' + f, import.meta.url), 'utf8'); } catch (_) { continue; }
  ok(!/\bfetch\s*\(|XMLHttpRequest|WebSocket|sendBeacon|EventSource|navigator\.sendBeacon|importScripts|new Image\s*\(/.test(src), `${f}: no fetch / XHR / WebSocket / beacon / image pings`);
}
try {
  const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
  ok(/connect-src 'none'/.test(html) && !/<script[^>]+src="https?:/.test(html), 'index.html: CSP connect-src none, no third-party scripts');
} catch (_) { /* not built */ }

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
