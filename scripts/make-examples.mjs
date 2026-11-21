// Generates examples.js (the "Load example" buttons) and test/fixtures.json.
//   node scripts/make-examples.mjs
// Keys below are throwaway example keys derived from public strings. Never send funds to their addresses.
import { writeFileSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';
import { signAuthorization, addressOf } from './sign.mjs';

const require = createRequire(import.meta.url);
const D = require('../doctor.js');
const root = new URL('..', import.meta.url);

const PAYER_KEY = D.keccakHex('x402-doctor example payer key - public, never fund it');
const PAYER = addressOf(PAYER_KEY);
const SELLER = addressOf(D.keccakHex('x402-doctor example seller key - public, never fund it'));
const OTHER = addressOf(D.keccakHex('x402-doctor example other address - public, never fund it'));
const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const USDC_BASE_SEPOLIA = '0x036CbD53842c5426634e7929541eC2318f3dCF7e';
const NOW = 1795200000; // fixed clock for reproducible examples (2026-11-20T18:40:00Z)
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64');
const nonce = (tag) => D.keccakHex('nonce:' + tag);

const BASE_DOMAIN = { name: 'USD Coin', version: '2', chainId: 8453, verifyingContract: USDC_BASE };
const req2 = (over = {}) => ({ scheme: 'exact', network: 'eip155:8453', amount: '10000', asset: USDC_BASE, payTo: SELLER, maxTimeoutSeconds: 60, extra: { name: 'USD Coin', version: '2' }, ...over });
const challenge2 = (accepts, over = {}) => ({
  x402Version: 2,
  error: 'Payment required',
  resource: { url: 'https://api.example.com/v1/weather?city=Lisbon', description: 'Current weather for one city', mimeType: 'application/json' },
  accepts,
  extensions: { bazaar: { info: { input: { type: 'http', method: 'GET', queryParams: { city: 'Lisbon' } }, output: { type: 'json', example: { tempC: 18 } } } } },
  ...over,
});
const auth = (over = {}) => ({ from: PAYER, to: SELLER, value: '10000', validAfter: String(NOW - 600), validBefore: String(NOW + 60), nonce: nonce('default'), ...over });
const pay2 = ({ accepted = req2(), authorization = auth(), domain = BASE_DOMAIN, primaryType, vOffset, highS, signature } = {}) => ({
  x402Version: 2,
  resource: { url: 'https://api.example.com/v1/weather?city=Lisbon' },
  accepted,
  payload: { signature: signature || signAuthorization({ keyHex: PAYER_KEY, domain, message: authorization, primaryType, vOffset, highS }), authorization },
});
const curl = (status, headers, body) => [`HTTP/2 ${status}`, ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`), '', body ? JSON.stringify(body, null, 2) : ''].join('\n').trim();

const examples = [];
const ex = (id, title, explain, texts, expect) => examples.push({ id, title, explain, now: NOW, texts, expect });

// 1. Everything right.
{
  const c = challenge2([req2()]);
  const p = pay2();
  ex('ok', 'Valid v2 payment', 'A correct x402 v2 challenge, payment and settlement on Base.', {
    challenge: curl(402, { 'content-type': 'application/json', 'payment-required': b64(c), 'access-control-expose-headers': 'PAYMENT-REQUIRED, PAYMENT-RESPONSE' }, {}),
    payment: 'PAYMENT-SIGNATURE: ' + b64(p),
    response: 'PAYMENT-RESPONSE: ' + b64({ success: true, transaction: '0x' + 'ab'.repeat(32), network: 'eip155:8453', payer: PAYER }),
  }, { verdict: 'ok', signature: 'valid' });
}
// 2. Client signed with the testnet token name.
{
  const c = challenge2([req2()]);
  const p = pay2({ domain: { ...BASE_DOMAIN, name: 'USDC' } });
  ex('wrong-name', 'Wrong token name in the EIP-712 domain', 'The client signed with name "USDC" (the Base Sepolia token) for Base mainnet USDC, whose name is "USD Coin". The facilitator answers invalid_exact_evm_payload_signature.', {
    challenge: b64(c), payment: b64(p),
    response: JSON.stringify({ success: false, errorReason: 'invalid_exact_evm_payload_signature', transaction: '', network: 'eip155:8453' }),
  }, { verdict: 'problems', signature: 'mismatch_found', diff: 'name "USDC"', codes: ['invalid_exact_evm_payload_signature'] });
}
// 3. Signed on the testnet chain and token.
{
  const c = challenge2([req2()]);
  const p = pay2({ domain: { name: 'USDC', version: '2', chainId: 84532, verifyingContract: USDC_BASE_SEPOLIA } });
  ex('testnet-domain', 'Signed for Base Sepolia, sent to Base', 'The wallet was still on Base Sepolia: chainId 84532 and the testnet USDC contract are in the signed domain.', {
    challenge: b64(c), payment: b64(p),
  }, { verdict: 'problems', signature: 'mismatch_found', diff: 'chainId 84532' });
}
// 4. Server bug: wrong extra.name in the challenge; the client trusted it.
{
  const bad = req2({ extra: { name: 'USDC', version: '2' } });
  const c = challenge2([bad]);
  const p = pay2({ accepted: bad, domain: { ...BASE_DOMAIN, name: 'USDC' } });
  ex('server-extra', 'Server advertises the wrong extra.name', 'The seller\'s challenge says extra.name "USDC" for Base mainnet USDC. Every client that trusts it signs the wrong domain, so every payment fails. Seen from the facilitator request body the seller logs.', {
    challenge: JSON.stringify({ x402Version: 2, paymentPayload: p, paymentRequirements: bad }, null, 2), payment: '', response: '',
  }, { verdict: 'problems', signature: 'mismatch_found', codes: ['invalid_exact_evm_payload_signature'], check: 'extra.name' });
}
// 5. v = 0/1 and high s.
{
  const c = challenge2([req2()]);
  const p = pay2({ vOffset: 0, authorization: auth({ nonce: nonce('v0') }) });
  ex('v-zero', 'Signature with v = 0/1', 'Some signing libraries return the recovery id (0/1) as v. USDC\'s signature check wants 27/28.', { challenge: b64(c), payment: b64(p) }, { verdict: 'warnings', signature: 'valid', check: 'signature.v' });
}
// 6. Milliseconds + expired.
{
  const c = challenge2([req2()]);
  const a = auth({ validAfter: String((NOW - 600) * 1000), validBefore: String((NOW + 60) * 1000), nonce: nonce('ms') });
  const p = pay2({ authorization: a });
  ex('milliseconds', 'Timestamps in milliseconds', 'validAfter/validBefore were built with Date.now() (milliseconds). EIP-3009 uses Unix seconds, so the authorization is "not valid yet" for ~50,000 years.', { challenge: b64(c), payment: b64(p) }, { verdict: 'problems', codes: ['invalid_exact_evm_payload_authorization_valid_after'] });
}
// 7. Expired header replayed.
{
  const c = challenge2([req2()]);
  const a = auth({ validAfter: String(NOW - 4000), validBefore: String(NOW - 3540), nonce: nonce('expired') });
  ex('expired', 'Expired payment header', 'A cached PAYMENT-SIGNATURE was replayed an hour later.', { challenge: b64(c), payment: b64(pay2({ authorization: a })) }, { verdict: 'problems', codes: ['invalid_exact_evm_payload_authorization_valid_before'] });
}
// 8. Amount and recipient mismatch (valid signature over the wrong values).
{
  const c = challenge2([req2()]);
  const a = auth({ to: OTHER, value: '10000000', nonce: nonce('mismatch') });
  ex('mismatch', 'Paid the wrong amount to the wrong address', 'The signature is fine, but it authorizes $10.00 to a different address: the client used dollars instead of atomic units and a cached payTo.', {
    challenge: b64(c), payment: b64(pay2({ accepted: req2({ payTo: OTHER, amount: '10000000' }), authorization: a })),
  }, { verdict: 'problems', signature: 'valid', codes: ['invalid_exact_evm_payload_recipient_mismatch', 'invalid_exact_evm_payload_authorization_value_mismatch'] });
}
// 9. v2 payload without "accepted", sent in X-PAYMENT.
{
  const c = challenge2([req2()]);
  const p = pay2();
  delete p.accepted;
  ex('no-accepted', 'v2 payload without "accepted", in X-PAYMENT', 'A hand-rolled client sends the v2 payload in the v1 header and leaves out "accepted".', { challenge: b64(c), payment: 'X-PAYMENT: ' + b64(p) }, { verdict: 'problems', codes: ['invalid_payload', 'invalid_x402_version'] });
}
// 10. v1 challenge with a CAIP-2 network.
{
  const v1req = { scheme: 'exact', network: 'eip155:8453', maxAmountRequired: '5000', resource: 'https://api.example.com/v1/quote', description: 'Quote', mimeType: 'application/json', payTo: SELLER, maxTimeoutSeconds: 60, asset: USDC_BASE, extra: { name: 'USD Coin', version: '2' } };
  const a = auth({ value: '5000', nonce: nonce('v1') });
  const p = { x402Version: 1, scheme: 'exact', network: 'base', payload: { signature: signAuthorization({ keyHex: PAYER_KEY, domain: BASE_DOMAIN, message: a }), authorization: a } };
  ex('v1-network', 'v1 challenge with a v2 network id', 'A v1 server advertises network "eip155:8453"; v1 clients expect "base" and cannot match the option.', {
    challenge: curl(402, { 'content-type': 'application/json' }, { x402Version: 1, error: 'X-PAYMENT header is required', accepts: [v1req] }), payment: 'X-PAYMENT: ' + b64(p),
  }, { verdict: 'problems', codes: ['invalid_network'] });
}
// 11. Smart wallet (ERC-6492) signature.
{
  const c = challenge2([req2()]);
  const sig = '0x' + '00'.repeat(32) + '41'.repeat(96) + '6492'.repeat(16);
  ex('smart-wallet', 'Smart-wallet (ERC-6492) signature', 'A counterfactual smart wallet produced a wrapped signature. It cannot be recovered like an EOA signature.', { challenge: b64(c), payment: b64(pay2({ signature: sig, authorization: auth({ nonce: nonce('6492') }) })) }, { verdict: 'warnings', check: 'payment.signature' });
}
// 12. ReceiveWithAuthorization instead of TransferWithAuthorization.
{
  const c = challenge2([req2()]);
  ex('receive-type', 'Wrong primary type', 'The client signed ReceiveWithAuthorization. x402 "exact" on EVM settles with transferWithAuthorization, so the signature does not verify.', {
    challenge: b64(c), payment: b64(pay2({ primaryType: 'ReceiveWithAuthorization', authorization: auth({ nonce: nonce('receive') }) })),
  }, { verdict: 'problems', signature: 'mismatch_found', diff: 'ReceiveWithAuthorization' });
}

const header = '/*! x402 Doctor examples — generated by scripts/make-examples.mjs. Example keys are public: never fund their addresses. */\n';
const body = `(function (root) { const EXAMPLES = ${JSON.stringify(examples.map(({ expect, ...e }) => e), null, 1)};\n  if (typeof module === 'object' && module.exports) module.exports = EXAMPLES; else root.X402_EXAMPLES = EXAMPLES; })(typeof globalThis !== 'undefined' ? globalThis : this);\n`;
writeFileSync(new URL('examples.js', root), header + body);
mkdirSync(new URL('test/', root), { recursive: true });
writeFileSync(new URL('test/fixtures.json', root), JSON.stringify({ payer: PAYER, seller: SELLER, examples }, null, 1) + '\n');
console.log(`wrote ${examples.length} examples (payer ${PAYER}, seller ${SELLER})`);
