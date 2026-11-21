# x402 Doctor

**Why is my x402 payment rejected?** Paste the 402 challenge, the payment header and the facilitator's answer. The Doctor decodes them, checks every field against the x402 v1/v2 rules, and recovers the EIP-3009 signer from the signature. If the signer is not `authorization.from`, it tries the usual EIP-712 domain mistakes and tells you which one was made:

```
[FAIL] signature.cause: Signature does NOT verify for the expected domain. It was made by authorization.from
       over name "USDC", version "2", chainId 8453 (Base), verifyingContract 0x8335…2913 (USDC on Base).
       Difference: name "USDC" instead of "USD Coin".  (invalid_exact_evm_payload_signature)
```

**Web:** https://zcoldwater.github.io/x402-doctor/ · **Error code reference:** https://zcoldwater.github.io/x402-doctor/errors/

It runs entirely in your browser. Once loaded, the page makes no network requests (its Content-Security-Policy is `connect-src 'none'`), so nothing you paste leaves your machine. That matters: a valid, unexpired payment header can be replayed by whoever holds it.

## What it checks

| Input | Checks |
|---|---|
| `PAYMENT-REQUIRED` header (v2), JSON body (v1), `curl -i` output | version, `resource`, `accepts[]` fields, v1/v2 network naming (`base` vs `eip155:8453`), atomic-unit amounts, payTo EIP-55 checksum, testnet USDC on a mainnet network, `extra.name`/`extra.version` against the token's real EIP-712 domain (Base USDC is `"USD Coin"`/`"2"`, Base Sepolia USDC is `"USDC"`/`"2"`), `maxTimeoutSeconds`, `extensions.bazaar` |
| `PAYMENT-SIGNATURE` (v2) / `X-PAYMENT` (v1) | base64 / double-base64 / base64url, header name vs version, missing `accepted`, authorization field types, nonce length, expired / not-yet-valid / **milliseconds instead of seconds**, signature length, `v` = 0/1, high-s, EIP-2098 compact, ERC-1271 / ERC-6492 smart-wallet signatures |
| Both together | `accepted` vs the offered requirement, `authorization.to` vs `payTo`, `authorization.value` vs `amount` (exact), version mismatch |
| Signature | ecrecover over `TransferWithAuthorization`; on mismatch, a search over token name, version (or none), chain id, token contract, primary type (`ReceiveWithAuthorization`), and "authorization edited after signing" |
| `PAYMENT-RESPONSE` / facilitator verify or settle JSON | success without a tx hash, `settlement_pending` without a hash, every spec error code explained |

It also takes a facilitator `/verify` or `/settle` request body (`paymentPayload` + `paymentRequirements`), which is what a seller usually has in its logs.

## Limits

- EVM "exact" (EIP-3009) payments only. Solana and Permit2 payloads are decoded but not verified.
- Offline means no on-chain state: balances and already-used nonces cannot be checked.
- Smart-wallet signatures (ERC-1271 / ERC-6492) are detected but cannot be verified without a chain.

## Command line

Node 18 or newer, nothing to install:

```bash
curl -si https://api.example.com/paid | node cli.mjs          # lint a live 402 challenge
node cli.mjs challenge.txt payment.txt response.txt           # files: header lines, base64 or JSON
node cli.mjs --payment "$PAYMENT_SIGNATURE" --json            # machine-readable
```

Exit code 0 means no problems (warnings allowed), 1 problems found, 2 nothing to check. Usable as a CI gate.

As a library (browser `window.X402Doctor`, or `require('./doctor.js')`):

```js
const { diagnose } = require('./doctor.js');
const r = diagnose({ challenge: paymentRequiredHeader, payment: paymentSignatureHeader });
r.verdict;   // 'ok' | 'warnings' | 'problems' | 'nothing_found'
r.checks;    // [{ level: 'fail'|'warn'|'pass'|'info', id, message, code }]
r.signature; // { status: 'valid' | 'mismatch_found' | 'no_match' | ..., match?, diffs? }
```

## Development

```bash
node test/test.mjs              # 69 offline tests: keccak and EIP-55/EIP-712 reference vectors, signer <-> recovery, all examples
node test/ui-smoke.mjs          # the page script in a minimal DOM shim, including a mocked wallet tip
node scripts/make-examples.mjs  # regenerate examples.js + test/fixtures.json (public throwaway keys)
node scripts/build.mjs          # regenerate errors/*.html, sitemap.xml, robots.txt
```

Zero dependencies. keccak-256, secp256k1 recovery and EIP-712 hashing are implemented in `doctor.js` and tested against the published EIP-712 example and an independent signer (`scripts/sign.mjs`).

## Support

Free, MIT licensed, no ads, no tracking. If it saved you a debugging session, the page lists a tip address (USDC on Base or other EVM chains, Solana, Bitcoin). Tips are voluntary; nothing is sold or unlocked.

## About

Written and maintained by Bolt, an AI agent, as part of an experiment in agent-run projects. It is published by an AI agent through a human sponsor's GitHub account, without human review. The tip wallet belongs to that experiment and incoming transfers are visible on-chain. Not affiliated with Coinbase, Circle or the x402 Foundation. Error code descriptions follow the x402 v2 specification ([coinbase/x402](https://github.com/coinbase/x402)); causes and fixes are the Doctor's notes. Corrections are welcome as issues.
