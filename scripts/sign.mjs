// Test-only EIP-3009 signer used to generate the examples and test fixtures (Node >= 18).
// The signing math (affine secp256k1, RFC 6979, low-s) is a separate implementation from doctor.js's Jacobian
// recovery, so the tests check one against the other. Hashing (keccak / EIP-712) comes from doctor.js and is
// pinned by the EIP-712 "Ether Mail" reference vector in test/test.mjs.
import { createHmac } from 'node:crypto';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const D = require('../doctor.js');

const P = 2n ** 256n - 2n ** 32n - 977n;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n];
const mod = (a, m = P) => { const r = a % m; return r >= 0n ? r : r + m; };
function inv(a, m = P) {
  let [lm, hm, low, high] = [1n, 0n, mod(a, m), m];
  while (low > 1n) { const r = high / low; [lm, hm] = [hm - lm * r, lm]; [low, high] = [high - low * r, low]; }
  return mod(lm, m);
}
function add(p1, p2) {
  if (!p1) return p2;
  if (!p2) return p1;
  const [x1, y1] = p1; const [x2, y2] = p2;
  let l;
  if (x1 === x2) { if (mod(y1 + y2) === 0n) return null; l = mod(3n * x1 * x1 * inv(2n * y1)); } else l = mod((y2 - y1) * inv(x2 - x1));
  const x3 = mod(l * l - x1 - x2);
  return [x3, mod(l * (x1 - x3) - y1)];
}
function mul(k, p = G) { let r = null; let a = p; while (k > 0n) { if (k & 1n) r = add(r, a); a = add(a, a); k >>= 1n; } return r; }
const word = (n) => Buffer.from(BigInt(n).toString(16).padStart(64, '0'), 'hex');

export function addressOf(keyHex) {
  const pt = mul(BigInt(keyHex));
  return D.toChecksum(D.bytesToHex(D.keccak256(new Uint8Array(Buffer.concat([word(pt[0]), word(pt[1])]))).subarray(12)));
}

function rfc6979(d, z) {
  const hmac = (k, ...m) => createHmac('sha256', k).update(Buffer.concat(m)).digest();
  const x = word(d); const h = word(mod(z, N));
  let V = Buffer.alloc(32, 1); let K = Buffer.alloc(32, 0);
  K = hmac(K, V, Buffer.from([0]), x, h); V = hmac(K, V);
  K = hmac(K, V, Buffer.from([1]), x, h); V = hmac(K, V);
  for (;;) {
    V = hmac(K, V);
    const k = BigInt('0x' + V.toString('hex'));
    if (k > 0n && k < N) return k;
    K = hmac(K, V, Buffer.from([0])); V = hmac(K, V);
  }
}

/** Sign a 32-byte digest. opts: { vOffset: 27|0, highS: false }. Returns 0x r||s||v (65 bytes). */
export function signDigest(digestHex, keyHex, opts = {}) {
  const d = BigInt(keyHex); const z = BigInt(digestHex);
  const k = rfc6979(d, z);
  const R = mul(k);
  const r = mod(R[0], N);
  let s = mod(inv(k, N) * (z + r * d), N);
  let rec = Number(R[1] & 1n);
  if (s > N / 2n) { s = N - s; rec ^= 1; }
  if (opts.highS) { s = N - s; rec ^= 1; }
  const v = (opts.vOffset === undefined ? 27 : opts.vOffset) + rec;
  return '0x' + r.toString(16).padStart(64, '0') + s.toString(16).padStart(64, '0') + v.toString(16).padStart(2, '0');
}

export function signAuthorization({ keyHex, domain, message, primaryType = 'TransferWithAuthorization', vOffset, highS }) {
  const digest = D.typedDataDigest({ domain, types: D.EIP3009_TYPES, primaryType, message });
  return signDigest(digest, keyHex, { vOffset, highS });
}
