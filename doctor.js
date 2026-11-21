/*! x402 Doctor — offline decoder and signature checker for x402 payments. MIT License. Zero dependencies.
 *
 * Runs entirely in the browser (or Node >= 18). It never makes a network request: everything is decoded and
 * checked locally from the text you paste. Works as a classic <script> (window.X402Doctor) and as an ES/CommonJS
 * import in Node.
 *
 * What it does
 *   - decodes PAYMENT-REQUIRED / PAYMENT-SIGNATURE / PAYMENT-RESPONSE (x402 v2) and X-PAYMENT / X-PAYMENT-RESPONSE (v1)
 *     headers, raw JSON, curl -i output, and facilitator /verify or /settle request bodies;
 *   - checks each object against the x402 v1/v2 field rules;
 *   - cross-checks the payment against the challenge (recipient, amount, network, accepted requirement);
 *   - recovers the EIP-3009 signer from the signature, compares it to authorization.from and, when they differ,
 *     searches common EIP-712 domain mistakes (token name, version, chain id, token contract, primary type) to say
 *     what the signature was actually made over.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.X402Doctor = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  // ------------------------------------------------------------------ keccak-256 (32-bit lanes)
  const RC = [
    1, 0, 32898, 0, 32906, 2147483648, 2147516416, 2147483648, 32907, 0, 2147483649, 0, 2147516545, 2147483648,
    32777, 2147483648, 138, 0, 136, 0, 2147516425, 0, 2147483658, 0, 2147516555, 0, 139, 2147483648, 32905,
    2147483648, 32771, 2147483648, 32770, 2147483648, 128, 2147483648, 32778, 0, 2147483658, 2147483648,
    2147516545, 2147483648, 32896, 2147483648, 2147483649, 0, 2147516424, 2147483648,
  ]; // [lo, hi] pairs for the 24 rounds
  const ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
  const PI = new Array(25);
  for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) PI[x + 5 * y] = y + 5 * ((2 * x + 3 * y) % 5);

  function keccakF(s) {
    const C = new Uint32Array(10);
    const B = new Uint32Array(50);
    for (let round = 0; round < 24; round++) {
      for (let x = 0; x < 5; x++) {
        C[2 * x] = s[2 * x] ^ s[2 * x + 10] ^ s[2 * x + 20] ^ s[2 * x + 30] ^ s[2 * x + 40];
        C[2 * x + 1] = s[2 * x + 1] ^ s[2 * x + 11] ^ s[2 * x + 21] ^ s[2 * x + 31] ^ s[2 * x + 41];
      }
      for (let x = 0; x < 5; x++) {
        const x1 = (x + 1) % 5;
        const x4 = (x + 4) % 5;
        const lo = C[2 * x4] ^ ((C[2 * x1] << 1) | (C[2 * x1 + 1] >>> 31));
        const hi = C[2 * x4 + 1] ^ ((C[2 * x1 + 1] << 1) | (C[2 * x1] >>> 31));
        for (let y = 0; y < 25; y += 5) { s[2 * (x + y)] ^= lo; s[2 * (x + y) + 1] ^= hi; }
      }
      for (let i = 0; i < 25; i++) {
        const lo = s[2 * i];
        const hi = s[2 * i + 1];
        const n = ROT[i];
        let rlo;
        let rhi;
        if (n === 0) { rlo = lo; rhi = hi; } else if (n < 32) {
          rlo = (lo << n) | (hi >>> (32 - n)); rhi = (hi << n) | (lo >>> (32 - n));
        } else if (n === 32) { rlo = hi; rhi = lo; } else {
          const m = n - 32; rlo = (hi << m) | (lo >>> (32 - m)); rhi = (lo << m) | (hi >>> (32 - m));
        }
        const j = PI[i];
        B[2 * j] = rlo; B[2 * j + 1] = rhi;
      }
      for (let y = 0; y < 25; y += 5) {
        for (let x = 0; x < 5; x++) {
          const a = 2 * (y + x);
          const b = 2 * (y + ((x + 1) % 5));
          const c = 2 * (y + ((x + 2) % 5));
          s[a] = B[a] ^ (~B[b] & B[c]);
          s[a + 1] = B[a + 1] ^ (~B[b + 1] & B[c + 1]);
        }
      }
      s[0] ^= RC[2 * round];
      s[1] ^= RC[2 * round + 1];
    }
  }

  const utf8 = (str) => new TextEncoder().encode(str);
  function keccak256(input) {
    const data = typeof input === 'string' ? utf8(input) : input;
    const rate = 136;
    const s = new Uint32Array(50);
    const padded = new Uint8Array(Math.floor(data.length / rate) * rate + rate);
    padded.set(data);
    padded[data.length] ^= 0x01;
    padded[padded.length - 1] ^= 0x80;
    for (let off = 0; off < padded.length; off += rate) {
      for (let i = 0; i < rate / 4; i++) {
        const k = off + 4 * i;
        s[i] ^= padded[k] | (padded[k + 1] << 8) | (padded[k + 2] << 16) | (padded[k + 3] << 24);
      }
      keccakF(s);
    }
    const out = new Uint8Array(32);
    for (let i = 0; i < 8; i++) {
      const w = s[i];
      out[4 * i] = w & 255; out[4 * i + 1] = (w >>> 8) & 255; out[4 * i + 2] = (w >>> 16) & 255; out[4 * i + 3] = (w >>> 24) & 255;
    }
    return out;
  }

  // ------------------------------------------------------------------ bytes / hex
  const HEX = /^0x[0-9a-fA-F]*$/;
  function hexToBytes(h) {
    let x = String(h).replace(/^0x/i, '');
    if (x.length % 2) x = '0' + x;
    const out = new Uint8Array(x.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(x.substr(2 * i, 2), 16);
    return out;
  }
  function bytesToHex(b) {
    let s = '0x';
    for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
    return s;
  }
  const concat = (...arr) => {
    const out = new Uint8Array(arr.reduce((n, a) => n + a.length, 0));
    let o = 0;
    for (const a of arr) { out.set(a, o); o += a.length; }
    return out;
  };
  const word = (n) => hexToBytes(BigInt.asUintN(256, BigInt(n)).toString(16).padStart(64, '0'));
  const keccakHex = (x) => bytesToHex(keccak256(typeof x === 'string' && HEX.test(x) ? hexToBytes(x) : x));

  // ------------------------------------------------------------------ addresses
  const isAddress = (a) => typeof a === 'string' && /^0x[0-9a-fA-F]{40}$/.test(a);
  function toChecksum(addr) {
    const lower = addr.toLowerCase().replace(/^0x/, '');
    const h = bytesToHex(keccak256(utf8(lower))).slice(2);
    let out = '0x';
    for (let i = 0; i < 40; i++) out += parseInt(h[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
    return out;
  }
  /** 'checksummed' | 'lowercase' | 'uppercase' | 'bad_checksum' | 'invalid' */
  function addressForm(a) {
    if (!isAddress(a)) return 'invalid';
    const body = a.slice(2);
    if (body === body.toLowerCase()) return 'lowercase';
    if (body === body.toUpperCase()) return 'uppercase';
    return toChecksum(a) === a ? 'checksummed' : 'bad_checksum';
  }
  const sameAddr = (a, b) => isAddress(a) && isAddress(b) && a.toLowerCase() === b.toLowerCase();
  const isSolanaAddress = (a) => typeof a === 'string' && /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(a);

  // ------------------------------------------------------------------ secp256k1 (Jacobian, BigInt)
  const P = 2n ** 256n - 2n ** 32n - 977n;
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const HALF_N = N >> 1n;
  const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
  const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
  const mod = (a, m = P) => { const r = a % m; return r >= 0n ? r : r + m; };
  function inv(a, m = P) {
    let lm = 1n; let hm = 0n; let low = mod(a, m); let high = m;
    while (low > 1n) { const r = high / low; [lm, hm] = [hm - lm * r, lm]; [low, high] = [high - low * r, low]; }
    return mod(lm, m);
  }
  function powMod(b, e, m) { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; }
  // Jacobian points: [X, Y, Z]; Z = 0 is infinity.
  const INF = [0n, 1n, 0n];
  function jDouble(p) {
    const [X, Y, Z] = p;
    if (Z === 0n || Y === 0n) return INF;
    const A = (X * X) % P;
    const B = (Y * Y) % P;
    const C = (B * B) % P;
    const D = mod(2n * (mod((X + B) * (X + B)) - A - C));
    const E = (3n * A) % P;
    const F = (E * E) % P;
    const X3 = mod(F - 2n * D);
    const Y3 = mod(E * (D - X3) - 8n * C);
    const Z3 = mod(2n * Y * Z);
    return [X3, Y3, Z3];
  }
  function jAdd(p, q) {
    if (p[2] === 0n) return q;
    if (q[2] === 0n) return p;
    const [X1, Y1, Z1] = p; const [X2, Y2, Z2] = q;
    const Z1Z1 = (Z1 * Z1) % P; const Z2Z2 = (Z2 * Z2) % P;
    const U1 = (X1 * Z2Z2) % P; const U2 = (X2 * Z1Z1) % P;
    const S1 = (Y1 * Z2 * Z2Z2) % P; const S2 = (Y2 * Z1 * Z1Z1) % P;
    if (U1 === U2) return S1 === S2 ? jDouble(p) : INF;
    const H = mod(U2 - U1); const R = mod(S2 - S1);
    const H2 = (H * H) % P; const H3 = (H * H2) % P;
    const U1H2 = (U1 * H2) % P;
    const X3 = mod(R * R - H3 - 2n * U1H2);
    const Y3 = mod(R * (U1H2 - X3) - S1 * H3);
    const Z3 = (H * Z1 * Z2) % P;
    return [X3, Y3, Z3];
  }
  function jMul(k, p) {
    let r = INF; let a = p;
    while (k > 0n) { if (k & 1n) r = jAdd(r, a); a = jDouble(a); k >>= 1n; }
    return r;
  }
  function toAffine(p) {
    if (p[2] === 0n) return null;
    const zi = inv(p[2]); const zi2 = (zi * zi) % P;
    return [(p[0] * zi2) % P, (p[1] * zi2 % P) * zi % P];
  }
  // Fixed-base table for G: TABLE[i][j] = (j+1) * 16^i * G (Jacobian), built lazily.
  let G_TABLE = null;
  function gTable() {
    if (G_TABLE) return G_TABLE;
    G_TABLE = [];
    let base = [GX, GY, 1n];
    for (let i = 0; i < 64; i++) {
      const row = [base];
      for (let j = 1; j < 15; j++) row.push(jAdd(row[j - 1], base));
      G_TABLE.push(row);
      base = jDouble(jDouble(jDouble(jDouble(base))));
    }
    return G_TABLE;
  }
  function gMul(k) {
    const t = gTable();
    let r = INF;
    for (let i = 0; i < 64 && k > 0n; i++) {
      const nib = Number(k & 15n);
      if (nib) r = jAdd(r, t[i][nib - 1]);
      k >>= 4n;
    }
    return r;
  }
  function pubToAddress(pt) { return toChecksum(bytesToHex(keccak256(concat(word(pt[0]), word(pt[1]))).subarray(12))); }

  /** Parse a hex signature. Returns { kind, bytes, r, s, v, recId, highS, problems[] }. */
  function parseSignature(sigHex) {
    const out = { kind: 'invalid', bytes: 0, r: null, s: null, v: null, recId: null, highS: false, problems: [] };
    if (typeof sigHex !== 'string' || !HEX.test(sigHex)) { out.problems.push('not a 0x-prefixed hex string'); return out; }
    const hex = sigHex.slice(2);
    if (hex.length % 2) { out.problems.push('odd number of hex digits'); return out; }
    out.bytes = hex.length / 2;
    if (out.bytes === 65 || out.bytes === 64) {
      out.kind = 'ecdsa';
      out.r = BigInt('0x' + hex.slice(0, 64));
      let sv = BigInt('0x' + hex.slice(64, 128));
      if (out.bytes === 64) { // EIP-2098 compact: top bit of s is yParity
        out.recId = Number(sv >> 255n); sv &= (1n << 255n) - 1n; out.v = 27 + out.recId; out.compact = true;
      } else {
        out.v = parseInt(hex.slice(128, 130), 16);
        if (out.v === 27 || out.v === 28) out.recId = out.v - 27;
        else if (out.v === 0 || out.v === 1) out.recId = out.v;
      }
      out.s = sv;
      out.highS = sv > HALF_N;
      if (out.r === 0n || out.r >= N) out.problems.push('r is out of range');
      if (out.s === 0n || out.s >= N) out.problems.push('s is out of range');
      if (out.recId === null) out.problems.push(`v = ${out.v} (expected 27 or 28)`);
      return out;
    }
    if (hex.length >= 64 && hex.slice(-64) === '6492'.repeat(16)) { out.kind = 'erc6492'; return out; }
    if (out.bytes > 65) { out.kind = 'contract'; return out; }
    out.problems.push(`${out.bytes} bytes (an ECDSA signature is 65 bytes)`);
    return out;
  }

  /** Recover the signer address of a 32-byte digest. Returns checksummed address or null. */
  function recover(digestHex, sig) {
    const ps = typeof sig === 'string' ? parseSignature(sig) : sig;
    if (ps.kind !== 'ecdsa' || ps.recId === null || ps.problems.length) return null;
    const pre = precompute(ps);
    return pre ? recoverWith(pre, digestHex) : null;
  }
  // Part of the recovery that depends only on the signature: A = (s / r) * R.
  function precompute(ps) {
    const x = ps.r;
    if (x >= P) return null;
    const y2 = mod(x * x * x + 7n);
    let y = powMod(y2, (P + 1n) / 4n, P);
    if ((y * y) % P !== y2) return null; // r is not an x-coordinate on the curve
    if ((y & 1n) !== BigInt(ps.recId & 1)) y = P - y;
    const rInv = inv(ps.r, N);
    return { A: jMul(mod(ps.s * rInv, N), [x, y, 1n]), rInv };
  }
  function recoverWith(pre, digestHex) {
    const z = BigInt(digestHex);
    const Q = jAdd(pre.A, gMul(mod(-z * pre.rInv, N)));
    const aff = toAffine(Q);
    return aff ? pubToAddress(aff) : null;
  }

  // ------------------------------------------------------------------ EIP-712
  function typeDeps(primary, types, found) {
    if (found.has(primary) || !types[primary]) return found;
    found.add(primary);
    for (const f of types[primary]) typeDeps(f.type.replace(/\[\d*\]$/, ''), types, found);
    return found;
  }
  function encodeType(primary, types) {
    const deps = [...typeDeps(primary, types, new Set())].filter((t) => t !== primary).sort();
    return [primary, ...deps].map((t) => `${t}(${types[t].map((f) => `${f.type} ${f.name}`).join(',')})`).join('');
  }
  function encodeValue(type, value, types) {
    if (types[type]) return keccak256(encodeData(type, value, types));
    if (type === 'string') return keccak256(utf8(String(value)));
    if (type === 'bytes') return keccak256(hexToBytes(value));
    if (type === 'address') return word(BigInt(value));
    if (type === 'bool') return word(value ? 1n : 0n);
    if (/^bytes\d+$/.test(type)) { const b = hexToBytes(value); const out = new Uint8Array(32); out.set(b.subarray(0, 32)); return out; }
    if (/^u?int\d*$/.test(type)) return word(BigInt(value));
    throw new Error('unsupported EIP-712 type ' + type);
  }
  function encodeData(primary, data, types) {
    return concat(keccak256(utf8(encodeType(primary, types))), ...types[primary].map((f) => encodeValue(f.type, data[f.name], types)));
  }
  const hashStruct = (primary, data, types) => bytesToHex(keccak256(encodeData(primary, data, types)));
  function domainSeparator(domain) {
    const fields = [['name', 'string'], ['version', 'string'], ['chainId', 'uint256'], ['verifyingContract', 'address'], ['salt', 'bytes32']]
      .filter(([k]) => domain[k] !== undefined && domain[k] !== null).map(([name, type]) => ({ name, type }));
    return hashStruct('EIP712Domain', domain, { EIP712Domain: fields });
  }
  const digestOf = (domainSep, structHash) => bytesToHex(keccak256(concat(Uint8Array.of(0x19, 0x01), hexToBytes(domainSep), hexToBytes(structHash))));
  function typedDataDigest({ domain, types, primaryType, message }) {
    return digestOf(domainSeparator(domain), hashStruct(primaryType, message, types));
  }
  const AUTH_FIELDS = [
    { name: 'from', type: 'address' }, { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' }, { name: 'validBefore', type: 'uint256' }, { name: 'nonce', type: 'bytes32' },
  ];
  const EIP3009_TYPES = { TransferWithAuthorization: AUTH_FIELDS, ReceiveWithAuthorization: AUTH_FIELDS };

  // ------------------------------------------------------------------ networks and assets
  const NETWORKS = {
    'eip155:8453': { name: 'Base', v1: 'base', chainId: 8453, explorer: 'https://basescan.org/tx/' },
    'eip155:84532': { name: 'Base Sepolia (testnet)', v1: 'base-sepolia', chainId: 84532, testnet: true, explorer: 'https://sepolia.basescan.org/tx/' },
    'eip155:1': { name: 'Ethereum', v1: 'ethereum', chainId: 1, explorer: 'https://etherscan.io/tx/' },
    'eip155:11155111': { name: 'Ethereum Sepolia (testnet)', v1: 'sepolia', chainId: 11155111, testnet: true },
    'eip155:137': { name: 'Polygon', v1: 'polygon', chainId: 137, explorer: 'https://polygonscan.com/tx/' },
    'eip155:80002': { name: 'Polygon Amoy (testnet)', v1: 'polygon-amoy', chainId: 80002, testnet: true },
    'eip155:42161': { name: 'Arbitrum One', v1: 'arbitrum', chainId: 42161, explorer: 'https://arbiscan.io/tx/' },
    'eip155:421614': { name: 'Arbitrum Sepolia (testnet)', v1: 'arbitrum-sepolia', chainId: 421614, testnet: true },
    'eip155:10': { name: 'OP Mainnet', v1: 'optimism', chainId: 10, explorer: 'https://optimistic.etherscan.io/tx/' },
    'eip155:11155420': { name: 'OP Sepolia (testnet)', v1: 'optimism-sepolia', chainId: 11155420, testnet: true },
    'eip155:43114': { name: 'Avalanche C-Chain', v1: 'avalanche', chainId: 43114, explorer: 'https://snowtrace.io/tx/' },
    'eip155:43113': { name: 'Avalanche Fuji (testnet)', v1: 'avalanche-fuji', chainId: 43113, testnet: true },
    'eip155:56': { name: 'BNB Smart Chain', v1: 'bsc', chainId: 56, explorer: 'https://bscscan.com/tx/' },
    'eip155:1329': { name: 'Sei', v1: 'sei', chainId: 1329 },
    'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp': { name: 'Solana', v1: 'solana', solana: true },
    'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1': { name: 'Solana Devnet (testnet)', v1: 'solana-devnet', solana: true, testnet: true },
  };
  const V1_TO_CAIP = {};
  for (const [caip, n] of Object.entries(NETWORKS)) V1_TO_CAIP[n.v1] = caip;
  V1_TO_CAIP.mainnet = 'eip155:1';
  function resolveNetwork(raw) {
    if (typeof raw !== 'string' || !raw) return { raw, caip: null, form: 'missing', info: null };
    if (NETWORKS[raw]) return { raw, caip: raw, form: 'caip2', info: NETWORKS[raw] };
    if (V1_TO_CAIP[raw]) return { raw, caip: V1_TO_CAIP[raw], form: 'v1name', info: NETWORKS[V1_TO_CAIP[raw]] };
    const m = /^eip155:(\d+)$/.exec(raw);
    if (m) return { raw, caip: raw, form: 'caip2', info: { name: `EVM chain ${m[1]}`, chainId: Number(m[1]), unknown: true } };
    return { raw, caip: null, form: 'unknown', info: null };
  }
  // Canonical Circle-issued USDC. eip712 is the token's EIP-3009 signing domain where it is pinned by the x402
  // reference implementation's defaults; for the others the domain is read from extra.name / extra.version.
  const ASSETS = {
    'eip155:8453|0x833589fcd6edb6e08f4c7c32d4f71b54bda02913': { symbol: 'USDC', decimals: 6, eip712: { name: 'USD Coin', version: '2' } },
    'eip155:84532|0x036cbd53842c5426634e7929541ec2318f3dcf7e': { symbol: 'USDC', decimals: 6, eip712: { name: 'USDC', version: '2' } },
    'eip155:1|0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48': { symbol: 'USDC', decimals: 6 },
    'eip155:137|0x3c499c542cef5e3811e1192ce70d8cc03d5c3359': { symbol: 'USDC', decimals: 6 },
    'eip155:42161|0xaf88d065e77c8cc2239327c5edb3a432268e5831': { symbol: 'USDC', decimals: 6 },
    'eip155:10|0x0b2c639c533813f4aa9d7837caf62653d097ff85': { symbol: 'USDC', decimals: 6 },
    'eip155:43114|0xb97ef9ef8734c71904d8002f8b6bc66dd9c48a6e': { symbol: 'USDC', decimals: 6 },
    'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp|EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v': { symbol: 'USDC', decimals: 6 },
  };
  function assetInfo(caip, asset) {
    if (!caip || !asset) return null;
    const key = caip.startsWith('solana:') ? `${caip}|${asset}` : `${caip}|${String(asset).toLowerCase()}`;
    return ASSETS[key] || null;
  }
  function knownAssetAnyChain(asset) {
    if (!isAddress(asset)) return null;
    for (const [k, v] of Object.entries(ASSETS)) { const [caip, a] = k.split('|'); if (a === asset.toLowerCase()) return { caip, ...v }; }
    return null;
  }

  // ------------------------------------------------------------------ error codes (x402 v2 spec, section "Error codes")
  const ERROR_CODES = {
    insufficient_funds: {
      title: 'Payer does not hold enough tokens',
      spec: 'Client does not have enough tokens to complete the payment.',
      causes: [
        'The payer wallet holds less USDC than the required amount on the network in the requirement (balances on other chains do not count).',
        'The payer holds a different token: bridged USDbC or a lookalike instead of the asset address in the requirement.',
        'The amount was computed with the wrong decimals (USDC has 6): 0.01 USDC is "10000", not "10000000000000000".',
      ],
      fix: 'Check the payer\'s balance of the exact asset contract on the exact network. Paste the challenge here: the Doctor converts amount to a dollar price for known USDC deployments.',
    },
    invalid_exact_evm_payload_authorization_valid_after: {
      title: 'Authorization is not valid yet (validAfter is in the future)',
      spec: 'Payment authorization is not yet valid (before validAfter timestamp).',
      causes: [
        'validAfter was set to "now" on a client whose clock runs ahead of the facilitator\'s.',
        'validAfter is in milliseconds instead of seconds (a 13-digit number).',
      ],
      fix: 'Set validAfter a little in the past (for example now - 600 seconds), in Unix seconds.',
    },
    invalid_exact_evm_payload_authorization_valid_before: {
      title: 'Authorization has expired (validBefore has passed)',
      spec: 'Payment authorization has expired (after validBefore timestamp).',
      causes: [
        'The payment header was cached and replayed after validBefore.',
        'validBefore leaves too little time for verify + settle. Facilitators may reject authorizations that expire within a few seconds.',
        'validBefore was computed in the wrong unit, or from a clock that is behind.',
      ],
      fix: 'Build a fresh authorization per request with validBefore = now + maxTimeoutSeconds from the requirement, in Unix seconds.',
    },
    invalid_exact_evm_payload_authorization_value_mismatch: {
      title: 'Signed value does not match the required amount',
      spec: 'Payment amount does not exactly match the required amount.',
      causes: [
        'The client signed a different amount than accepts[].amount (v2) or maxAmountRequired (v1). The exact scheme needs an exact match.',
        'Decimal conversion error: amount is in atomic units (USDC: 6 decimals), not dollars.',
        'The client signed against an old challenge after the server changed its price.',
      ],
      fix: 'Copy the amount string from the requirement into authorization.value unchanged.',
    },
    invalid_exact_evm_payload_signature: {
      title: 'Signature does not verify',
      spec: 'Payment authorization signature is invalid or improperly signed.',
      causes: [
        'Wrong EIP-712 domain: token name (Base USDC is "USD Coin", Base Sepolia USDC is "USDC"), version, chainId, or verifyingContract differs from the token\'s.',
        'Signed on one chain, sent to another (for example signed with chainId 84532 for a Base mainnet requirement).',
        'The authorization was changed after signing (value, to, validBefore, nonce), or the wrong primary type was used (ReceiveWithAuthorization instead of TransferWithAuthorization).',
        'v is 0/1 instead of 27/28, or s is in the upper half of the curve order: USDC\'s signature library rejects both unless the facilitator normalizes them.',
        'Smart-contract wallet signature (ERC-1271 / ERC-6492) sent to a facilitator or token path that only accepts EOA signatures.',
      ],
      fix: 'Paste the challenge and the payment header into the Doctor. It recovers the signer and, if it is not authorization.from, tries the common domain mistakes and tells you which one the signature was made with.',
    },
    invalid_exact_evm_payload_recipient_mismatch: {
      title: 'authorization.to is not the payTo address',
      spec: 'Recipient address does not match payment requirements.',
      causes: [
        'The client signed to a hard-coded or cached address instead of accepts[].payTo.',
        'The server rotated its payTo address but an old challenge was used.',
      ],
      fix: 'Set authorization.to to the payTo of the requirement you are paying (case does not matter, the address must).',
    },
    invalid_network: {
      title: 'Network is not supported',
      spec: 'Specified blockchain network is not supported.',
      causes: [
        'v1/v2 network naming mixed up: v1 uses names such as "base" and "base-sepolia", v2 uses CAIP-2 ids such as "eip155:8453".',
        'The facilitator does not support this network (for example a testnet-only facilitator for a mainnet payment).',
      ],
      fix: 'Use the naming of the protocol version you speak, and check the facilitator\'s GET /supported list for the exact (x402Version, scheme, network) triple.',
    },
    invalid_payload: {
      title: 'Payment payload is malformed',
      spec: 'Payment payload is malformed or contains invalid data.',
      causes: [
        'The header is not base64 of a JSON object, or it was double-encoded.',
        'A v2 payload without the required "accepted" field (the requirement being paid).',
        'Missing or mistyped fields in payload.authorization (numbers instead of strings, nonce not 32 bytes).',
      ],
      fix: 'Paste the header into the Doctor to see the decoded JSON and every missing or mistyped field.',
    },
    invalid_payment_requirements: {
      title: 'Payment requirements are malformed',
      spec: 'Payment requirements object is invalid or malformed.',
      causes: [
        'The server sent the facilitator a requirement that is missing scheme, network, amount, asset, payTo or maxTimeoutSeconds.',
        'v1 field names in a v2 request (maxAmountRequired instead of amount) or the other way round.',
      ],
      fix: 'Paste the facilitator request body (paymentPayload + paymentRequirements) into the Doctor to check both objects.',
    },
    invalid_scheme: {
      title: 'Scheme is invalid',
      spec: 'Specified payment scheme is not supported.',
      causes: ['The scheme string is misspelled or not one the server/facilitator implements (most implement "exact").'],
      fix: 'Use a scheme listed in the challenge\'s accepts[] and in the facilitator\'s /supported list.',
    },
    unsupported_scheme: {
      title: 'Facilitator does not support this scheme',
      spec: 'Payment scheme is not supported by the facilitator.',
      causes: ['The (scheme, network) pair is not in the facilitator\'s /supported list.'],
      fix: 'Pick a facilitator that lists the pair, or offer an option it does support.',
    },
    invalid_x402_version: {
      title: 'Protocol version is not supported',
      spec: 'Protocol version is not supported.',
      causes: [
        'A v1 payment (X-PAYMENT header, network "base") sent to a v2-only server or facilitator, or the reverse.',
        'x402Version missing or sent as a string.',
      ],
      fix: 'Answer a v2 challenge (PAYMENT-REQUIRED header) with a v2 PAYMENT-SIGNATURE header, and a v1 challenge (JSON body) with X-PAYMENT.',
    },
    invalid_transaction_state: {
      title: 'Settlement transaction failed or was rejected',
      spec: 'Blockchain transaction failed or was rejected.',
      causes: [
        'The authorization nonce was already used (replay), or the payer cancelled it.',
        'The payer moved funds between verify and settle.',
        'The authorization expired while the transaction was pending.',
      ],
      fix: 'Do not deliver. Ask the client for a fresh payment with a new nonce.',
    },
    unexpected_verify_error: {
      title: 'Facilitator error during verification',
      spec: 'Unexpected error occurred during payment verification.',
      causes: ['Facilitator-side failure (RPC outage, rate limit, bug). Not proof that the payment is bad.'],
      fix: 'Retry later or with another facilitator. A seller should not deliver until a verify/settle succeeds.',
    },
    unexpected_settle_error: {
      title: 'Facilitator error during settlement',
      spec: 'Unexpected error occurred during payment settlement.',
      causes: ['Facilitator-side failure while broadcasting or confirming. The transfer may or may not have happened.'],
      fix: 'A seller should check the chain (AuthorizationUsed + Transfer to payTo for this payer and nonce) before deciding, and not deliver on an unknown outcome.',
    },
    settlement_pending: {
      title: 'Settlement broadcast but not confirmed yet',
      spec: 'The settlement transaction was broadcast but its confirmation could not be established. This code is non-terminal: the transaction may still confirm, and the response must include the transaction hash and network.',
      causes: ['Slow confirmation or a facilitator timeout after broadcast.'],
      fix: 'Reconcile with the transaction hash before retrying or delivering. Do not ask the client to pay again until the first transaction is known to have failed.',
    },
  };

  // ------------------------------------------------------------------ decoding pasted text
  function b64ToText(s) {
    let t = String(s).trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(t)) throw new Error('not base64');
    while (t.length % 4) t += '=';
    const bin = typeof atob === 'function' ? atob(t) : Buffer.from(t, 'base64').toString('binary');
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  }
  function tryJSON(t) { try { const v = JSON.parse(t); return v && typeof v === 'object' ? v : null; } catch (_) { return null; } }
  /** Decode one value that may be JSON, base64(JSON) or base64(base64(JSON)). */
  function decodeValue(text) {
    const notes = [];
    const t = String(text || '').trim().replace(/^["']|["']$/g, '');
    if (!t) return { value: null, notes, encoding: null };
    let v = tryJSON(t);
    if (v) return { value: v, notes, encoding: 'json' };
    try {
      const once = b64ToText(t);
      v = tryJSON(once);
      if (v) return { value: v, notes, encoding: 'base64' };
      try {
        const twice = b64ToText(once);
        v = tryJSON(twice);
        if (v) { notes.push('The value was base64-encoded twice. Encode the JSON once.'); return { value: v, notes, encoding: 'base64x2' }; }
      } catch (_) { /* not double */ }
    } catch (_) { /* not base64 */ }
    return { value: null, notes: ['Could not decode: not JSON and not base64 of JSON.'], encoding: null };
  }

  const HEADER_ROLES = {
    'payment-required': 'challenge', 'payment-signature': 'payment', 'x-payment': 'payment',
    'payment-response': 'settlement', 'x-payment-response': 'settlement',
  };
  /** Classify a decoded object. */
  function classify(o) {
    if (!o || typeof o !== 'object') return null;
    if (o.paymentPayload || o.paymentRequirements) return 'facilitator_request';
    if (Array.isArray(o.accepts)) return 'challenge';
    if (o.payload && typeof o.payload === 'object') return 'payment';
    if ('isValid' in o) return 'verify_response';
    if ('success' in o || 'errorReason' in o) return 'settlement';
    return null;
  }

  /**
   * Split pasted text into x402 objects. Accepts: raw headers ("Name: value" lines, e.g. curl -i output),
   * a bare header value, raw JSON, a JSON body after headers, or several of these in one box.
   * Returns { challenge, payment, settlement, verify, notes[], sources{} }.
   */
  function extract(texts) {
    const found = { challenge: null, payment: null, settlement: null, verify: null, notes: [], sources: {} };
    const put = (role, value, source) => {
      if (role === 'verify_response') role = 'verify';
      if (!found[role]) { found[role] = value; found.sources[role] = source; } else if (JSON.stringify(found[role]) !== JSON.stringify(value)) {
        found.notes.push({ level: 'info', text: `More than one ${role} object found (for example a v2 header plus a v1-compatible body); checking the first (${found.sources[role]}).` });
      }
    };
    const handleObject = (o, source, hint) => {
      const kind = classify(o) || hint;
      if (kind === 'facilitator_request') {
        if (o.paymentPayload) put('payment', o.paymentPayload, source + ' → paymentPayload');
        if (o.paymentRequirements) {
          const req = o.paymentRequirements;
          // The facilitator receives ONE requirement; wrap it so the challenge checks can run.
          const v = (o.paymentPayload && o.paymentPayload.x402Version) || o.x402Version || (req.amount !== undefined ? 2 : 1);
          put('challenge', { x402Version: v, accepts: [req], __fromFacilitatorRequest: true, resource: o.paymentPayload && o.paymentPayload.resource }, source + ' → paymentRequirements');
        }
        return true;
      }
      if (kind) { put(kind, o, source); return true; }
      return false;
    };
    for (const [label, raw] of Object.entries(texts || {})) {
      const text = String(raw || '');
      if (!text.trim()) continue;
      const lines = text.split(/\r?\n/);
      let sawHeader = false;
      let bodyStart = -1;
      for (let i = 0; i < lines.length; i++) {
        const m = /^\s*(?:[<>]\s*)?([A-Za-z0-9-]+)\s*:\s*(.+)$/.exec(lines[i]);
        if (m && HEADER_ROLES[m[1].toLowerCase()]) {
          sawHeader = true;
          const d = decodeValue(m[2]);
          d.notes.forEach((n) => found.notes.push({ level: 'warn', text: `${m[1]}: ${n}` }));
          if (d.value) handleObject(d.value, `${m[1]} header`, HEADER_ROLES[m[1].toLowerCase()]);
          if (m[1].toLowerCase() === 'payment-signature' || m[1].toLowerCase() === 'x-payment') found.headerName = m[1];
          if (m[1].toLowerCase() === 'payment-required') found.challengeInHeader = true;
        } else if (/^HTTP\/[\d.]+\s+(\d{3})/.test(lines[i])) {
          sawHeader = true; found.httpStatus = Number(/^HTTP\/[\d.]+\s+(\d{3})/.exec(lines[i])[1]);
        } else if (sawHeader && bodyStart < 0 && lines[i].trim() === '') bodyStart = i + 1;
      }
      if (sawHeader) {
        if (bodyStart > 0) {
          const body = tryJSON(lines.slice(bodyStart).join('\n').trim());
          if (body) handleObject(body, 'response body');
        }
        continue;
      }
      const d = decodeValue(text);
      d.notes.forEach((n) => found.notes.push({ level: 'warn', text: `${label}: ${n}` }));
      if (d.value) {
        if (!handleObject(d.value, label + (d.encoding === 'json' ? ' (JSON)' : ' (base64)'))) found.notes.push({ level: 'warn', text: `${label}: decoded, but it does not look like an x402 object.` });
        if (d.encoding === 'json' && classify(d.value) === 'payment') found.paymentWasRawJSON = true;
      }
    }
    return found;
  }

  // ------------------------------------------------------------------ checks
  const isIntString = (v) => typeof v === 'string' && /^\d+$/.test(v);
  function fmtUsd(atomic, decimals) {
    if (!isIntString(atomic)) return null;
    const n = BigInt(atomic); const d = 10n ** BigInt(decimals);
    const whole = n / d; const frac = (n % d).toString().padStart(decimals, '0').replace(/0+$/, '');
    return '$' + whole.toString() + (frac ? '.' + frac : '');
  }

  function checkChallenge(pr, add, ctx) {
    const v = pr.x402Version;
    if (pr.__fromFacilitatorRequest) add('info', 'challenge', 'Requirement taken from the facilitator request body (paymentRequirements).');
    if (v === 2) add('pass', 'challenge.version', 'x402Version 2.');
    else if (v === 1) add('pass', 'challenge.version', 'x402Version 1 (legacy, still widely used).');
    else add('fail', 'challenge.version', `x402Version is ${JSON.stringify(v)}; expected the number 1 or 2.`, 'invalid_x402_version');
    if (v === 2 && !pr.__fromFacilitatorRequest) {
      if (!pr.resource || typeof pr.resource !== 'object' || !pr.resource.url) add('warn', 'challenge.resource', 'v2 challenge has no resource.url (the spec marks resource as required).');
      if (ctx.challengeSource && !ctx.challengeInHeader && ctx.httpStatus) add('warn', 'challenge.header', 'v2 challenge found in the body only. v2 clients read the base64 PAYMENT-REQUIRED header.');
      if (pr.extensions && pr.extensions.bazaar) add('pass', 'challenge.bazaar', 'extensions.bazaar present (discovery metadata for Bazaar-style catalogs).');
      else add('info', 'challenge.bazaar', 'No extensions.bazaar block. Catalogs such as the CDP Bazaar use it to index the endpoint.');
    }
    if (ctx.httpStatus && ctx.httpStatus !== 402) add('warn', 'challenge.status', `HTTP status is ${ctx.httpStatus}; x402 challenges use 402.`);
    const accepts = Array.isArray(pr.accepts) ? pr.accepts : [];
    if (!accepts.length) add('fail', 'challenge.accepts', 'accepts[] is empty: there is no way to pay.', 'invalid_payment_requirements');
    accepts.forEach((a, i) => {
      const id = `challenge.accepts[${i}]`;
      if (!a || typeof a !== 'object') { add('fail', id, 'Not an object.', 'invalid_payment_requirements'); return; }
      const net = resolveNetwork(a.network);
      if (!a.scheme) add('fail', id + '.scheme', 'Missing scheme.', 'invalid_payment_requirements');
      else if (a.scheme !== 'exact') add('info', id + '.scheme', `Scheme "${a.scheme}". Most clients and facilitators implement "exact".`);
      if (net.form === 'missing') add('fail', id + '.network', 'Missing network.', 'invalid_payment_requirements');
      else if (net.form === 'unknown') add('warn', id + '.network', `Unrecognized network "${a.network}".`, 'invalid_network');
      else if (v === 2 && net.form === 'v1name') add('fail', id + '.network', `v2 uses CAIP-2 network ids: "${net.caip}", not "${a.network}".`, 'invalid_network');
      else if (v === 1 && net.form === 'caip2' && net.info && net.info.v1) add('warn', id + '.network', `v1 uses network names: "${net.info.v1}". "${a.network}" is the v2 (CAIP-2) form; many v1 clients reject it.`, 'invalid_network');
      if (net.info && net.info.testnet) add('info', id + '.testnet', `${net.info.name}: test money only.`);
      const amount = v === 1 ? a.maxAmountRequired : a.amount;
      const amountField = v === 1 ? 'maxAmountRequired' : 'amount';
      if (v === 2 && a.amount === undefined && a.maxAmountRequired !== undefined) add('fail', id + '.amount', 'v2 requirements use "amount"; "maxAmountRequired" is the v1 name.', 'invalid_payment_requirements');
      else if (v === 1 && a.maxAmountRequired === undefined && a.amount !== undefined) add('fail', id + '.amount', 'v1 requirements use "maxAmountRequired"; "amount" is the v2 name.', 'invalid_payment_requirements');
      else if (!isIntString(amount)) add('fail', id + '.amount', `${amountField} must be a string of atomic units (digits only), got ${JSON.stringify(amount)}.`, 'invalid_payment_requirements');
      const evm = net.caip ? net.caip.startsWith('eip155:') : isAddress(a.asset);
      const known = assetInfo(net.caip, a.asset);
      if (evm) {
        const pf = addressForm(a.payTo);
        if (pf === 'invalid') add('fail', id + '.payTo', `payTo is not an EVM address: ${JSON.stringify(a.payTo)}.`, 'invalid_payment_requirements');
        else if (pf === 'bad_checksum') add('fail', id + '.payTo', `payTo has mixed case but a wrong EIP-55 checksum (expected ${toChecksum(a.payTo)}). It may be mistyped.`);
        else if (/^0x0{40}$/i.test(a.payTo)) add('fail', id + '.payTo', 'payTo is the zero address: funds would be burned.');
        else if (pf !== 'checksummed') add('info', id + '.payTo', `payTo is ${pf}; the checksummed form is ${toChecksum(a.payTo)}.`);
        if (!isAddress(a.asset)) add('fail', id + '.asset', `asset is not a token address: ${JSON.stringify(a.asset)}.`, 'invalid_payment_requirements');
        else if (!known) {
          const elsewhere = knownAssetAnyChain(a.asset);
          if (elsewhere) add('fail', id + '.asset', `asset is USDC on ${NETWORKS[elsewhere.caip].name}, but network is ${net.info ? net.info.name : a.network}.`, 'invalid_payment_requirements');
          else add('info', id + '.asset', `asset ${a.asset} is not in the Doctor's list of canonical USDC deployments; the dollar price cannot be shown.`);
        }
      } else if (net.info && net.info.solana && !isSolanaAddress(a.payTo)) add('fail', id + '.payTo', 'payTo is not a Solana address.', 'invalid_payment_requirements');
      if (known && isIntString(amount)) add('info', id + '.price', `Price: ${fmtUsd(amount, known.decimals)} ${known.symbol} on ${net.info.name}.`);
      if (typeof a.maxTimeoutSeconds !== 'number') add(v === 2 ? 'fail' : 'warn', id + '.maxTimeoutSeconds', `maxTimeoutSeconds should be a number, got ${JSON.stringify(a.maxTimeoutSeconds)}.`, v === 2 ? 'invalid_payment_requirements' : undefined);
      else if (a.maxTimeoutSeconds < 10) add('warn', id + '.maxTimeoutSeconds', `maxTimeoutSeconds = ${a.maxTimeoutSeconds} leaves little time to sign, verify and settle.`);
      if (evm && a.scheme === 'exact') {
        const ex = a.extra || {};
        if (!ex.name || !ex.version) add('warn', id + '.extra', 'extra.name / extra.version (the token\'s EIP-712 domain) missing: clients must guess the domain, and a wrong guess makes the signature invalid.');
        else if (known && known.eip712) {
          if (ex.name !== known.eip712.name) add('fail', id + '.extra.name', `extra.name is "${ex.name}" but this token signs with name "${known.eip712.name}". Every client that trusts extra.name will produce an invalid signature.`, 'invalid_exact_evm_payload_signature');
          if (String(ex.version) !== known.eip712.version) add('fail', id + '.extra.version', `extra.version is "${ex.version}" but this token signs with version "${known.eip712.version}".`, 'invalid_exact_evm_payload_signature');
          if (ex.name === known.eip712.name && String(ex.version) === known.eip712.version) add('pass', id + '.extra', `EIP-712 domain matches the token ("${ex.name}", version "${ex.version}").`);
        }
      }
      if (v === 1) {
        if (!a.resource) add('warn', id + '.resource', 'v1 requirement without resource URL.');
        if (!a.description) add('info', id + '.description', 'No description: agents cannot tell what they buy.');
      }
    });
  }

  function checkPayment(pp, add, ctx) {
    const v = pp.x402Version;
    if (v === 2) add('pass', 'payment.version', 'x402Version 2.');
    else if (v === 1) add('pass', 'payment.version', 'x402Version 1.');
    else add('fail', 'payment.version', `x402Version is ${JSON.stringify(v)}; expected the number 1 or 2.`, 'invalid_x402_version');
    if (ctx.paymentWasRawJSON) add('info', 'payment.encoding', 'You pasted raw JSON. On the wire the header value must be base64 of this JSON.');
    if (ctx.headerName) {
      const h = ctx.headerName.toLowerCase();
      if (v === 2 && h === 'x-payment') add('fail', 'payment.header', 'v2 payment sent in X-PAYMENT. v2 servers read PAYMENT-SIGNATURE.', 'invalid_x402_version');
      if (v === 1 && h === 'payment-signature') add('warn', 'payment.header', 'v1 payment sent in PAYMENT-SIGNATURE. v1 servers read X-PAYMENT.', 'invalid_x402_version');
    }
    let req = null;
    if (v === 2) {
      if (!pp.accepted || typeof pp.accepted !== 'object') add('fail', 'payment.accepted', 'v2 payload has no "accepted" object (the requirement being paid). The spec marks it as required; facilitators reject the payload without it.', 'invalid_payload');
      else req = pp.accepted;
      if (pp.scheme || pp.network) add('warn', 'payment.shape', 'Top-level scheme/network is the v1 layout. In v2 they live inside "accepted".');
    } else if (v === 1) {
      if (!pp.scheme) add('fail', 'payment.scheme', 'v1 payload missing scheme.', 'invalid_payload');
      if (!pp.network) add('fail', 'payment.network', 'v1 payload missing network.', 'invalid_payload');
      else if (resolveNetwork(pp.network).form === 'caip2') add('warn', 'payment.network', `v1 payloads use network names ("${(resolveNetwork(pp.network).info || {}).v1 || '…'}"), not CAIP-2 ids.`, 'invalid_network');
      if (pp.accepted) add('info', 'payment.shape', '"accepted" is a v2 field; v1 servers ignore it.');
    }
    const pl = pp.payload || {};
    const auth = pl.authorization;
    if (!auth || typeof auth !== 'object') {
      add('fail', 'payment.authorization', 'payload.authorization missing: this is not an EIP-3009 "exact" EVM payment (Solana and Permit2 payloads are not checked by the Doctor).', 'invalid_payload');
      return { req, auth: null };
    }
    for (const k of ['from', 'to']) {
      const f = addressForm(auth[k]);
      if (f === 'invalid') add('fail', `payment.authorization.${k}`, `${k} is not an address: ${JSON.stringify(auth[k])}.`, 'invalid_payload');
      else if (f === 'bad_checksum') add('warn', `payment.authorization.${k}`, `${k} has a wrong EIP-55 checksum (expected ${toChecksum(auth[k])}).`);
    }
    for (const k of ['value', 'validAfter', 'validBefore']) {
      if (typeof auth[k] === 'number') add('warn', `payment.authorization.${k}`, `${k} is a JSON number; send it as a decimal string ("${auth[k]}"). Large numbers lose precision as JSON numbers.`, 'invalid_payload');
      else if (!isIntString(auth[k])) add('fail', `payment.authorization.${k}`, `${k} must be a decimal string, got ${JSON.stringify(auth[k])}.`, 'invalid_payload');
    }
    if (typeof auth.nonce !== 'string' || !/^0x[0-9a-fA-F]{64}$/.test(auth.nonce)) add('fail', 'payment.authorization.nonce', `nonce must be 32 bytes of hex (0x + 64 hex digits), got ${JSON.stringify(auth.nonce)}.`, 'invalid_payload');
    const now = ctx.now;
    const va = Number(auth.validAfter); const vb = Number(auth.validBefore);
    if (Number.isFinite(vb)) {
      if (vb > 1e12) add('fail', 'payment.validBefore', `validBefore = ${auth.validBefore} looks like milliseconds. EIP-3009 uses Unix seconds.`, 'invalid_exact_evm_payload_authorization_valid_before');
      else if (vb <= now) add('fail', 'payment.validBefore', `Expired ${ago(now - vb)} ago (validBefore ${iso(vb)}).`, 'invalid_exact_evm_payload_authorization_valid_before');
      else if (vb - now < 6) add('warn', 'payment.validBefore', `Expires in ${vb - now}s: too little time for verify + settle.`, 'invalid_exact_evm_payload_authorization_valid_before');
      else add('pass', 'payment.validBefore', `Valid for another ${ago(vb - now)} (until ${iso(vb)}).`);
    }
    if (Number.isFinite(va)) {
      if (va > 1e12) add('fail', 'payment.validAfter', `validAfter = ${auth.validAfter} looks like milliseconds. EIP-3009 uses Unix seconds.`, 'invalid_exact_evm_payload_authorization_valid_after');
      else if (va > now) add('fail', 'payment.validAfter', `Not valid for another ${ago(va - now)} (validAfter ${iso(va)}). Check the signer's clock or set validAfter in the past.`, 'invalid_exact_evm_payload_authorization_valid_after');
    }
    if (req && typeof req.maxTimeoutSeconds === 'number' && Number.isFinite(vb) && Number.isFinite(va) && vb < 1e12 && vb - Math.max(va, 0) > 0 && vb - now > req.maxTimeoutSeconds + 120) {
      add('info', 'payment.window', `validBefore is ${ago(vb - now)} away, longer than maxTimeoutSeconds (${req.maxTimeoutSeconds}s). Allowed, but a stolen header stays usable that long.`);
    }
    add('info', 'payment.nonce', 'Nonce reuse cannot be checked offline: the token contract rejects a nonce that was already used (authorizationState on-chain).');
    const sig = parseSignature(pl.signature);
    if (sig.kind === 'invalid') add('fail', 'payment.signature', `signature: ${sig.problems.join('; ') || 'missing'}.`, 'invalid_exact_evm_payload_signature');
    else if (sig.kind === 'erc6492') add('warn', 'payment.signature', `ERC-6492 signature (${sig.bytes} bytes) from a smart-contract wallet that may not be deployed yet. It cannot be checked offline; it only works if the facilitator and the token support ERC-6492/ERC-1271.`, 'invalid_exact_evm_payload_signature');
    else if (sig.kind === 'contract') add('warn', 'payment.signature', `${sig.bytes}-byte signature: looks like a smart-contract wallet (ERC-1271) signature. It cannot be checked offline; it only works if the facilitator and the token accept ERC-1271 signatures.`, 'invalid_exact_evm_payload_signature');
    else {
      if (sig.compact) add('info', 'payment.signature', '64-byte compact (EIP-2098) signature. Many facilitators expect 65 bytes (r, s, v).');
      if (sig.v === 0 || sig.v === 1) add('warn', 'payment.signature.v', `v = ${sig.v}. USDC's signature check accepts only v = 27 or 28; this works only if the facilitator converts it (use ${sig.v + 27}).`, 'invalid_exact_evm_payload_signature');
      else if (sig.recId === null) add('fail', 'payment.signature.v', `v = ${sig.v}; expected 27 or 28.`, 'invalid_exact_evm_payload_signature');
      if (sig.highS) add('warn', 'payment.signature.s', 's is in the upper half of the curve order (not EIP-2 canonical). USDC\'s signature check rejects it unless the facilitator normalizes it.', 'invalid_exact_evm_payload_signature');
      sig.problems.filter((p) => !/^v = /.test(p)).forEach((p) => add('fail', 'payment.signature', p, 'invalid_exact_evm_payload_signature'));
    }
    return { req, auth, sig };
  }

  const ago = (sec) => (sec >= 86400 ? `${Math.round(sec / 86400)}d` : sec >= 3600 ? `${Math.round(sec / 3600)}h` : sec >= 60 ? `${Math.round(sec / 60)}m` : `${Math.round(sec)}s`);
  const iso = (sec) => { try { return new Date(sec * 1000).toISOString().replace('.000Z', 'Z'); } catch (_) { return String(sec); } };

  const REQ_FIELDS = ['scheme', 'network', 'amount', 'asset', 'payTo', 'maxTimeoutSeconds'];
  function crossCheck(pr, pp, payInfo, add) {
    const accepts = Array.isArray(pr.accepts) ? pr.accepts : [];
    const v = pp.x402Version;
    if (pr.x402Version !== v && (pr.x402Version === 1 || pr.x402Version === 2)) add('fail', 'match.version', `Challenge is x402 v${pr.x402Version} but the payment is v${v}.`, 'invalid_x402_version');
    let chosen = null;
    if (v === 2 && payInfo.req) {
      const a = payInfo.req;
      let best = null; let bestDiff = null;
      accepts.forEach((r, i) => {
        const diff = REQ_FIELDS.filter((k) => (k === 'payTo' || k === 'asset') ? !sameAddr(String(r[k]), String(a[k])) && r[k] !== a[k] : String(r[k]) !== String(a[k]));
        if (bestDiff === null || diff.length < bestDiff.length) { best = i; bestDiff = diff; }
      });
      if (best === null) add('warn', 'match.accepted', 'The challenge has no requirements to compare against.');
      else if (!bestDiff.length) { chosen = accepts[best]; add('pass', 'match.accepted', `payload.accepted matches challenge accepts[${best}].`); }
      else {
        chosen = accepts[best];
        add('fail', 'match.accepted', `payload.accepted differs from the closest requirement (accepts[${best}]) in: ${bestDiff.map((k) => `${k} (${JSON.stringify(a[k])} vs ${JSON.stringify(accepts[best][k])})`).join(', ')}. Servers match "accepted" against what they offered.`, 'invalid_payload');
      }
    } else if (v === 1) {
      const idx = accepts.findIndex((r) => r.scheme === pp.scheme && r.network === pp.network);
      if (idx < 0) add('fail', 'match.option', `No v1 requirement with scheme "${pp.scheme}" and network "${pp.network}".`, 'invalid_network');
      else { chosen = accepts[idx]; add('pass', 'match.option', `Payment answers accepts[${idx}] (${pp.scheme} on ${pp.network}).`); }
    }
    if (!chosen && accepts.length === 1) chosen = accepts[0];
    const auth = payInfo.auth;
    if (chosen && auth) {
      const amount = v === 1 ? chosen.maxAmountRequired : chosen.amount;
      if (isAddress(chosen.payTo) && isAddress(auth.to)) {
        if (sameAddr(chosen.payTo, auth.to)) add('pass', 'match.to', 'authorization.to equals payTo.');
        else add('fail', 'match.to', `authorization.to (${auth.to}) is not payTo (${chosen.payTo}).`, 'invalid_exact_evm_payload_recipient_mismatch');
      }
      if (isIntString(amount) && auth.value !== undefined) {
        if (String(auth.value) === amount) add('pass', 'match.value', `authorization.value equals the required amount (${amount}).`);
        else add('fail', 'match.value', `authorization.value is ${auth.value} but the requirement asks exactly ${amount}.`, 'invalid_exact_evm_payload_authorization_value_mismatch');
      }
    }
    return chosen;
  }

  // Build the EIP-712 domain the payment should have been signed with.
  function expectedDomain(req, pp) {
    const r = req || {};
    const net = resolveNetwork(r.network || (pp && pp.network));
    const chainId = net.info && net.info.chainId;
    const asset = r.asset;
    const known = assetInfo(net.caip, asset);
    const ex = r.extra || {};
    // For tokens whose domain is known, the token's real domain wins over extra (a wrong extra.name is a server bug
    // that makes every client sign the wrong domain). Otherwise trust extra.name / extra.version.
    const pinned = known && known.eip712;
    const name = pinned ? pinned.name : ex.name;
    const version = pinned ? pinned.version : (ex.version !== undefined && ex.version !== null ? String(ex.version) : undefined);
    if (!chainId || !isAddress(asset) || !name || !version) return { domain: null, why: !chainId ? 'unknown chain' : !isAddress(asset) ? 'no asset address' : 'no EIP-712 name/version (extra.name / extra.version) and the token is not one the Doctor knows', extra: ex };
    return { domain: { name, version, chainId, verifyingContract: asset }, source: pinned ? 'known token' : 'extra' };
  }

  function domainCandidates(base, req) {
    const ex = (req && req.extra) || {};
    const names = [...new Set([base && base.name, typeof ex.name === 'string' ? ex.name : null, 'USD Coin', 'USDC'].filter(Boolean))];
    const versions = [...new Set([base && base.version, ex.version !== undefined && ex.version !== null ? String(ex.version) : null, '2', '1'].filter(Boolean)), null];
    const chains = new Set();
    if (base && base.chainId) chains.add(base.chainId);
    else if (req) { const n = resolveNetwork(req.network); if (n.info && n.info.chainId) chains.add(n.info.chainId); }
    for (const n of Object.values(NETWORKS)) if (n.chainId) chains.add(n.chainId);
    const pairs = [];
    const contracts = new Set();
    if (base && base.verifyingContract) contracts.add(base.verifyingContract.toLowerCase());
    else if (req && isAddress(req.asset)) contracts.add(req.asset.toLowerCase());
    for (const chainId of chains) {
      for (const c of contracts) pairs.push([chainId, c]);
      for (const k of Object.keys(ASSETS)) {
        const [caip, addr] = k.split('|');
        if (NETWORKS[caip] && NETWORKS[caip].chainId === chainId && isAddress(addr) && !contracts.has(addr)) pairs.push([chainId, addr]);
      }
    }
    const out = [];
    for (const [chainId, verifyingContract] of pairs) for (const name of names) for (const version of versions) {
      const d = { name, chainId, verifyingContract };
      if (version !== null) d.version = version;
      out.push(d);
    }
    return out;
  }

  function describeDomain(d) {
    const net = Object.values(NETWORKS).find((n) => n.chainId === d.chainId);
    const tok = knownAssetAnyChain(d.verifyingContract);
    return `name "${d.name}", version ${d.version === undefined ? '(none)' : '"' + d.version + '"'}, chainId ${d.chainId}${net ? ' (' + net.name + ')' : ''}, verifyingContract ${toChecksum(d.verifyingContract)}${tok ? ' (USDC on ' + NETWORKS[tok.caip].name + ')' : ''}`;
  }

  /** Signature analysis. Returns a result object; adds checks via add(). */
  function checkSignature(req, pp, payInfo, add, opts = {}) {
    const auth = payInfo.auth; const sig = payInfo.sig;
    const result = { status: 'skipped' };
    if (!auth || !sig || sig.kind !== 'ecdsa' || sig.recId === null || sig.problems.length) return result;
    if (!isAddress(auth.from) || !isAddress(auth.to) || !/^0x[0-9a-fA-F]{64}$/.test(String(auth.nonce)) || !['value', 'validAfter', 'validBefore'].every((k) => /^\d+$/.test(String(auth[k])))) return result;
    const pre = precompute(sig);
    if (!pre) { add('fail', 'signature.recover', 'Signature r is not a valid curve point: it cannot come from any key.', 'invalid_exact_evm_payload_signature'); return { status: 'invalid' }; }
    const msg = { from: auth.from, to: auth.to, value: String(auth.value), validAfter: String(auth.validAfter), validBefore: String(auth.validBefore), nonce: auth.nonce };
    const exp = expectedDomain(req, pp);
    result.expectedDomain = exp.domain;
    const structTWA = hashStruct('TransferWithAuthorization', msg, EIP3009_TYPES);
    if (exp.domain) {
      const signer = recoverWith(pre, digestOf(domainSeparator(exp.domain), structTWA));
      result.recoveredWithExpected = signer;
      if (sameAddr(signer, auth.from)) {
        add('pass', 'signature.valid', `Signature verifies: recovered ${signer} = authorization.from, over TransferWithAuthorization with ${describeDomain(exp.domain)}.`);
        result.status = 'valid';
        return result;
      }
    } else {
      add('info', 'signature.domain', `Expected EIP-712 domain unknown (${exp.why}). Searching common domains instead.`);
    }
    // Search: domain variants x primary types x message variants.
    const msgs = [{ label: null, m: msg }];
    if (req) {
      const amount = req.amount !== undefined ? req.amount : req.maxAmountRequired;
      if (isIntString(amount) && amount !== msg.value) msgs.push({ label: `value ${amount} (the required amount)`, m: { ...msg, value: amount } });
      if (isAddress(req.payTo) && !sameAddr(req.payTo, msg.to)) msgs.push({ label: `to ${req.payTo} (payTo)`, m: { ...msg, to: req.payTo } });
    }
    const types = ['TransferWithAuthorization', 'ReceiveWithAuthorization'];
    const structs = new Map();
    const domains = domainCandidates(exp.domain, req);
    const sepCache = new Map();
    let tried = 0;
    const limit = opts.maxCandidates || 4000;
    outer:
    for (const t of types) for (const mv of msgs) {
      const sk = t + '|' + mv.label;
      if (!structs.has(sk)) structs.set(sk, hashStruct(t, mv.m, EIP3009_TYPES));
      for (const d of domains) {
        if (++tried > limit) break outer;
        const dk = JSON.stringify(d);
        if (!sepCache.has(dk)) sepCache.set(dk, domainSeparator(d));
        const signer = recoverWith(pre, digestOf(sepCache.get(dk), structs.get(sk)));
        if (sameAddr(signer, auth.from)) { result.match = { domain: d, type: t, messageChange: mv.label }; break outer; }
      }
    }
    result.tried = Math.min(tried, limit);
    if (result.match) {
      const m = result.match; const diffs = [];
      const e = exp.domain || {};
      if (exp.domain) {
        if (m.domain.name !== e.name) diffs.push(`name "${m.domain.name}" instead of "${e.name}"`);
        if (m.domain.version !== e.version) diffs.push(m.domain.version === undefined ? 'no version field in the domain' : `version "${m.domain.version}" instead of "${e.version}"`);
        if (m.domain.chainId !== e.chainId) diffs.push(`chainId ${m.domain.chainId} instead of ${e.chainId}`);
        if (!sameAddr(m.domain.verifyingContract, e.verifyingContract)) diffs.push(`verifyingContract ${toChecksum(m.domain.verifyingContract)} instead of ${toChecksum(e.verifyingContract)}`);
      }
      if (m.type !== 'TransferWithAuthorization') diffs.push(`primary type ${m.type} instead of TransferWithAuthorization`);
      if (m.messageChange) diffs.push(`the signed message had ${m.messageChange}, then the authorization was changed`);
      result.diffs = diffs;
      if (!exp.domain && !m.messageChange) {
        result.status = 'valid_for_found_domain';
        add('pass', 'signature.valid', `Signature verifies: authorization.from signed ${m.type} over ${describeDomain(m.domain)}. Make sure this is the token's real EIP-712 domain (its name() and version() on-chain).`);
        return result;
      }
      result.status = 'mismatch_found';
      add('fail', 'signature.cause', `Signature does NOT verify for the expected domain. It was made by authorization.from over ${describeDomain(m.domain)}${m.type !== 'TransferWithAuthorization' ? ' with ' + m.type : ''}. ${diffs.length ? 'Difference: ' + diffs.join('; ') + '.' : ''}`, 'invalid_exact_evm_payload_signature');
    } else {
      result.status = 'no_match';
      add('fail', 'signature.cause', `Signature does NOT verify${exp.domain ? ' for ' + describeDomain(exp.domain) : ''}${result.recoveredWithExpected ? ' (it recovers to ' + result.recoveredWithExpected + ', not ' + auth.from + ')' : ''}. None of ${result.tried} common domain/type variants match either: the signer is not authorization.from, or fields such as validAfter, validBefore or nonce were changed after signing.`, 'invalid_exact_evm_payload_signature');
    }
    return result;
  }

  function checkSettlement(s, add) {
    if ('success' in s) {
      if (s.success === true) {
        if (typeof s.transaction === 'string' && /^0x[0-9a-fA-F]{64}$/.test(s.transaction)) {
          const net = resolveNetwork(s.network);
          add('pass', 'settlement.success', `Settled: transaction ${s.transaction}${net.info ? ' on ' + net.info.name : ''}.`);
          if (!s.network) add('warn', 'settlement.network', 'SettleResponse without network (the spec marks it as required).');
          return { explorer: net.info && net.info.explorer ? net.info.explorer + s.transaction : null };
        }
        if (typeof s.transaction === 'string' && /^[1-9A-HJ-NP-Za-km-z]{64,90}$/.test(s.transaction)) { add('pass', 'settlement.success', `Settled: Solana transaction ${s.transaction}.`); return {}; }
        add('warn', 'settlement.transaction', `success is true but transaction is ${JSON.stringify(s.transaction)}, not a transaction hash. A careful seller should not treat this as settled.`);
      } else {
        const code = s.errorReason || null;
        add(code === 'settlement_pending' ? 'warn' : 'fail', 'settlement.failed', `Settlement ${code === 'settlement_pending' ? 'pending' : 'failed'}${code ? ': ' + code : ''}.`, code || undefined);
        if (code === 'settlement_pending' && !s.transaction) add('fail', 'settlement.pending', 'settlement_pending without a transaction hash: the caller cannot reconcile it (the spec requires the hash).');
      }
    }
    return {};
  }

  function checkVerify(v, add) {
    if (v.isValid === true) add('pass', 'verify.valid', `Facilitator verify: valid${v.payer ? ' (payer ' + v.payer + ')' : ''}.`);
    else add('fail', 'verify.invalid', `Facilitator verify: invalid${v.invalidReason ? ': ' + v.invalidReason : ''}.`, v.invalidReason || undefined);
  }

  /**
   * Main entry. texts: { challenge?: string, payment?: string, response?: string } (any box may hold anything).
   * opts.now: Unix seconds (defaults to the current time).
   */
  function diagnose(texts, opts = {}) {
    const now = opts.now !== undefined ? opts.now : Math.floor(Date.now() / 1000);
    const checks = [];
    const add = (level, id, message, code) => checks.push({ level, id, message, code: code || null });
    const ex = extract(texts);
    ex.notes.forEach((n) => add(n.level, 'decode', n.text));
    const ctx = { now, headerName: ex.headerName, httpStatus: ex.httpStatus, challengeInHeader: ex.challengeInHeader, challengeSource: ex.sources.challenge, paymentWasRawJSON: ex.paymentWasRawJSON };
    if (ex.challenge) checkChallenge(ex.challenge, add, ctx);
    let payInfo = { req: null, auth: null, sig: null };
    if (ex.payment) payInfo = checkPayment(ex.payment, add, ctx);
    let chosen = null;
    if (ex.challenge && ex.payment) chosen = crossCheck(ex.challenge, ex.payment, payInfo, add);
    let signature = { status: 'skipped' };
    if (ex.payment && payInfo.auth) {
      const req = (ex.payment.x402Version === 2 && payInfo.req) ? payInfo.req : chosen;
      const reqForDomain = req || (ex.payment.x402Version === 1 ? { network: ex.payment.network, asset: knownV1Asset(ex.payment.network) } : null);
      signature = checkSignature(reqForDomain, ex.payment, payInfo, add, opts);
    }
    let settlement = {};
    if (ex.settlement) settlement = checkSettlement(ex.settlement, add);
    if (ex.verify) checkVerify(ex.verify, add);
    const codes = [...new Set(checks.filter((c) => c.code && (c.level === 'fail' || c.level === 'warn')).map((c) => c.code))];
    const fails = checks.filter((c) => c.level === 'fail').length;
    const warns = checks.filter((c) => c.level === 'warn').length;
    const found = ['challenge', 'payment', 'settlement', 'verify'].filter((k) => ex[k]);
    let verdict;
    if (!found.length) verdict = 'nothing_found';
    else if (fails) verdict = 'problems';
    else if (warns) verdict = 'warnings';
    else verdict = 'ok';
    return { verdict, fails, warns, found, decoded: { challenge: ex.challenge, payment: ex.payment, settlement: ex.settlement, verify: ex.verify }, sources: ex.sources, checks, codes, signature, settlement, now };
  }
  // For a v1 payment without its challenge: assume canonical USDC on that network if the Doctor knows one.
  function knownV1Asset(v1net) {
    const caip = V1_TO_CAIP[v1net];
    if (!caip) return null;
    const k = Object.keys(ASSETS).find((x) => x.startsWith(caip + '|'));
    return k ? k.split('|')[1] : null;
  }

  return {
    VERSION: '1.0.0',
    diagnose, extract, decodeValue, classify, parseSignature, recover, typedDataDigest, domainSeparator, hashStruct,
    encodeType, keccak256, keccakHex, toChecksum, addressForm, isAddress, isSolanaAddress, resolveNetwork, assetInfo,
    NETWORKS, ASSETS, ERROR_CODES, EIP3009_TYPES, bytesToHex, hexToBytes,
    _internal: { gMul, jMul, toAffine, precompute, recoverWith, domainCandidates, P, N, GX, GY },
  };
});
