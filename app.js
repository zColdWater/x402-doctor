/*! x402 Doctor UI. MIT License. No network requests: everything runs locally. */
(function () {
  'use strict';
  const D = window.X402Doctor;
  const EXAMPLES = window.X402_EXAMPLES || [];

  // Tip addresses (the maintainer's public receiving addresses). Each one is validated below and hidden if invalid.
  const TIP = {
    evm: '0x73218b6438e15E75B115EA47837F2a7fde79f623',
    solana: 'ACwEDgFzYZuxeyx6BKBP3BpeaHzKEp4Y9rbXTemrgLZ8',
    bitcoin: 'bc1qhzk7wfwtjfrxtds2z2y202v9ftqd789wjlas05',
  };
  const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
  const BASE_CHAIN_HEX = '0x2105';

  const $ = (id) => document.getElementById(id);
  const el = (tag, attrs, ...kids) => {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === 'class') n.className = v; else if (k === 'text') n.textContent = v; else n.setAttribute(k, v);
    }
    for (const k of kids) if (k !== null && k !== undefined) n.append(k);
    return n;
  };
  const inputs = { challenge: $('in-challenge'), payment: $('in-payment'), response: $('in-response') };
  let exampleNow = null;

  // ---------------------------------------------------------------- examples
  const exBox = $('examples');
  EXAMPLES.forEach((e) => {
    const b = el('button', { type: 'button', text: e.title });
    b.addEventListener('click', () => {
      inputs.challenge.value = e.texts.challenge || '';
      inputs.payment.value = e.texts.payment || '';
      inputs.response.value = e.texts.response || '';
      exampleNow = e.now;
      document.querySelector('input[name=clock][value=custom]').checked = true;
      $('clock-custom').value = String(e.now);
      const ex = $('example-explain');
      ex.textContent = e.explain + ' Times are checked against the example\'s own clock (' + new Date(e.now * 1000).toISOString().replace('.000Z', 'Z') + ').';
      ex.hidden = false;
      run();
    });
    exBox.append(b);
  });

  // ---------------------------------------------------------------- run
  function clockNow() {
    const mode = document.querySelector('input[name=clock]:checked').value;
    if (mode === 'custom') {
      const v = Number($('clock-custom').value.trim());
      if (Number.isFinite(v) && v > 0) return Math.floor(v > 1e12 ? v / 1000 : v);
    }
    return Math.floor(Date.now() / 1000);
  }

  const LEVEL_ORDER = { fail: 0, warn: 1, pass: 2, info: 3 };
  const VERDICT_TEXT = {
    ok: ['No problems found.', 'Everything the Doctor can check offline looks right. If the payment still fails, check the payer\'s balance, whether the nonce was already used, and the facilitator\'s /supported list.'],
    warnings: ['Warnings only.', 'Nothing is certainly broken, but the warnings below are common reasons for rejected payments.'],
    problems: ['Problems found.', 'The failures below would make a facilitator or server reject this payment.'],
    nothing_found: ['Nothing to check.', 'No x402 object was found. Paste a header value (base64), a header line, raw JSON, or curl -i output.'],
  };

  function run() {
    const texts = { challenge: inputs.challenge.value, payment: inputs.payment.value, response: inputs.response.value };
    const out = $('results');
    out.textContent = '';
    if (!texts.challenge.trim() && !texts.payment.trim() && !texts.response.trim()) return;
    let r;
    try { r = D.diagnose(texts, { now: clockNow() }); } catch (e) {
      out.append(el('div', { class: 'verdict v-problems', text: 'The Doctor hit an internal error: ' + String(e && e.message || e) }));
      return;
    }
    const panel = el('div', { class: 'panel' });
    const [head, sub] = VERDICT_TEXT[r.verdict];
    const counts = r.verdict === 'nothing_found' ? '' : ` ${r.fails} fail, ${r.warns} warning${r.warns === 1 ? '' : 's'}.`;
    panel.append(el('div', { class: 'verdict v-' + r.verdict }, head + counts, el('p', { text: sub })));
    if (r.found.length) panel.append(el('p', { class: 'note', text: 'Found: ' + r.found.map((k) => k + (r.sources[k] ? ' (' + r.sources[k] + ')' : '')).join(', ') + '. Clock: ' + new Date(r.now * 1000).toISOString().replace('.000Z', 'Z') + '.' }));

    const showInfo = el('input', { type: 'checkbox', id: 'show-info' });
    const list = el('ul', { class: 'checks' });
    const checks = r.checks.slice().sort((a, b) => LEVEL_ORDER[a.level] - LEVEL_ORDER[b.level]);
    const render = () => {
      list.textContent = '';
      for (const c of checks) {
        if (c.level === 'info' && !showInfo.checked) continue;
        const msg = el('div', { class: 'msg' }, el('span', { class: 'cid', text: c.id }), c.message);
        if (c.code && D.ERROR_CODES[c.code]) msg.append(el('a', { class: 'code-link', href: 'errors/' + c.code + '.html', text: '→ ' + c.code }));
        list.append(el('li', {}, el('span', { class: 'tag t-' + c.level, text: c.level }), msg));
      }
      if (!list.children.length) list.append(el('li', {}, el('span', { class: 'tag t-info', text: 'info' }), el('div', { class: 'msg', text: 'No failures or warnings.' })));
    };
    showInfo.addEventListener('change', render);
    render();
    const infoCount = checks.filter((c) => c.level === 'info').length;
    if (infoCount) panel.append(el('label', { class: 'toggle', for: 'show-info' }, showInfo, `Show ${infoCount} informational note${infoCount === 1 ? '' : 's'}`));
    panel.append(list);

    if (r.codes.length) {
      const box = el('div', { class: 'note' }, 'Error codes this matches: ');
      r.codes.forEach((c, i) => {
        if (i) box.append(', ');
        box.append(D.ERROR_CODES[c] ? el('a', { href: 'errors/' + c + '.html', text: c }) : el('code', { text: c }));
      });
      panel.append(box);
    }
    if (r.settlement && r.settlement.explorer) panel.append(el('p', { class: 'note' }, 'Transaction: ', el('a', { href: r.settlement.explorer, rel: 'noopener noreferrer', target: '_blank', text: 'open in block explorer' }), ' (opens a third-party site).'));

    for (const k of ['challenge', 'payment', 'settlement', 'verify']) {
      const v = r.decoded[k];
      if (!v) continue;
      const clean = JSON.parse(JSON.stringify(v, (key, val) => (key === '__fromFacilitatorRequest' ? undefined : val)));
      panel.append(el('details', {}, el('summary', { text: 'Decoded ' + k }), el('pre', { text: JSON.stringify(clean, null, 2) })));
    }
    out.append(panel);
  }

  let timer = null;
  for (const t of Object.values(inputs)) t.addEventListener('input', () => { clearTimeout(timer); timer = setTimeout(run, 350); });
  $('run').addEventListener('click', run);
  $('clear').addEventListener('click', () => {
    for (const t of Object.values(inputs)) t.value = '';
    $('results').textContent = '';
    $('example-explain').hidden = true;
    document.querySelector('input[name=clock][value=now]').checked = true;
    $('clock-custom').value = '';
    exampleNow = null;
  });
  $('clock-custom').addEventListener('input', () => { document.querySelector('input[name=clock][value=custom]').checked = true; });
  document.querySelectorAll('input[name=clock]').forEach((r) => r.addEventListener('change', run));
  $('ver').textContent = 'Version ' + D.VERSION + '.';

  // ---------------------------------------------------------------- tip addresses (validated before display)
  const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  function base58Len(s) {
    let n = 0n;
    for (const ch of s) { const i = B58.indexOf(ch); if (i < 0) return -1; n = n * 58n + BigInt(i); }
    let bytes = 0; while (n > 0n) { n >>= 8n; bytes++; }
    for (const ch of s) { if (ch === '1') bytes++; else break; }
    return bytes;
  }
  function bech32Ok(addr) {
    const CH = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
    const s = addr.toLowerCase();
    const pos = s.lastIndexOf('1');
    if (s !== addr || pos < 1 || pos + 7 > s.length) return false;
    const hrp = s.slice(0, pos); const data = [];
    for (const c of s.slice(pos + 1)) { const v = CH.indexOf(c); if (v < 0) return false; data.push(v); }
    const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    const vals = [...hrp].map((c) => c.charCodeAt(0) >> 5).concat([0], [...hrp].map((c) => c.charCodeAt(0) & 31), data);
    for (const v of vals) { const b = chk >> 25; chk = ((chk & 0x1ffffff) << 5) ^ v; for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= G[i]; }
    return hrp === 'bc' && chk === 1 && data[0] === 0 && (data.length - 7 === 32 || data.length - 7 === 52);
  }
  const evmOk = D.isAddress(TIP.evm) && D.toChecksum(TIP.evm) === TIP.evm && !/^0x0{40}$/i.test(TIP.evm);
  if (evmOk) {
    $('tip-evm').textContent = TIP.evm;
    $('tip-box').hidden = false;
    if (base58Len(TIP.solana) === 32) { $('tip-sol').textContent = TIP.solana; $('tip-sol-row').hidden = false; }
    if (bech32Ok(TIP.bitcoin)) { $('tip-btc').textContent = TIP.bitcoin; $('tip-btc-row').hidden = false; }
  }
  document.querySelectorAll('[data-copy]').forEach((b) => b.addEventListener('click', async () => {
    const text = $(b.getAttribute('data-copy')).textContent;
    try { await navigator.clipboard.writeText(text); b.textContent = 'Copied'; } catch (_) { b.textContent = 'Select and copy'; }
    setTimeout(() => { b.textContent = 'Copy'; }, 1600);
  }));

  // Browser-wallet tip: asks the wallet to send USDC on Base. The user confirms in the wallet.
  const status = $('tip-status');
  function eth() { return window.ethereum && typeof window.ethereum.request === 'function' ? window.ethereum : null; }
  function showWalletButtons() { if (evmOk && eth()) $('tip-buttons').hidden = false; }
  showWalletButtons();
  window.addEventListener('ethereum#initialized', showWalletButtons, { once: true });
  setTimeout(showWalletButtons, 1200);
  const pad = (hex) => hex.replace(/^0x/, '').toLowerCase().padStart(64, '0');
  document.querySelectorAll('[data-tip]').forEach((b) => b.addEventListener('click', async () => {
    const usd = Number(b.getAttribute('data-tip'));
    const provider = eth();
    if (!provider || !evmOk) { status.textContent = 'No browser wallet found. Send USDC on Base to the address above from any wallet.'; return; }
    if (!window.confirm(`Ask your wallet to send ${usd} USDC on Base to ${TIP.evm}? You will see and confirm the transfer in your wallet.`)) return;
    try {
      status.textContent = 'Connecting to your wallet…';
      const [from] = await provider.request({ method: 'eth_requestAccounts' });
      let chain = await provider.request({ method: 'eth_chainId' });
      if (chain !== BASE_CHAIN_HEX) {
        status.textContent = 'Asking your wallet to switch to Base…';
        await provider.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: BASE_CHAIN_HEX }] });
        chain = await provider.request({ method: 'eth_chainId' });
        if (chain !== BASE_CHAIN_HEX) { status.textContent = 'Your wallet is not on Base. Nothing was sent.'; return; }
      }
      const amount = BigInt(Math.round(usd * 1e6));
      const data = '0xa9059cbb' + pad(TIP.evm) + amount.toString(16).padStart(64, '0');
      status.textContent = 'Confirm the transfer in your wallet…';
      const tx = await provider.request({ method: 'eth_sendTransaction', params: [{ from, to: USDC_BASE, data, value: '0x0' }] });
      status.textContent = '';
      status.append('Thank you! Transaction sent: ', el('a', { href: 'https://basescan.org/tx/' + tx, target: '_blank', rel: 'noopener noreferrer', text: String(tx).slice(0, 18) + '…' }));
    } catch (e) {
      const code = e && e.code;
      status.textContent = code === 4001 ? 'Cancelled in the wallet. Nothing was sent.' : code === 4902 ? 'Your wallet does not have the Base network yet. Add Base, or send USDC to the address above.' : 'The wallet returned an error: ' + String((e && e.message) || e).slice(0, 200) + '. Nothing was sent unless your wallet shows a transaction.';
    }
  }));
})();
