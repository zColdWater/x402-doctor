// Builds the static pages that are generated from doctor.js: errors/*.html, sitemap.xml, robots.txt.
//   node scripts/build.mjs [--base https://zcoldwater.github.io/x402-doctor/]
import { writeFileSync, mkdirSync } from 'node:fs';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const D = require('../doctor.js');
const root = new URL('..', import.meta.url);
const argBase = process.argv.indexOf('--base');
const BASE = (argBase > 0 ? process.argv[argBase + 1] : 'https://zcoldwater.github.io/x402-doctor/').replace(/\/?$/, '/');
const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const codeify = (s) => esc(s).replace(/&quot;([^&<>]{1,60}?)&quot;/g, '<code>$1</code>');

const CSP = "default-src 'none'; style-src 'self'; img-src 'self' data:; connect-src 'none'; base-uri 'none'; form-action 'none'";
const ICON = "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%231f5eff'/%3E%3Ctext x='16' y='22' font-family='monospace' font-size='15' font-weight='700' text-anchor='middle' fill='white'%3E402%3C/text%3E%3C/svg%3E";
const page = ({ title, description, canonical, body }) => `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="${CSP}">
<meta name="referrer" content="no-referrer">
<title>${esc(title)}</title>
<meta name="description" content="${esc(description)}">
<link rel="canonical" href="${esc(canonical)}">
<link rel="stylesheet" href="../style.css">
<link rel="icon" href="${ICON}">
</head>
<body>
<div class="wrap">
  <header class="top">
    <h1><a href="../">x402 Doctor</a></h1>
    <nav aria-label="Site"><a href="./">Error codes</a><a href="../#support">Support</a><a href="https://github.com/zColdWater/x402-doctor">Source</a></nav>
  </header>
${body}
  <footer class="foot">
    <p>Descriptions follow the error code table of the <a href="https://github.com/coinbase/x402">x402 v2 specification</a>; causes and fixes are the Doctor's notes. Facilitators may also return codes of their own.</p>
    <p>x402 Doctor is free and MIT licensed; it is written by Bolt, an AI agent, as part of an experiment in agent-run projects, and published without human review. Not affiliated with Coinbase, Circle or the x402 Foundation.</p>
  </footer>
</div>
</body>
</html>
`;

mkdirSync(new URL('errors/', root), { recursive: true });
const codes = Object.keys(D.ERROR_CODES);
for (const code of codes) {
  const e = D.ERROR_CODES[code];
  const others = codes.filter((c) => c !== code).map((c) => `<li><a href="${c}.html"><code>${c}</code></a></li>`).join('');
  const body = `  <article class="doc panel">
    <h1>x402 error <code>${esc(code)}</code></h1>
    <p class="lede">${esc(e.title)}.</p>
    <h2>What the spec says</h2>
    <blockquote>${esc(e.spec)}</blockquote>
    <h2>Common causes</h2>
    <ul>${e.causes.map((c) => `<li>${codeify(c)}</li>`).join('')}</ul>
    <h2>How to fix it</h2>
    <p>${codeify(e.fix)}</p>
    <h2>Check your own payment</h2>
    <p>Paste the 402 challenge, the <code>PAYMENT-SIGNATURE</code> / <code>X-PAYMENT</code> header and the response into <a href="../">x402 Doctor</a>. It decodes them in your browser, checks every field, and for signature errors recovers the signer and names the EIP-712 domain the signature was really made with. Nothing is uploaded.</p>
  </article>
  <section class="panel"><h2>Other x402 error codes</h2><ul class="err-list">${others}</ul></section>`;
  writeFileSync(new URL(`errors/${code}.html`, root), page({
    title: `x402 error ${code}: ${e.title}`,
    description: `What the x402 error ${code} means, its common causes, and how to fix it. ${e.spec}`.slice(0, 300),
    canonical: `${BASE}errors/${code}.html`,
    body,
  }));
}
const index = `  <article class="doc panel">
    <h1>x402 error code reference</h1>
    <p class="lede">The error codes a facilitator or server returns in <code>invalidReason</code> (verify) or <code>errorReason</code> (settle), what they mean, and how to fix them.</p>
    <ul class="err-list">${codes.map((c) => `<li><a href="${c}.html"><code>${c}</code></a> · ${esc(D.ERROR_CODES[c].title)}</li>`).join('')}</ul>
    <p>Got one of these? Paste your headers into <a href="../">x402 Doctor</a> to find the cause. It runs offline in your browser.</p>
  </article>`;
writeFileSync(new URL('errors/index.html', root), page({
  title: 'x402 error code reference: invalid_exact_evm_payload_signature, insufficient_funds and more',
  description: 'All x402 v2 error codes (invalidReason / errorReason) with their meaning, common causes and fixes.',
  canonical: `${BASE}errors/`,
  body: index,
}));

const urls = [BASE, `${BASE}errors/`, ...codes.map((c) => `${BASE}errors/${c}.html`)];
const today = new Date().toISOString().slice(0, 10);
writeFileSync(new URL('sitemap.xml', root), `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls.map((u) => `  <url><loc>${u}</loc><lastmod>${today}</lastmod></url>`).join('\n')}\n</urlset>\n`);
writeFileSync(new URL('robots.txt', root), `User-agent: *\nAllow: /\n\nSitemap: ${BASE}sitemap.xml\n`);
console.log(`built ${codes.length} error pages + index, sitemap (${urls.length} URLs), robots.txt for ${BASE}`);
