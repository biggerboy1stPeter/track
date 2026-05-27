# Redirect Tracker Server - Complete Documentation

## Overview

A production-ready Express.js server that handles URL redirects with:

- **Multi-layer encoding** with HMAC signing for tamper detection
- **Bot detection** (server + client side)
- **Geolocation filtering** (whitelist/blacklist countries)
- **Rate limiting** (adaptive for mobile)
- **Proof of Work** (invisible on client)
- **Secure logging**
- **CSP headers** and XSS protection

-----

## Installation & Setup

### 1. Install Dependencies

```bash
npm install
```

### 2. Generate HMAC Secret

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Copy the output to your `.env` file.

### 3. Configure Environment Variables

```bash
cp .env.example .env
```

Edit `.env`:

```env
PORT=10000
NODE_ENV=production
HMAC_SECRET=<paste-your-generated-secret>
TARGET_URL=https://www.example.com
BLOCKED_COUNTRIES=CN,RU,KP
LOG_FILE=clicks.log
```

### 4. Run Server

```bash
npm start
# or for development:
npm run dev
```

Server starts on `http://localhost:10000`

-----

## API Endpoints

### 1. Generate Tracked Link

**Endpoint:** `GET /generate?target=https://example.com`

**Response:**

```json
{
  "success": true,
  "tracked_url": "https://yourserver.com/r/track?p=...&l=...",
  "target": "https://example.com",
  "generated_at": "2024-01-15T10:30:00.000Z"
}
```

**Usage:**

```bash
curl "http://localhost:10000/generate?target=https://www.google.com"
```

### 2. Redirect (Click Link)

**Endpoint:** `GET /r/track?p=<encoded>&l=<payload>`

Flow:

1. Client visits link
1. Server validates HMAC signature
1. Checks geo/bot detection
1. Serves security verification page
1. Client completes proof of work
1. Redirects to target

### 3. Health Check

**Endpoint:** `GET /health`, `GET /ping`, `GET /healthz`

**Response:** `OK` (200)

-----

## Security Features

### HMAC Signing

- **Problem Fixed:** Secret no longer regenerated on restart
- **Solution:** Requires `HMAC_SECRET` env variable in production
- **Benefit:** Links remain valid across server restarts

### Multi-Layer Encoding

- **Layers:** base64, rot13, hex, reverse, Caesar cipher
- **Process:**
1. Add noise (random 16 hex chars on both sides)
1. Apply 5 random encoders in random order
1. Triple URL-encode
1. Generate HMAC-SHA256 signature
- **Tamper Detection:** Any modification invalidates HMAC

### Bot Detection (Server-side)

Scoring system:

- Suspicious user-agent keywords (+40)
- Missing Mozilla header (+20)
- No accept-language header (+18)
- Missing sec-ch-ua on desktop (+25)
- Few HTTP headers (<12) (+22)
- **Threshold:** Score ≥60 = blocked

### Bot Detection (Client-side)

Checks for:

- `navigator.webdriver` (Selenium, Puppeteer, Playwright)
- `window.outerWidth === 0` (Headless)
- Missing `window.chrome` (non-Chrome browser on desktop)
- Phantom.js indicators

### Geolocation Filtering

```env
# Whitelist approach (only allow these countries)
ALLOWED_COUNTRIES=US,CA,GB

# Blacklist approach (block these countries)
BLOCKED_COUNTRIES=CN,RU,KP
```

Uses `ipinfo.io` by default (1-hour cache). Can override:

```env
GEO_API_URL=https://your-api.com/{ip}/country
```

### Rate Limiting

- Desktop: 5 requests/minute
- Mobile: 15 requests/minute
- Excludes health checks

### XSS Protection

- Content Security Policy headers (via Helmet)
- JSON.stringify() for URL injection safety
- Nonce-based inline script execution
- No dangerous HTML/script injection

-----

## Logs

### Format

```
2024-01-15T10:30:00.000Z | ACCESS | IP: 192.168.1.1 | Country: US | ALLOWED
2024-01-15T10:30:05.000Z | BLOCKED | IP: 203.0.113.45 | Country: CN | GEO_RESTRICTION
2024-01-15T10:30:10.000Z | BLOCKED | IP: 198.51.100.0 | Country: US | BOT_DETECTED
2024-01-15T10:30:15.000Z | ERROR | IP: 203.0.113.99 | Country: XX | DECODE_FAILED: HMAC verification failed
```

### Log File

Default: `clicks.log` (in server directory)

Configure: `LOG_FILE=/path/to/logfile`

-----

## Environment Variables Reference

|Variable           |Default           |Required|Notes                                |
|-------------------|------------------|--------|-------------------------------------|
|`PORT`             |10000             |No      |Server port                          |
|`NODE_ENV`         |development       |No      |Set to `production` for strict mode  |
|`HMAC_SECRET`      |random (dev)      |Yes*    |*Required in production              |
|`TARGET_URL`       |https://google.com|No      |Default redirect target              |
|`GEO_API_URL`      |ipinfo.io         |No      |Custom geo API endpoint              |
|`LOG_FILE`         |clicks.log        |No      |Path to access logs                  |
|`ALLOWED_COUNTRIES`|(empty)           |No      |Whitelist countries (comma-separated)|
|`BLOCKED_COUNTRIES`|(empty)           |No      |Blacklist countries (comma-separated)|

-----

## Example Usage

### Generate and Share Links

```javascript
// Node.js example
const fetch = require('node-fetch');

async function createTrackedLink(targetUrl) {
  const res = await fetch(`http://localhost:10000/generate?target=${encodeURIComponent(targetUrl)}`);
  const data = await res.json();
  return data.tracked_url;
}

// Use it
createTrackedLink('https://example.com').then(url => {
  console.log('Share this link:', url);
  // Share on social media, email, etc.
});
```

### Monitoring Access

```bash
# Watch log file in real-time
tail -f clicks.log

# Count access by country
cat clicks.log | grep "ACCESS" | awk '{print $NF}' | sort | uniq -c

# Find bot attempts
cat clicks.log | grep "BOT_DETECTED"

# Failed decodes
cat clicks.log | grep "DECODE_FAILED"
```

-----

## Deployment

### Docker Example

```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY server.js .

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

CMD ["node", "server.js"]
```

Deploy:

```bash
docker build -t redirect-server .
docker run -p 3000:3000 \
  -e HMAC_SECRET='your-secret' \
  -e TARGET_URL='https://example.com' \
  redirect-server
```

### Heroku Example

```bash
heroku create your-app-name
heroku config:set HMAC_SECRET="your-secret"
heroku config:set TARGET_URL="https://example.com"
git push heroku main
```

-----

## Troubleshooting

### Issue: “HMAC_SECRET environment variable is required”

**Solution:** Set in production:

```bash
export HMAC_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")
npm start
```

### Issue: All clicks redirected to bot URL

**Check:**

1. Bot detection too aggressive? Check user-agent
1. Geolocation blocked? Verify `ALLOWED_COUNTRIES` / `BLOCKED_COUNTRIES`
1. HMAC mismatch? Ensure same `HMAC_SECRET` on all instances

### Issue: Proof of work timeout on slow networks

**Solution:** Increase timeout (in HTML script):

```javascript
const timeout = isMobile ? 180000 : 90000; // 3 min / 1.5 min
```

### Issue: Logs not being written

**Check:**

1. Disk space available
1. File permissions: `chmod 666 clicks.log`
1. Path exists: `mkdir -p $(dirname $LOG_FILE)`

-----

## Security Recommendations

✅ **Production Checklist:**

- [ ] Generate unique HMAC_SECRET
- [ ] Set NODE_ENV=production
- [ ] Use HTTPS (reverse proxy with SSL)
- [ ] Set BLOCKED_COUNTRIES or ALLOWED_COUNTRIES
- [ ] Monitor logs regularly
- [ ] Rate limiting configured per your needs
- [ ] Keep dependencies updated: `npm audit fix`
- [ ] Use strong bot detection thresholds
- [ ] Rotate logs periodically
- [ ] Monitor for unusual patterns

-----

## License

ISC

-----

## Support

For issues or improvements, check logs and server console for error messages.
