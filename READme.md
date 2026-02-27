Here’s a clean, modern, and visually appealing complete README.md for your Anti-Bot Gateway project with working badges (using real Shields.io URLs so they always stay up-to-date and render correctly on GitHub).
# 🛡️ Anti-Bot Gateway




![Node.js Version](https://img.shields.io/badge/Node.js-%3E%3D14.0.0-brightgreen?style=for-the-badge&logo=nodedotjs&logoColor=white)
![Express](https://img.shields.io/badge/Express-4.x-000000?style=for-the-badge&logo=express&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Project Status](https://img.shields.io/badge/Status-Production-orange?style=for-the-badge)
![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=for-the-badge&logo=github)

🛡️ Anti-Bot Gateway

A powerful multi-layered security middleware that separates real humans from bots

Protect downloads, premium content, private APIs, admin panels, gated links — anything you want to keep away from scrapers, credential stuffers, and automated abuse.


  Features •
  How It Works •
  Quick Start •
  API •
  Contributing






---

## 📋 Table of Contents

- [✨ Features](#-features)
- [🔧 How It Works](#-how-it-works)
- [🚀 Quick Start](#-quick-start)
- [⚙️ Configuration](#-configuration)
- [📚 API Reference](#-api-reference)
- [🤖 Advanced Bot Detection](#-advanced-bot-detection)
- [🔐 Security Highlights](#-security-highlights)
- [⚡ Performance](#-performance)
- [🧪 Testing](#-testing)
- [☁️ Deployment](#-deployment)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

---

## ✨ Features

### Multi-Layer Protection Stack

| Layer                | Technology                  | Purpose                                          |
|----------------------|-----------------------------|--------------------------------------------------|
| Rate Limiting        | `express-rate-limit`        | Adaptive per-device throttling                   |
| Passive Bot Scoring  | Header + Fingerprint analysis | 15+ weighted signals                             |
| Geo Restriction      | ipinfo.io                   | Country allow / block lists                      |
| Active Verification  | Canvas + Mouse / Touch      | Interactive puzzle + behavioral entropy          |
| URL Obfuscation      | 5-layer encoding + noise    | Breaks pattern-based scraping                    |

### Mobile-First Design

- Touch-optimized puzzle with adjusted sensitivity  
- Relaxed thresholds (3 moves vs 6, 120s vs 45s timeout)  
- Lower entropy requirement on mobile (8 vs 18)  
- Graceful fallback for real mobile browsers  

### Bot Detection Power

| Signal                        | Weight   | Detection Logic                                      |
|-------------------------------|----------|------------------------------------------------------|
| Suspicious User-Agent         | +35      | HeadlessChrome, Phantom, curl, python-requests…     |
| Alphabetically sorted headers | +20      | Almost always a bot library                          |
| Missing `sec-*` headers       | +14–25   | Modern browsers send them                            |
| Too few headers               | +18      | <10 headers = strong bot signal                      |
| Canvas fingerprint mismatch   | Auto-ban | Known headless rendering patterns                    |
| Low movement entropy          | Scoring  | Straight-line or repetitive mouse/touch paths        |
| DevTools / console traps      | -40      | Penalize detected debugging attempts                 |

---

## 🔧 How It Works

```mermaid
graph TD
    A[Visitor] --> B{Rate Limit Check}
    B -->|Allowed| C{Server-Side Bot Scoring}
    B -->|Blocked| X[🚫 Rate Limit Exceeded → Benign Redirect]

    C -->|Score ≥ 65| Y[🚫 Bot Detected → Benign Redirect]
    C -->|Score < 65| D{Geolocation Allowed?}

    D -->|No| Z[🚫 Geo Blocked → Benign Redirect]
    D -->|Yes| E[Show Verification Page]

    E --> F{Client Verification}
    F -->|Pass| G[✅ Forward to real content]
    F -->|Fail / Timeout| H[❌ Benign fallback page]

    style G fill:#2ecc71,stroke:#27ae60,color:#fff
    style H fill:#e74c3c,stroke:#c0392b,color:#fff
    style X fill:#7f8c8d,stroke:#95a5a6
    style Y fill:#7f8c8d,stroke:#95a5a6
    style Z fill:#7f8c8d,stroke:#95a5a6

🚀 Quick Start
npm install anti-bot-gateway
const express = require('express');
const { antiBotGateway } = require('anti-bot-gateway');

const app = express();

app.use('/downloads/*', antiBotGateway({
  targetUrl:      'https://your-real-secret-content.com/file.zip',
  fallbackUrl:    'https://example.com/sorry-not-allowed',
  ipinfoToken:    process.env.IPINFO_TOKEN,           // optional but recommended
  allowedCountries: ['NG', 'US', 'CA', 'GB'],
  strictMode:     true,                               // tighter thresholds
  maxScore:       65,                                 // tune sensitivity
}));

app.listen(3000, () => console.log('Protected server running → http://localhost:3000'));

⚙️ Configuration Options
Option
Type
Default
Description
targetUrl
string
required
Where legitimate users go after passing
fallbackUrl
string
required
Where blocked / failed users are sent
ipinfoToken
string
optional
For geo filtering
allowedCountries
string[]
[] (all)
ISO 3166-1 alpha-2 codes
blockedCountries
string[]
[]
Takes priority over allowed
strictMode
boolean
false
Tighter behavioral & header checks
maxScore
number
65
Bot score threshold (higher = more permissive)
challengeTimeout
number
45 (desktop)
Seconds before timeout

📚 API Reference
antiBotGateway(options: AntiBotGatewayOptions): express.RequestHandler
See full TypeScript definitions in /src/types.ts

🤖 Advanced Bot Detection (Summary)
	•	Header anomalies (order, count, missing sec-*)
	•	User-Agent blacklisting + entropy scoring
	•	Canvas fingerprinting (headless detection)
	•	Mouse / touch movement entropy analysis
	•	DevTools & console trap detection
	•	Adaptive mobile vs desktop thresholds

🔐 Security Highlights
	•	Strict CSP with nonces
	•	No external scripts on challenge page
	•	Multi-layer URL encoding + random noise
	•	Clickjacking & XSS protection built-in
	•	Privacy-respecting logging (no PII by default)

🤝 Contributing
PRs are very welcome!
	1	Fork the repo
	2	Create your feature branch (git checkout -b feature/amazing-thing)
	3	Commit your changes (git commit -m 'Add some amazing thing')
	4	Push to the branch (git push origin feature/amazing-thing)
	5	Open a Pull Request


Made with ❤️ from nelly king of j town • 2026 

Protect the real users. Let the bots stay out.
```
