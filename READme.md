# 🛡️ Anti-Bot Gateway

<div align="center">

<!-- Badges using the exact SVGs you provided -->
![Node Version](./badges/node.svg)
![Express](./badges/express.svg)
![License](./badges/license.svg)
![Status](./badges/status.svg)
![PRs welcome](./badges/prs.svg)

<h1>🛡️ Advanced Multi-Layer Bot Protection Gateway</h1>

<h3>A sophisticated security middleware that reliably separates humans from bots</h3>

<p>Protect sensitive links, gated downloads, private APIs, premium content, admin panels — or anything you don't want scraped or abused.</p>

<p>
  <strong>Features</strong> •
  <strong>How It Works</strong> •
  <strong>Quick Start</strong> •
  <strong>API</strong> •
  <strong>Security</strong> •
  <strong>Contributing</strong>
</p>

</div>

<br>

---

## 📋 Table of Contents

- [✨ Features](#-features)
- [🔧 How It Works](#-how-it-works)
- [🏗️ Architecture](#-architecture)
- [🚀 Quick Start](#-quick-start)
- [⚙️ Configuration](#-configuration)
- [📚 API Reference](#-api-reference)
- [🤖 Bot Detection](#-bot-detection)
- [🔐 Security](#-security)
- [⚡ Performance](#-performance)
- [🧪 Testing](#-testing)
- [☁️ Deployment](#-deployment)
- [🛠️ Troubleshooting](#-troubleshooting)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [🙏 Acknowledgments](#-acknowledgments)

---

## ✨ Features

### 🛡️ Multi-Layer Protection

| Layer               | Technology              | Description                                      |
|---------------------|-------------------------|--------------------------------------------------|
| **Rate Limiting**   | `express-rate-limit`    | Adaptive limits based on device type             |
| **Bot Detection**   | Header Analysis         | 15+ metrics with weighted scoring system         |
| **Geo Filtering**   | ipinfo.io API           | Country allow/block lists                        |
| **Verification**    | Canvas + Behavior       | Interactive puzzle + entropy-based movement check|
| **Obfuscation**     | Multi-layer encoding    | 5-layer encoding + random noise injection        |

### 📱 Mobile-Optimized Experience

- ✅ Touch-event support with calibrated sensitivity  
- ✅ Relaxed header checks for real mobile browsers  
- ✅ Adaptive thresholds (3 moves vs 6 on desktop)  
- ✅ Extended timeouts (120s vs 45s on desktop)  
- ✅ Lower entropy requirements (8 vs 18 on desktop)  

### 🎯 Bot Detection Arsenal

| Method                     | Description                                    | Weight  |
|----------------------------|------------------------------------------------|---------|
| User-Agent Analysis        | Headless, phantom, bot patterns                | +35     |
| Header Order Check         | Alphabetically sorted = almost certainly a bot | +20     |
| Security Headers           | Missing `sec-*` headers                        | +14–25  |
| Accept-Language            | Missing or suspiciously short                  | +16     |
| Header Count               | Fewer than 10 headers                          | +18     |
| Canvas Fingerprint         | Known headless/browser automation patterns     | Auto-block |
| Behavioral Analysis        | Mouse/touch movement entropy                   | Scoring |
| DevTools Detection         | Console traps & debugging detection            | -40 entropy |

### 🔒 Hardened Security Features

- Strict Content-Security-Policy with nonces  
- Zero external JavaScript dependencies on verification page  
- Multi-layer URL obfuscation  
- Random noise injection to break pattern recognition  
- Comprehensive (but privacy-respecting) logging  
- Built-in XSS & clickjacking protection  

---

## 🔧 How It Works

### Request Flow

```mermaid
graph TD
    A[Visitor] --> B{Rate Limiter}
    B -->|Under Limit| C{Server-Side<br>Bot Detection}
    B -->|Over Limit| D[🚫 Block: Rate Limit]

    C -->|Score < 65| E{Geolocation<br>Check}
    C -->|Score ≥ 65| F[🚫 Block: Bot Detected]

    E -->|Allowed Country| G[Verification Page]
    E -->|Blocked Country| H[🚫 Block: Geo Restricted]

    G --> I{Client-Side<br>Verification}
    I -->|Pass: Puzzle + Behavior| J[✅ Forward to Target URL]
    I -->|Fail: Low entropy / no interaction| K[❌ Fallback / Benign Redirect]
    I -->|Timeout| K

    D --> L[Redirect to safe / dummy page]
    F --> L
    H --> L
    K --> L

    style J fill:#2ecc71,stroke:#27ae60
    style K fill:#e74c3c,stroke:#c0392b
