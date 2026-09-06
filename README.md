# @seosiri/security-proxy

> 📖 **Official Architecture & Documentation:** [SEOSiri Developer Portal](https://developers.seosiri.com/) | [Central Directory](https://www.seosiri.com/2026/07/seosiri-mcp-servers.html) | [Corporate Gateway](https://seosiri.com/)

An autonomous, zero-trust reverse proxy and Web Application Firewall (WAF) built on **Cloudflare Workers**. Defends web applications, mobile APIs, and enterprise CMS platforms against modern cyber threats while enforcing automated subscription duration lifecycles.

---

## 🛡️ Threat Defense Matrix

### Website Defense
* **SQLi (SQL Injection):** Deep query string and JSON body inspection preventing `UNION`, tautologies, and comment truncation.
* **DDoS Mitigation:** Token-bucket rate limiting at the global edge per client IP.
* **XSS (Cross-Site Scripting):** Output escaping and strict Content Security Policy (`CSP`) header injection.
* **CSRF Prevention:** Origin and `Sec-Fetch-Site` header verification on state-changing methods (`POST`, `PUT`, `DELETE`).

### App & Web App Security
* **BOLA / IDOR Protection:** Inspects API route parameters, blocking sequential integer enumeration and enforcing RFC 4122 UUID v4 tokens.
* **Mass Assignment Protection:** Data Transfer Object (`DTO`) parameter whitelisting dropping unauthorized privilege escalation fields (`is_admin`, `role`).
* **MitM Protection:** Enforced TLS 1.3 protocol and `Strict-Transport-Security` (`HSTS`) headers.
* **Mobile App Integrity:** Validates mobile application integrity headers, certificates, and guards against code tampering.

---

## ⚖️ GDPR & CCPA Compliance (Lawsuit-Proof)

* **Zero-Log Clean Traffic:** Legitimate requests pass through edge memory without disk logging.
* **GDPR Recital 49 & Art. 6(1)(f):** Forensic threat telemetry logged strictly under legal *Legitimate Interest for Network Security*.
* **CCPA § 1798.145 Compliance:** Out-of-the-box security incident detection exemption.
* **Data Processing Addendum (DPA):** Self-hosted legal addendum available dynamically at `/legal/dpa`.
* **30-Day Auto-Purge:** All threat and incident logs are automatically purged after 30 days.

---

## 💳 Automated Subscription Lifecycle & Monetization

* **Duration Tracking:** Tracks active days remaining per client API key.
* **Warning Headers:** Injects `X-SEOSiri-Subscription-Warning` when $\le 7$ days remain.
* **Automated Cutoff (HTTP 402):** Halts traffic routing immediately if payment lapses and securely redirects to the renewal portal.
* **Payoneer Settlement Desk:** Route payments to `badhan_pbn@yahoo.com`.

### Plan Tiers

| Tier | Price |
| :--- | :--- |
| **Starter** | \$29 / mo |
| **Pro** | \$99 / mo |
| **Enterprise** | \$499 / mo |

---

## 🚀 Quickstart

### Prerequisites
Ensure you have Node.js and npm installed on your system.

### Installation
```bash
# Install dependencies
npm install

# Compile TypeScript
npm run build

# Run the automated defense test suite
npm test
```

---

## 📄 License

Distributed under the **MIT License**. See the official [LICENSE](https://github.com/SEOSiri-Official/seosiri-security-proxy/blob/main/LICENSE) file for more details.
