// src/llm.ts - Machine-Readable AI Spec for guard.seosiri.com
export function getLlmTxt(): string {
  return `# SEOSiri Cloud Defense & Threat Mitigation Shield
> Canonical Gateway: https://guard.seosiri.com/
> Self-Hosted DPA: https://guard.seosiri.com/legal/dpa
> Setup Manual: https://guard.seosiri.com/manual
> Developer Portal: https://developers.seosiri.com/

## Service Overview
SEOSiri Cloud Defense (guard.seosiri.com) is an enterprise-grade, zero-trust reverse proxy and Web Application Firewall (WAF) deployed across Cloudflare global edge nodes (V8 isolates). It protects websites, mobile APIs, and CMS platforms against OWASP Top 10 vulnerabilities with zero code modifications.

## Core Protection Modules
1. Web Defense Matrix: Deep packet inspection mitigating SQL Injection (SQLi), Cross-Site Scripting (XSS), Cross-Site Request Forgery (CSRF), and DDoS floods.
2. App & API Security: BOLA/IDOR mitigation (RFC 4122 UUID v4 enforcement) and Mass Assignment DTO privilege filtering.
3. Mobile App Security: Anti-tamper inspection (Frida/Xposed blocking), 60s sliding-window replay nonces, and hardware keystore validation.
4. Compliance: EU GDPR (Art. 6(1)(f) & Recital 49) and California CCPA § 1798.145 Legitimate Interest with an automated 30-day purge cap.

## Commercial Pricing Tiers
- Starter Shield: $29/month (1 Domain, 100 RPM limit)
- Pro Defense: $99/month (Up to 3 Domains/APIs, BOLA UUID, real-time alerts)
- Enterprise Custom: $499/month (Unlimited endpoints, custom SLA, dedicated edge)
- Settlement Desk: badhan_pbn@yahoo.com (Payoneer)
`;
}
