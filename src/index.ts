import { CLIENT_REGISTRY, MONETIZATION_CONFIG } from './config.js';
import { EnterpriseThreatEngine } from './firewall.js';
import { SubscriptionLifecycleManager } from './subscription.js';
import { ComplianceLegalShield } from './legal.js';
import { GoogleIdentityVerifier, GitHubAppService } from './auth.js';

// In-Memory Sliding-Window DDoS Rate Limiter
const IP_REQUEST_CACHE = new Map<string, number[]>();

function checkDdosRateLimit(ip: string, maxRpm: number): { allowed: boolean; remaining: number; resetSeconds: number } {
  const now = Date.now();
  const windowMs = 60 * 1000;
  const timestamps = (IP_REQUEST_CACHE.get(ip) || []).filter(ts => now - ts < windowMs);

  if (timestamps.length >= maxRpm) {
    return { allowed: false, remaining: 0, resetSeconds: Math.ceil((timestamps[0] + windowMs - now) / 1000) };
  }

  timestamps.push(now);
  IP_REQUEST_CACHE.set(ip, timestamps);
  return { allowed: true, remaining: maxRpm - timestamps.length, resetSeconds: 60 };
}

export interface Env {
  GITHUB_APP_ID?: string;
  GITHUB_APP_PRIVATE_KEY?: string;
  GITHUB_INSTALLATION_ID?: string;
  ALERT_REPO?: string;
  GOOGLE_CLIENT_ID?: string;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const hostname = url.hostname;
    const clientIp = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
    const clientAsn = request.cf?.asn ? `ASN: ${request.cf.asn} (${request.cf.asOrganization || 'ISP'})` : 'Unknown Network';
    const clientCountry = typeof request.cf?.country === 'string' ? request.cf.country : 'GLOBAL';

    // 1. Legal Data Processing Addendum (DPA)
    if (url.pathname === '/legal/dpa') {
      return new Response(ComplianceLegalShield.getDpaDocument(), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    // 2. Google OAuth Token Verification
    if (url.pathname === '/auth/verify-google' && request.method === 'POST') {
      const authHeader = request.headers.get('Authorization') || '';
      const token = authHeader.replace('Bearer ', '').trim();
      const verification = await GoogleIdentityVerifier.verifyToken(token, env.GOOGLE_CLIENT_ID);
      
      if (!verification.valid) {
        return new Response(JSON.stringify({ error: 'INVALID_GOOGLE_TOKEN', reason: verification.error }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        });
      }
      return new Response(JSON.stringify({ status: 'AUTHENTICATED', user: verification.payload?.email }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // MATCH CLIENT PROFILE BEFORE RATE LIMITING AND FIREWALL
    const client = CLIENT_REGISTRY[hostname] || CLIENT_REGISTRY['guard.seosiri.com'];

    // 2.5 DDoS & High-Volume Flood Rate Limiter (Enforce client RPM tier)
    const rateCheck = checkDdosRateLimit(clientIp, client.rateLimitPerMinute);
    if (!rateCheck.allowed) {
      return new Response(JSON.stringify({
        error: "RATE_LIMIT_EXCEEDED",
        message: `Edge rate limit exceeded (${client.rateLimitPerMinute} RPM cap for ${client.tier} Tier). Retry in ${rateCheck.resetSeconds}s.`,
        clientDomain: client.clientDomain,
        renewalDesk: MONETIZATION_CONFIG.payoneerEmail
      }), {
        status: 429,
        headers: {
          "Content-Type": "application/json",
          "Retry-After": String(rateCheck.resetSeconds),
          "X-RateLimit-Limit": String(client.rateLimitPerMinute),
          "X-RateLimit-Remaining": "0"
        }
      });
    }

    // 3. PRIORITY FIREWALL: Evaluate Web & Mobile Threats First
    const threat = await EnterpriseThreatEngine.inspectRequest(request);

    if (threat.isBlocked) {
      const auditLog = ComplianceLegalShield.createAuditRecord(
        threat.threatCategory || 'Unknown Threat',
        threat.details || '',
        clientIp,
        clientAsn,
        clientCountry
      );

      // Background Alert Dispatch
      if (env.GITHUB_APP_ID && env.GITHUB_APP_PRIVATE_KEY && env.GITHUB_INSTALLATION_ID && env.ALERT_REPO) {
        ctx.waitUntil((async () => {
          try {
            const token = await GitHubAppService.getInstallationToken(env.GITHUB_APP_ID!, env.GITHUB_APP_PRIVATE_KEY!, env.GITHUB_INSTALLATION_ID!);
            await GitHubAppService.dispatchSecurityIncident(token, env.ALERT_REPO!, {
              ...auditLog,
              targetHostname: hostname
            });
          } catch (e) {
            console.error('Alert dispatch error:', e);
          }
        })());
      }

      return new Response(JSON.stringify({
        error: 'ACCESS_DENIED_THREAT_INTERCEPTED',
        incident_id: auditLog.incidentId,
        threat: threat.threatCategory,
        timestamp: auditLog.timestamp,
        legal_notice: auditLog.legalBasis,
        message: 'Malicious exploit vector dropped at SEOSiri Edge Security Perimeter.'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 4. Enterprise Product Catalog & Storefront (Direct visits to guard.seosiri.com)
    if ((url.pathname === "/" || url.pathname === "") && (hostname === "guard.seosiri.com" || hostname.includes("workers.dev"))) {
      const accept = request.headers.get("Accept") || "";
      if (accept.includes("text/html")) {
        return new Response(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SEOSiri Cloud Defense | Enterprise Web &amp; Mobile App Security Proxy</title>
  <meta name="description" content="Autonomous Zero-Trust Reverse Proxy &amp; WAF protecting Web, Mobile APIs, and CMS platforms against SQLi, XSS, BOLA, CSRF, and Mobile Code Tampering. Fully compliant with GDPR Recital 49 and CCPA.">
  <link rel="canonical" href="https://guard.seosiri.com/">

  <meta property="og:title" content="SEOSiri Cloud Defense &amp; Threat Mitigation Shield">
  <meta property="og:description" content="Enterprise Zero-Trust WAF &amp; Mobile App Security Gateway protecting APIs with zero code changes.">
  <meta property="og:url" content="https://guard.seosiri.com/">
  <meta property="og:type" content="website">

  <!-- AEO, GEO & Multi-Entity JSON-LD Schema -->
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "SoftwareApplication",
        "@id": "https://guard.seosiri.com/#software",
        "name": "SEOSiri Cloud Defense & Mobile Security Proxy",
        "applicationCategory": "SecurityApplication",
        "operatingSystem": "Cloudflare Workers Global Edge (V8 Isolates)",
        "offers": [
          { "@type": "Offer", "name": "Starter Shield", "price": "29", "priceCurrency": "USD" },
          { "@type": "Offer", "name": "Pro Defense", "price": "99", "priceCurrency": "USD" },
          { "@type": "Offer", "name": "Enterprise Custom", "price": "499", "priceCurrency": "USD" }
        ],
        "publisher": {
          "@type": "Organization",
          "name": "SEOSiri Enterprise Labs",
          "url": "https://seosiri.com"
        }
      },
      {
        "@type": "FAQPage",
        "@id": "https://guard.seosiri.com/#faq",
        "mainEntity": [
          {
            "@type": "Question",
            "name": "How does SEOSiri protect Mobile Phone Applications?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text": "SEOSiri inspects mobile API traffic for hooking frameworks (Frida, Xposed), rejects requests from compromised/jailbroken runtimes, enforces 60-second sliding-window anti-replay nonces, and validates hardware keystore tokens."
            }
          },
          {
            "@type": "Question",
            "name": "Is reverse proxying compliant with EU GDPR and California CCPA?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text": "Yes. Clean traffic passes through in-memory isolates without logging. Threat data is collected strictly under EU GDPR Recital 49 and CCPA § 1798.145 Legitimate Interest for Network Security with an automated 30-day purge cap."
            }
          }
        ]
      }
    ]
  }
  </script>

  <style>
    body { background: #0f172a; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 40px 20px; line-height: 1.6; }
    .container { max-width: 1060px; margin: 0 auto; }
    .header { text-align: center; margin-bottom: 40px; }
    .badge { display: inline-block; background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.3); color: #38bdf8; font-family: monospace; font-size: 11px; padding: 4px 12px; border-radius: 9999px; font-weight: bold; margin-bottom: 12px; }
    h1 { font-size: 32px; margin: 0 0 10px 0; color: #ffffff; letter-spacing: -0.5px; }
    .subtitle { font-size: 15px; color: #94a3b8; max-width: 680px; margin: 0 auto; }

    .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 30px 0; }
    .feature-box { background: #1e293b; border: 1px solid #334155; border-radius: 16px; padding: 24px; text-align: left; }
    .feature-box h3 { margin-top: 0; font-size: 16px; color: #38bdf8; display: flex; align-items: center; gap: 8px; }
    .feature-box p { font-size: 13px; color: #cbd5e1; margin: 0; }

    .pricing-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(290px, 1fr)); gap: 22px; margin: 40px 0; }
    .pricing-card { background: #1e293b; border: 1px solid #334155; border-radius: 20px; padding: 30px; display: flex; flex-direction: column; justify-content: space-between; text-align: left; }
    .pricing-card.featured { border-color: #38bdf8; box-shadow: 0 12px 30px -5px rgba(56, 189, 248, 0.25); position: relative; }
    .popular-tag { position: absolute; top: -12px; right: 24px; background: #0284c7; color: #ffffff; font-family: monospace; font-size: 10px; font-weight: bold; padding: 4px 10px; border-radius: 9999px; }
    .plan-name { font-size: 14px; font-family: monospace; font-weight: bold; color: #38bdf8; text-transform: uppercase; }
    .price { font-size: 34px; font-weight: 800; color: #ffffff; margin: 12px 0; }
    .price span { font-size: 13px; color: #94a3b8; font-weight: normal; }
    .features { list-style: none; padding: 0; margin: 20px 0; font-size: 13px; color: #cbd5e1; flex-grow: 1; }
    .features li { margin-bottom: 10px; display: flex; align-items: center; gap: 8px; }
    .features li::before { content: "✓"; color: #34d399; font-weight: bold; }

    /* CTA Card Buttons */
    .card-btn { display: block; text-align: center; padding: 12px; border-radius: 10px; font-weight: bold; font-size: 13px; text-decoration: none; transition: all 0.2s; margin-top: 10px; }
    .btn-starter { background: #334155; color: #f8fafc; }
    .btn-starter:hover { background: #475569; }
    .btn-pro { background: #0284c7; color: white; box-shadow: 0 4px 14px rgba(2,132,199,0.4); }
    .btn-pro:hover { background: #0369a1; }
    .btn-ent { background: #7c3aed; color: white; }
    .btn-ent:hover { background: #6d28d9; }

    /* Settlement Box */
    .payoneer-box { background: #1e293b; border: 1px solid #475569; border-radius: 20px; padding: 30px; text-align: center; margin-top: 40px; }
    .payoneer-email { font-family: monospace; color: #34d399; font-size: 18px; font-weight: bold; margin: 12px 0; display: inline-block; background: #0f172a; padding: 8px 18px; border-radius: 10px; border: 1px solid #334155; user-select: all; }
    .settlement-actions { display: flex; flex-wrap: wrap; justify-content: center; gap: 12px; margin-top: 18px; }
    .btn-action { display: inline-flex; align-items: center; gap: 6px; padding: 12px 22px; border-radius: 10px; font-weight: bold; font-size: 13px; text-decoration: none; transition: all 0.2s; }
    .btn-primary-action { background: #0284c7; color: white; }
    .btn-primary-action:hover { background: #0369a1; }
    .btn-secondary-action { background: #334155; color: #f8fafc; border: 1px solid #475569; }
    .btn-secondary-action:hover { background: #475569; }

    .footer-links { text-align: center; margin-top: 50px; font-size: 13px; color: #64748b; border-top: 1px solid #334155; padding-top: 30px; }
    .footer-links a { color: #38bdf8; text-decoration: none; margin: 0 10px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <span class="badge">TLS 1.3 SECURED EDGE REVERSE PROXY &amp; MOBILE WAF</span>
      <h1>SEOSiri Cloud Defense &amp; Mobile App Security Shield</h1>
      <p class="subtitle">Autonomous Web Application Firewall and Mobile API Proxy protecting Web, iOS, Android, and CMS backends with zero code modifications.</p>
    </div>

    <!-- Web & Mobile Capabilities Grid -->
    <div class="grid-2">
      <div class="feature-box">
        <h3>📱 Mobile Application Defense</h3>
        <p>Enforces Anti-Tamper &amp; Anti-Hooking (Frida/Xposed blocking), TLS Certificate Pinning support, 60-second sliding-window Nonce replay prevention, and Hardware Keystore / Secure Enclave validation.</p>
      </div>
      <div class="feature-box">
        <h3>🌐 Web App &amp; API Security Checklist</h3>
        <p>Real-time edge mitigation for SQL Injection (SQLi), Cross-Site Scripting (XSS), BOLA/IDOR (Sequential integer blocking with UUID enforcement), and Mass Assignment DTO privilege escalation.</p>
      </div>
    </div>

    <!-- High-Converting Pricing Grid with Direct Action Buttons -->
    <div class="pricing-grid">
      <!-- Starter Card -->
      <div class="pricing-card">
        <div>
          <div class="plan-name">Starter Shield</div>
          <div class="price">$29 <span>/ month</span></div>
          <p style="font-size: 13px; color: #94a3b8;">Essential perimeter defense for blogs, SMBs, and single CMS websites.</p>
          <ul class="features">
            <li>1 Protected Domain / API</li>
            <li>SQL Injection (SQLi) Defense</li>
            <li>Cross-Site Scripting (XSS) Filter</li>
            <li>Standard Rate Limiting (100 RPM)</li>
            <li>GDPR &amp; CCPA Lawsuit-Proof DPA</li>
          </ul>
        </div>
        <a href="https://developers.seosiri.com/#pricing" class="card-btn btn-starter">
          Deploy Starter Shield &rarr;
        </a>
      </div>

      <!-- Pro Card (Featured) -->
      <div class="pricing-card featured">
        <span class="popular-tag">RECOMMENDED</span>
        <div>
          <div class="plan-name" style="color: #34d399;">Pro Defense</div>
          <div class="price">$99 <span>/ month</span></div>
          <p style="font-size: 13px; color: #94a3b8;">High-throughput defense for Mobile APIs, SaaS web apps, and e-commerce.</p>
          <ul class="features">
            <li>Up to 3 Domains &amp; Mobile APIs</li>
            <li>Mobile Anti-Hooking &amp; Replay Nonce</li>
            <li>BOLA / IDOR Sequential ID Blocking</li>
            <li>Mass Assignment DTO Protection</li>
            <li>5-Minute Real-Time Incident Alerts</li>
          </ul>
        </div>
        <a href="https://developers.seosiri.com/#key-issuer" class="card-btn btn-pro">
          Issue Pro License Key &rarr;
        </a>
      </div>

      <!-- Enterprise Card -->
      <div class="pricing-card">
        <div>
          <div class="plan-name" style="color: #c084fc;">Enterprise Custom</div>
          <div class="price">$499 <span>/ month</span></div>
          <p style="font-size: 13px; color: #94a3b8;">Dedicated Cloudflare Zero Trust setup with custom engineering SLA.</p>
          <ul class="features">
            <li>Unlimited Web &amp; Mobile Endpoints</li>
            <li>Dedicated Subdomain (guard.client.com)</li>
            <li>Hardware Keystore Token Attestation</li>
            <li>HIPAA &amp; PCI-DSS Audit Reports</li>
            <li>24/7 Priority Emergency Support</li>
          </ul>
        </div>
        <a href="mailto:info@seosiri.com?subject=Enterprise%20Security%20Proxy%20Consultation" class="card-btn btn-ent">
          Contact Enterprise Desk &rarr;
        </a>
      </div>
    </div>

    <!-- Direct Settlement Desk with Direct Funnel Action Buttons -->
    <div class="payoneer-box">
      <h3 style="margin-top:0; color:#ffffff; font-size:18px;">Direct Subscription Settlement Desk</h3>
      <p style="font-size:13px; color:#cbd5e1; margin-bottom:5px;">To activate active edge protection for your domain or mobile API, submit monthly payment to our verified Payoneer account:</p>
      
      <div>
        <span class="payoneer-email">${MONETIZATION_CONFIG.payoneerEmail}</span>
      </div>
      
      <p style="font-size:12px; color:#94a3b8; max-width:600px; margin: 10px auto;">
        Include your <strong>Protected Domain</strong> and <strong>Alert Email</strong> in the payment notes. Your edge CNAME configuration will be active within 15 minutes.
      </p>

      <div class="settlement-actions">
        <a href="https://developers.seosiri.com/#key-issuer" class="btn-action btn-primary-action">
          🔑 Generate Scoped License Key &rarr;
        </a>
        <a href="https://developers.seosiri.com/#user-portal" class="btn-action btn-secondary-action">
          👤 Client Security Dashboard
        </a>
        <a href="https://developers.seosiri.com/#pricing" class="btn-action btn-secondary-action">
          📊 Compare All 20 API Packages
        </a>
      </div>
    </div>

    <!-- Footer Links with rel="nofollow" on Author Name -->
    <div class="footer-links">
      <a href="/legal/dpa">Data Processing Addendum (DPA)</a> • 
      <a href="https://developers.seosiri.com/">SEOSiri Developer Portal</a> • 
      <a href="mailto:${MONETIZATION_CONFIG.supportDesk}">Corporate Support Desk</a>
      <p style="margin-top: 15px;">
        © 2026 SEOSiri Enterprise Labs. Designed by Lead Architect 
        <a href="https://www.seosiri.com/p/about.html" rel="nofollow noopener noreferrer" style="color: #38bdf8; text-decoration: underline;">Momenul Ahmad</a>.
      </p>
    </div>
  </div>
</body>
</html>`, {
          status: 200,
          headers: { "Content-Type": "text/html; charset=utf-8" }
        });
      }
    }

    // 5. Automated Subscription Lifecycle Cutoff
    const subStatus = SubscriptionLifecycleManager.evaluateStatus(client);
    if (!subStatus.hasActiveSubscription) {
      return new Response(SubscriptionLifecycleManager.generateLapsedPage(client.clientDomain), {
        status: 402,
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'X-SEOSiri-Subscription-Status': 'EXPIRED_HALTED',
          'Retry-After': '86400'
        }
      });
    }

    // 6. Forward Clean Traffic to Upstream Origin Server
    try {
      const originUrl = new URL(url.pathname + url.search, client.originServerUrl);
      const proxyRequest = new Request(originUrl.toString(), {
        method: request.method,
        headers: request.headers,
        body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
        redirect: 'follow'
      });

      const originResponse = await fetch(proxyRequest);
      const responseHeaders = new Headers(originResponse.headers);

      EnterpriseThreatEngine.applySecurityHeaders(responseHeaders);

      if (subStatus.status === 'WARNING_EXPIRING_SOON') {
        responseHeaders.set('X-SEOSiri-Subscription-Warning', subStatus.message);
      }

      return new Response(originResponse.body, {
        status: originResponse.status,
        headers: responseHeaders
      });
    } catch (err: any) {
      return new Response(JSON.stringify({
        error: 'ORIGIN_GATEWAY_TIMEOUT',
        message: 'Unable to establish secure connection with origin upstream server.'
      }), {
        status: 502,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
};
