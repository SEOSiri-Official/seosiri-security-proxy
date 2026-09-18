// src/storefront.ts - Dedicated Storefront HTML Component for guard.seosiri.com
import { MONETIZATION_CONFIG } from './config.js';

export function getStorefrontHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SEOSiri Cloud Defense | Enterprise Web &amp; Mobile App Security Proxy</title>
  <meta name="description" content="Zero-Trust Reverse Proxy &amp; WAF protecting Web, Mobile APIs, and CMS platforms against SQLi, XSS, BOLA, CSRF, and Mobile Code Tampering. Fully compliant with GDPR Recital 49 and CCPA.">
  <link rel="canonical" href="https://guard.seosiri.com/">

  <meta property="og:title" content="SEOSiri Cloud Defense &amp; Threat Mitigation Shield">
  <meta property="og:description" content="Enterprise Zero-Trust WAF &amp; Mobile App Security Gateway protecting APIs with zero code changes.">
  <meta property="og:image" content="https://raw.githubusercontent.com/SEOSiri-Official/developers-seosiri-com/main/public/momenul-ahmad.png">
  <meta property="og:url" content="https://guard.seosiri.com/">
  <meta property="og:type" content="website">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="SEOSiri Cloud Defense &amp; Threat Mitigation Shield">
  <meta name="twitter:description" content="Enterprise Zero-Trust WAF protecting Web &amp; Mobile APIs with zero code changes.">
  <meta name="twitter:image" content="https://raw.githubusercontent.com/SEOSiri-Official/developers-seosiri-com/main/public/momenul-ahmad.png">

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
            "name": "How does Method A (DNS / CNAME Proxy) protect my site with zero code modifications?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text": "You point your domain or API subdomain CNAME to guard.seosiri.com. Traffic hits Cloudflare edge nodes first. Malicious SQL injections, XSS payloads, and BOLA probes are dropped instantly; legitimate traffic is proxied to your origin server with strict HSTS and CSP headers."
            }
          },
          {
            "@type": "Question",
            "name": "How does automated Payoneer activation and subscription duration work?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text": "Subscriptions settle via Payoneer to badhan_pbn@yahoo.com. Your domain is provisioned within 15 minutes. The proxy checks subscription duration in-memory on every request."
            }
          },
          {
            "@type": "Question",
            "name": "Is reverse proxy inspection compliant with EU GDPR and California CCPA?",
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
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body { background: #0f172a; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 0; line-height: 1.6; }
    
    .nav-bar { position: sticky; top: 0; z-index: 50; background: rgba(15, 23, 42, 0.9); backdrop-filter: blur(12px); border-bottom: 1px solid #1e293b; padding: 12px 24px; }
    .nav-content { max-width: 1100px; margin: 0 auto; display: flex; align-items: center; justify-content: space-between; gap: 16px; }
    .brand { font-weight: 800; font-size: 15px; color: #ffffff; text-decoration: none; display: flex; align-items: center; gap: 8px; }
    .brand-tag { font-size: 10px; font-family: monospace; background: rgba(56, 189, 248, 0.15); color: #38bdf8; padding: 2px 8px; border-radius: 6px; border: 1px solid rgba(56, 189, 248, 0.3); }
    .nav-links { display: flex; align-items: center; gap: 18px; list-style: none; margin: 0; padding: 0; font-size: 13px; }
    .nav-links a { color: #94a3b8; text-decoration: none; font-weight: 500; transition: color 0.2s; }
    .nav-links a:hover { color: #ffffff; }
    .nav-cta { background: #0284c7; color: white !important; padding: 6px 14px; border-radius: 8px; font-weight: 600; font-size: 12px; transition: background 0.2s; }
    .nav-cta:hover { background: #0369a1 !important; }

    .container { max-width: 1060px; margin: 0 auto; padding: 40px 20px; }
    .header { text-align: center; margin-bottom: 40px; margin-top: 20px; }
    .badge { display: inline-block; background: rgba(56, 189, 248, 0.1); border: 1px solid rgba(56, 189, 248, 0.3); color: #38bdf8; font-family: monospace; font-size: 11px; padding: 4px 12px; border-radius: 9999px; font-weight: bold; margin-bottom: 12px; }
    h1 { font-size: 34px; margin: 0 0 12px 0; color: #ffffff; letter-spacing: -0.5px; }
    .subtitle { font-size: 15px; color: #94a3b8; max-width: 700px; margin: 0 auto; }

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

    .card-btn { display: block; text-align: center; padding: 12px; border-radius: 10px; font-weight: bold; font-size: 13px; text-decoration: none; transition: all 0.2s; margin-top: 10px; }
    .btn-starter { background: #334155; color: #f8fafc; }
    .btn-starter:hover { background: #475569; }
    .btn-pro { background: #0284c7; color: white; box-shadow: 0 4px 14px rgba(2,132,199,0.4); }
    .btn-pro:hover { background: #0369a1; }
    .btn-ent { background: #7c3aed; color: white; }
    .btn-ent:hover { background: #6d28d9; }

    .payoneer-box { background: #1e293b; border: 1px solid #475569; border-radius: 20px; padding: 30px; text-align: center; margin-top: 40px; }
    .payoneer-email-container { display: inline-flex; align-items: center; gap: 8px; background: #0f172a; padding: 8px 18px; border-radius: 10px; border: 1px solid #334155; margin: 12px 0; }
    .payoneer-email { font-family: monospace; color: #34d399; font-size: 18px; font-weight: bold; user-select: all; }
    .copy-btn { background: #334155; border: none; color: #f8fafc; font-size: 11px; padding: 4px 8px; border-radius: 6px; cursor: pointer; font-family: monospace; transition: background 0.2s; }
    .copy-btn:hover { background: #475569; }
    .settlement-actions { display: flex; flex-wrap: wrap; justify-content: center; gap: 12px; margin-top: 18px; }
    .btn-action { display: inline-flex; align-items: center; gap: 6px; padding: 12px 22px; border-radius: 10px; font-weight: bold; font-size: 13px; text-decoration: none; transition: all 0.2s; }
    .btn-primary-action { background: #0284c7; color: white; }
    .btn-primary-action:hover { background: #0369a1; }
    .btn-secondary-action { background: #334155; color: #f8fafc; border: 1px solid #475569; }
    .btn-secondary-action:hover { background: #475569; }

    .faq-section { margin-top: 60px; text-align: left; }
    .faq-header { text-align: center; margin-bottom: 30px; }
    .faq-grid { display: flex; flex-direction: column; gap: 12px; }
    details { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 14px 18px; transition: border-color 0.2s; }
    details[open] { border-color: #38bdf8; }
    summary { font-weight: 700; font-size: 14px; color: #f8fafc; cursor: pointer; list-style: none; display: flex; justify-content: space-between; align-items: center; }
    summary::-webkit-details-marker { display: none; }
    summary::after { content: "+"; font-size: 18px; color: #38bdf8; }
    details[open] summary::after { content: "−"; }
    .faq-answer { margin-top: 12px; font-size: 13px; color: #cbd5e1; line-height: 1.6; border-top: 1px solid #334155; padding-top: 10px; }

    .footer-links { text-align: center; margin-top: 60px; font-size: 13px; color: #64748b; border-top: 1px solid #334155; padding-top: 30px; }
    .footer-links a { color: #38bdf8; text-decoration: none; margin: 0 10px; }

    @media (max-width: 768px) {
      .nav-links { display: none; }
      h1 { font-size: 26px; }
      .pricing-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>

  <header class="nav-bar">
    <div class="nav-content">
      <a href="https://guard.seosiri.com/" class="brand">
        <span>🛡️ SEOSiri Cloud Defense</span>
        <span class="brand-tag">WAF &amp; PROXY</span>
      </a>
      <ul class="nav-links">
        <li><a href="#capabilities">Capabilities</a></li>
        <li><a href="#mobile">Mobile WAF</a></li>
        <li><a href="#pricing">Pricing</a></li>
        <li><a href="#faq">FAQ</a></li>
        <li><a href="/manual">Manual</a></li>
        <li><a href="/legal/dpa">Legal DPA</a></li>
        <li><a href="https://developers.seosiri.com/#user-portal" class="nav-cta">Client Dashboard &rarr;</a></li>
      </ul>
    </div>
  </header>

  <div class="container">
    <div class="header">
      <span class="badge">TLS 1.3 SECURED EDGE REVERSE PROXY &amp; MOBILE WAF</span>
      <h1>SEOSiri Cloud Defense &amp; Mobile App Security Shield</h1>
      <p class="subtitle">Autonomous Web Application Firewall and Mobile API Proxy protecting Web, iOS, Android, and CMS backends with zero code modifications.</p>
    </div>

    <div class="grid-2" id="capabilities">
      <div class="feature-box" id="mobile">
        <h3>📱 Mobile Application Defense</h3>
        <p>Enforces Anti-Tamper &amp; Anti-Hooking (Frida/Xposed blocking), TLS Certificate Pinning support, 60-second sliding-window Nonce replay prevention, and Hardware Keystore / Secure Enclave validation.</p>
      </div>
      <div class="feature-box">
        <h3>🌐 Web App &amp; API Security Checklist</h3>
        <p>Real-time edge mitigation for SQL Injection (SQLi), Cross-Site Scripting (XSS), BOLA/IDOR (Sequential integer blocking with UUID enforcement), and Mass Assignment DTO privilege escalation.</p>
      </div>
    </div>

    <div class="pricing-grid" id="pricing">
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

    <div class="payoneer-box">
      <h3 style="margin-top:0; color:#ffffff; font-size:18px;">Direct Subscription Settlement Desk</h3>
      <p style="font-size:13px; color:#cbd5e1; margin-bottom:5px;">To activate active edge protection for your domain or mobile API, submit monthly payment to our verified Payoneer account:</p>
      
      <div class="payoneer-email-container">
        <span class="payoneer-email" id="payoneer-addr">${MONETIZATION_CONFIG.payoneerEmail}</span>
        <button class="copy-btn" id="copy-btn" onclick="copyPayoneer()">Copy</button>
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

    <section class="faq-section" id="faq">
      <div class="faq-header">
        <span class="badge">FREQUENTLY ASKED QUESTIONS</span>
        <h2 style="font-size:24px; color:#ffffff; margin:8px 0;">Enterprise Architecture &amp; Deployment FAQ</h2>
        <p style="font-size:13px; color:#94a3b8;">Everything technical directors, developers, and security auditors need to know.</p>
      </div>

      <div class="faq-grid">
        <details open>
          <summary>How does Method A (DNS / CNAME Proxy) protect my site with zero code modifications?</summary>
          <div class="faq-answer">
            You point your domain or API subdomain CNAME (e.g. <code>api.yourdomain.com</code>) to <code>guard.seosiri.com</code>. Incoming traffic routes through Cloudflare global edge nodes before reaching your server. Malicious SQL injections, XSS payloads, and BOLA/IDOR probes are intercepted and dropped at the edge. Legitimate traffic is proxied transparently to your origin server with strict HSTS and CSP headers injected automatically.
          </div>
        </details>

        <details>
          <summary>How does automated Payoneer activation and subscription duration work?</summary>
          <div class="faq-answer">
            Subscriptions are settled via Payoneer to <code>badhan_pbn@yahoo.com</code>. Your domain profile is provisioned with its active expiration timestamp. The proxy checks subscription duration in-memory on every request. If a subscription lapses, a graceful suspension notice is served (HTTP 402) rather than exposing an unprotected backend to the open internet.
          </div>
        </details>

        <details>
          <summary>Will the reverse proxy add latency to my website or mobile API?</summary>
          <div class="faq-answer">
            No. SEOSiri operates on Cloudflare Workers V8 memory isolates deployed across 330+ edge locations worldwide. Threat inspection, regular expression scanning, and rate limiting occur in-memory with sub-10ms global latency.
          </div>
        </details>

        <details>
          <summary>How does SEOSiri protect Mobile Phone Applications (iOS and Android)?</summary>
          <div class="faq-answer">
            The gateway blocks requests originating from mobile dynamic instrumentation frameworks (Frida, Xposed, Cydia, Substrate), rejects traffic from flagged rooted/jailbroken devices, enforces 60-second sliding-window replay nonces, and verifies hardware keystore tokens.
          </div>
        </details>

        <details>
          <summary>Is reverse proxy inspection compliant with EU GDPR and California CCPA?</summary>
          <div class="faq-answer">
            Yes. Clean traffic passes through in-memory isolates with zero persistent logging. Threat telemetry is captured strictly under <strong>EU GDPR Recital 49 &amp; Art. 6(1)(f)</strong> and <strong>CCPA § 1798.145</strong> under Legitimate Interest for Network Security, bounded by an automated 30-day purge cap. Read our full <a href="/legal/dpa" style="color:#38bdf8;">Data Processing Addendum (DPA)</a>.
          </div>
        </details>

        <details>
          <summary>How are security alerts dispatched when an attack occurs?</summary>
          <div class="faq-answer">
            When a threat is intercepted, the Worker generates a background out-of-band dispatch to GitHub Actions via RS256 JWT authentication, triggering an instant incident email to your designated admin email with the attacker IP, network ASN, and payload forensic signature.
          </div>
        </details>
      </div>
    </section>

    <div class="footer-links">
      <a href="/manual">User Manual</a> • 
      <a href="/legal/dpa">Data Processing Addendum (DPA)</a> • 
      <a href="/faq">Storefront FAQ</a> • 
      <a href="/sitemap.xml">XML Sitemap</a> • 
      <a href="/llm.txt">/llm.txt Machine Spec</a> • 
      <a href="https://developers.seosiri.com/">SEOSiri Developer Portal</a> • 
      <a href="mailto:${MONETIZATION_CONFIG.supportDesk}">Corporate Support Desk</a>
      <p style="margin-top: 15px;">
        © 2026 SEOSiri Enterprise Labs. Designed by Lead Architect 
        <a href="https://www.seosiri.com/p/about.html" rel="nofollow noopener noreferrer" style="color: #38bdf8; text-decoration: underline;">Momenul Ahmad</a>.
      </p>
    </div>
  </div>

  <script>
    function copyPayoneer() {
      const email = document.getElementById("payoneer-addr").innerText;
      navigator.clipboard.writeText(email).then(() => {
        const btn = document.getElementById("copy-btn");
        btn.innerText = "Copied!";
        btn.style.background = "#059669";
        setTimeout(() => {
          btn.innerText = "Copy";
          btn.style.background = "#334155";
        }, 2000);
      });
    }
  </script>
</body>
</html>`;
}
