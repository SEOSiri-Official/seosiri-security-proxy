// src/storefront.ts - High-Converting Enterprise Storefront for guard.seosiri.com
import { MONETIZATION_CONFIG } from './config.js';

export function getStorefrontHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SEOSiri Cloud Defense | Enterprise Web &amp; Mobile App Security Shield</title>
  <meta name="description" content="Instant zero-code web and mobile API security shield. Protect your business from website downtime, database attacks, and bot scraping while ensuring GDPR and CCPA compliance.">
  <link rel="canonical" href="https://guard.seosiri.com/">

  <!-- Favicons for Users & Mobile Browsers -->
  <link rel="icon" type="image/svg+xml" href="https://developers.seosiri.com/favicon.svg">
  <link rel="icon" type="image/png" href="https://raw.githubusercontent.com/SEOSiri-Official/developers-seosiri-com/main/public/momenul-ahmad.png">
  <link rel="apple-touch-icon" href="https://developers.seosiri.com/favicon.svg">

  <!-- Open Graph & Social Cards -->
  <meta property="og:title" content="SEOSiri Cloud Defense &amp; Threat Mitigation Shield">
  <meta property="og:description" content="Zero-code enterprise security shield protecting your websites, mobile apps, and customer data with zero latency.">
  <meta property="og:image" content="https://raw.githubusercontent.com/SEOSiri-Official/developers-seosiri-com/main/public/momenul-ahmad.png">
  <meta property="og:url" content="https://guard.seosiri.com/">
  <meta property="og:type" content="website">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="SEOSiri Cloud Defense &amp; Mobile Security Shield">
  <meta name="twitter:description" content="Instant edge protection for Web and Mobile APIs with automated regulatory compliance.">
  <meta name="twitter:image" content="https://raw.githubusercontent.com/SEOSiri-Official/developers-seosiri-com/main/public/momenul-ahmad.png">

  <!-- AEO, GEO & Multi-Entity JSON-LD Schema -->
  <script type="application/ld+json">
  {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "SoftwareApplication",
        "@id": "https://guard.seosiri.com/#software",
        "name": "SEOSiri Cloud Defense & Security Shield",
        "applicationCategory": "SecurityApplication",
        "operatingSystem": "Cloudflare Global Edge Network",
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
            "name": "How does SEOSiri protect my website without requiring complex developer changes?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text": "You simply point your domain or API address to our edge shield via standard DNS. Our network filters out malicious automated traffic, hacker probes, and abuse before requests reach your servers, keeping your platform online without modifying your existing code."
            }
          },
          {
            "@type": "Question",
            "name": "How does this reduce our monthly cloud hosting bills and prevent downtime?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text": "Malicious scrapers and automated vulnerability scans waste significant server CPU, memory, and database bandwidth. By dropping unauthorized traffic at our global edge boundary, your origin servers only process legitimate, revenue-generating customer visits."
            }
          },
          {
            "@type": "Question",
            "name": "Will adding a security proxy slow down our website or mobile app?",
            "acceptedAnswer": {
              "@type": "Answer",
              "text": "No. All threat inspection runs in memory across hundreds of global edge data centers in under 10 milliseconds, ensuring your visitors experience fast page loads."
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
    .subtitle { font-size: 15px; color: #94a3b8; max-width: 720px; margin: 0 auto; }

    /* Value & Productivity Grid */
    .grid-2 { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin: 30px 0; }
    .feature-box { background: #1e293b; border: 1px solid #334155; border-radius: 16px; padding: 24px; text-align: left; }
    .feature-box h3 { margin-top: 0; font-size: 16px; color: #38bdf8; display: flex; align-items: center; gap: 8px; }
    .feature-box p { font-size: 13px; color: #cbd5e1; margin: 0; }

    /* Pricing Grid */
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

    /* Settlement Box */
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

    /* Clean FAQ Section */
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
    .footer-links a { color: #38bdf8; text-decoration: none; margin: 0 8px; }

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
        <li><a href="#benefits">Benefits</a></li>
        <li><a href="#mobile">Mobile Protection</a></li>
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
      <span class="badge">ZERO-CODE DEPLOYMENT • ENTERPRISE PEACE OF MIND</span>
      <h1>Autonomous Web &amp; Mobile Application Security Shield</h1>
      <p class="subtitle">Protect your platforms from downtime, data breaches, and server crashes. Works instantly with WordPress, Shopify, Next.js, and mobile APIs with zero code changes.</p>
    </div>

    <!-- High-Impact Business Benefits Grid (Productivity & Sales Intent) -->
    <div class="grid-2" id="benefits">
      <div class="feature-box">
        <h3>⚡ 5-Minute Setup &amp; Zero Developer Overhead</h3>
        <p>Connect your domain or API through standard DNS in 5 minutes. No complex software installations, code rewrites, or ongoing server maintenance required.</p>
      </div>
      <div class="feature-box">
        <h3>💰 Cut Cloud Hosting Bills &amp; Prevent Outages</h3>
        <p>Drop abusive bot traffic and automated vulnerability scanners at our global network edge before they consume your server CPU, memory, and database resources.</p>
      </div>
      <div class="feature-box" id="mobile">
        <h3>📱 Complete Mobile App &amp; API Integrity</h3>
        <p>Protect your iOS and Android mobile backends against fraudulent request replays, reverse engineering attempts, and unauthorized API exploitation.</p>
      </div>
      <div class="feature-box">
        <h3>⚖️ Lawsuit-Proof Enterprise Compliance</h3>
        <p>Instant coverage under EU GDPR Recital 49 and California CCPA security exemptions. Includes a ready-to-use Data Processing Addendum (DPA) to help you close B2B enterprise deals.</p>
      </div>
    </div>

    <!-- Pricing Grid with Direct Lead Generation CTAs -->
    <div class="pricing-grid" id="pricing">
      <div class="pricing-card">
        <div>
          <div class="plan-name">Starter Shield</div>
          <div class="price">$29 <span>/ month</span></div>
          <p style="font-size: 13px; color: #94a3b8;">Complete peace of mind for business websites, stores, and blogs.</p>
          <ul class="features">
            <li>1 Protected Domain or API</li>
            <li>Automated Attack &amp; Exploit Blocking</li>
            <li>Bot Flood &amp; Traffic Spike Protection</li>
            <li>Pre-Built GDPR &amp; CCPA Legal Shield</li>
            <li>Continuous 99.9% Uptime Guarantee</li>
          </ul>
        </div>
        <a href="https://developers.seosiri.com/#pricing" class="card-btn btn-starter">
          Deploy Starter Shield &rarr;
        </a>
      </div>

      <div class="pricing-card featured">
        <span class="popular-tag">RECOMMENDED FOR SAAS</span>
        <div>
          <div class="plan-name" style="color: #34d399;">Pro Defense</div>
          <div class="price">$99 <span>/ month</span></div>
          <p style="font-size: 13px; color: #94a3b8;">High-throughput protection for web apps, mobile APIs, and stores.</p>
          <ul class="features">
            <li>Up to 3 Domains &amp; Mobile Backends</li>
            <li>Advanced Mobile API &amp; Anti-Tamper Shield</li>
            <li>Database Manipulation &amp; Exploit Guard</li>
            <li>Instant Email Incident Notifications</li>
            <li>Priority Network Throughput</li>
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
          <p style="font-size: 13px; color: #94a3b8;">Tailored infrastructure defense with dedicated SLA guarantees.</p>
          <ul class="features">
            <li>Unlimited Web &amp; Mobile Endpoints</li>
            <li>Custom Domain Proxying (guard.yourdomain.com)</li>
            <li>Bespoke Security Rules &amp; Allowlisting</li>
            <li>Enterprise Compliance Verification Reports</li>
            <li>24/7 Dedicated Priority Technical Support</li>
          </ul>
        </div>
        <a href="https://developers.seosiri.com/#custom-mcp" class="card-btn btn-ent" title="Book Enterprise Consultation">
          Contact Enterprise Desk &rarr;
        </a>
      </div>
    </div>

    <!-- Direct Settlement Desk -->
    <div class="payoneer-box">
      <h3 style="margin-top:0; color:#ffffff; font-size:18px;">Direct Subscription Settlement Desk</h3>
      <p style="font-size:13px; color:#cbd5e1; margin-bottom:5px;">Activate edge protection for your business by submitting payment to our verified Payoneer account:</p>
      
      <div class="payoneer-email-container">
        <span class="payoneer-email" id="payoneer-addr">${MONETIZATION_CONFIG.payoneerEmail}</span>
        <button class="copy-btn" id="copy-btn" onclick="copyPayoneer()">Copy</button>
      </div>
      
      <p style="font-size:12px; color:#94a3b8; max-width:600px; margin: 10px auto;">
        Include your <strong>Domain Name</strong> and <strong>Notification Email</strong> in the payment notes. Your edge configuration activates within 15 minutes.
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

    <!-- Safe, Business-Focused FAQ (Zero Clues for Hackers) -->
    <section class="faq-section" id="faq">
      <div class="faq-header">
        <span class="badge">FREQUENTLY ASKED QUESTIONS</span>
        <h2 style="font-size:24px; color:#ffffff; margin:8px 0;">Frequently Asked Questions</h2>
        <p style="font-size:13px; color:#94a3b8;">Clear answers on how SEOSiri protects your business, team, and revenue.</p>
      </div>

      <div class="faq-grid">
        <details open>
          <summary>How does SEOSiri protect my website without requiring complex developer changes?</summary>
          <div class="faq-answer">
            You simply route your domain or API subdomain traffic through our edge proxy using standard DNS settings. We inspect incoming traffic, block malicious attacks, and forward clean customer requests directly to your servers with zero code modifications needed.
          </div>
        </details>

        <details>
          <summary>How does this reduce our monthly cloud hosting bills and prevent downtime?</summary>
          <div class="faq-answer">
            Malicious scrapers, brute-force bots, and automated vulnerability scanners waste significant server CPU, memory, and database bandwidth. By dropping bad traffic at our global edge boundary, your servers only spend resources processing legitimate, paying customer visits.
          </div>
        </details>

        <details>
          <summary>Will adding a security shield slow down our website or mobile app?</summary>
          <div class="faq-answer">
            No. Our proxy operates entirely in memory across hundreds of edge data centers worldwide. Inspection occurs in under 10 milliseconds, ensuring your visitors experience fast page loads.
          </div>
        </details>

        <details>
          <summary>How does SEOSiri protect iOS and Android mobile app backends?</summary>
          <div class="faq-answer">
            Mobile APIs are often targeted by automated scripts and reverse-engineering tools. SEOSiri verifies the integrity of mobile requests, prevents fraudulent transaction replays, and blocks unauthorized automated bots from abusing your backend data.
          </div>
        </details>

        <details>
          <summary>Is our data and customer traffic compliant with privacy regulations?</summary>
          <div class="faq-answer">
            Yes. All legitimate traffic passes through in-memory isolates without persistent logging. Threat metadata is captured strictly under <strong>EU GDPR Recital 49 &amp; Art. 6(1)(f)</strong> and <strong>CCPA § 1798.145</strong> to preserve network security with an automated 30-day purge cap. Read our full <a href="/legal/dpa" style="color:#38bdf8;">Data Processing Addendum (DPA)</a>.
          </div>
        </details>

        <details>
          <summary>How quickly can my website or mobile API be protected?</summary>
          <div class="faq-answer">
            Setup takes less than 5 minutes. As soon as you update your DNS or point your API endpoint to our edge proxy, active defense begins immediately.
          </div>
        </details>
      </div>
    </section>

    <!-- Clean Footer with Smooth Anchor Links & rel="nofollow" -->
    <div class="footer-links">
      <a href="/manual">User Manual</a> • 
      <a href="/legal/dpa">Data Processing Addendum (DPA)</a> • 
      <a href="#faq">Frequently Asked Questions</a> • 
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
