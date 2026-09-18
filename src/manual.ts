// src/manual.ts - Complete HTML User Manual for guard.seosiri.com/manual
export function getManualHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>User Manual &amp; Deployment Guide | SEOSiri Cloud Defense</title>
  <meta name="description" content="Deployment and setup manual for SEOSiri Cloud Defense reverse proxy, mobile WAF, and automated subscription lifecycle.">
  <link rel="canonical" href="https://guard.seosiri.com/manual">
  <style>
    body { background: #0f172a; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; padding: 40px 20px; line-height: 1.7; }
    .container { max-width: 880px; margin: 0 auto; background: #1e293b; border: 1px solid #334155; border-radius: 20px; padding: 36px; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }
    h1 { color: #38bdf8; font-size: 28px; margin-top: 0; }
    h2 { color: #ffffff; font-size: 18px; margin-top: 28px; border-bottom: 1px solid #334155; padding-bottom: 8px; }
    code { background: #0f172a; color: #34d399; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 13px; }
    pre { background: #0f172a; padding: 16px; border-radius: 10px; border: 1px solid #334155; overflow-x: auto; color: #38bdf8; font-size: 13px; font-family: monospace; }
    .step-box { background: #0f172a; border-left: 4px solid #0284c7; padding: 14px 18px; border-radius: 0 8px 8px 0; margin: 16px 0; }
    a { color: #38bdf8; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="container">
    <h1>📖 SEOSiri Cloud Defense User Manual &amp; Setup Guide</h1>
    <p>Complete deployment reference for engineering managers, DevOps leads, and application developers.</p>

    <h2>Method A: Zero-Code Reverse Proxy Setup (Recommended)</h2>
    <p>Protects WordPress, Shopify, Webflow, or custom web apps with zero code changes:</p>
    <div class="step-box">
      <strong>Step 1:</strong> In your domain DNS manager (Cloudflare, GoDaddy, Namecheap, Route53), add a CNAME record:<br>
      <code>CNAME api.yourdomain.com &rarr; guard.seosiri.com</code>
    </div>
    <div class="step-box">
      <strong>Step 2:</strong> Traffic is inspected at Cloudflare edge nodes for SQLi, XSS, BOLA, and CSRF before being forwarded to your origin server.
    </div>

    <h2>Method B: Mobile App API Security Integration (iOS &amp; Android)</h2>
    <p>To enable anti-replay and device integrity protection on mobile endpoints, include these HTTP headers:</p>
    <pre>POST /api/mobile/checkout HTTP/1.1
Host: guard.seosiri.com
X-App-Platform: iOS
X-App-Timestamp: 1788700000
X-App-Nonce: nonce_unique_random_9918
X-Device-Attestation: [SIGNED_HARDWARE_TOKEN]</pre>

    <h2>Automated Billing &amp; Subscription Cutoff</h2>
    <p>Subscriptions settle via Payoneer to <code>badhan_pbn@yahoo.com</code>. Pro accounts ($99/mo) receive a 7-day warning header <code>X-SEOSiri-Subscription-Warning</code> prior to expiration, preventing abrupt traffic cutoffs.</p>

    <p style="margin-top:30px; font-size:13px; color:#94a3b8;">
      &larr; <a href="https://guard.seosiri.com/">Return to Main Storefront</a> • <a href="https://developers.seosiri.com/">SEOSiri Developer Portal</a>
    </p>
  </div>
</body>
</html>`;
}
