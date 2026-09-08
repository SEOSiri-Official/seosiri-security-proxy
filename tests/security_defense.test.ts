import { EnterpriseThreatEngine } from '../src/firewall.js';
import { SubscriptionLifecycleManager } from '../src/subscription.js';
import { ComplianceLegalShield } from '../src/legal.js';
import { GoogleIdentityVerifier } from '../src/auth.js';
import { CLIENT_REGISTRY } from '../src/config.js';

function assert(condition: boolean, message: string) {
  if (!condition) {
    console.error(`❌ FAILED: ${message}`);
    process.exit(1);
  }
  console.log(`✅ PASSED: ${message}`);
}

async function runMasterAudit() {
  console.log("================================================================================");
  console.log("  SEOSIRI ENTERPRISE DEFENSE & MOBILE APPLICATION SECURITY AUDIT SUITE (12/12)   ");
  console.log("================================================================================");

  // 1. SQLi Defense
  console.log("\n[1. Website Defense: SQLi Mitigation]");
  const sqliReq = new Request("https://protected-site.com/products?id=1'%20UNION%20SELECT%20*%20FROM%20users--");
  const sqliRes = await EnterpriseThreatEngine.inspectRequest(sqliReq);
  assert(sqliRes.isBlocked && sqliRes.threatCategory?.includes('SQL Injection'), "Blocked SQL Injection query parameter payload");

  // 2. XSS Defense
  console.log("\n[2. Website Defense: XSS Mitigation]");
  const xssReq = new Request("https://protected-site.com/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E");
  const xssRes = await EnterpriseThreatEngine.inspectRequest(xssReq);
  assert(xssRes.isBlocked && xssRes.threatCategory?.includes('Cross-Site Scripting'), "Blocked malicious XSS script payload");

  // 3. BOLA / IDOR Enforcement
  console.log("\n[3. App & API Defense: BOLA / IDOR Enforcement]");
  const idorReq = new Request("https://protected-site.com/api/v1/users/88219");
  const idorRes = await EnterpriseThreatEngine.inspectRequest(idorReq);
  assert(idorRes.isBlocked && idorRes.threatCategory?.includes('BOLA / IDOR'), "Blocked sequential integer IDOR probe; enforced UUID token rule");

  const uuidReq = new Request("https://protected-site.com/api/v1/users/550e8400-e29b-41d4-a716-446655440000");
  const uuidRes = await EnterpriseThreatEngine.inspectRequest(uuidReq);
  assert(!uuidRes.isBlocked, "Permitted compliant RFC 4122 UUID v4 resource identifier");

  // 4. Mass Assignment DTO Protection
  console.log("\n[4. App & API Defense: Mass Assignment Prevention]");
  const massAssignReq = new Request("https://protected-site.com/api/profile", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "john_doe", is_admin: true })
  });
  const massRes = await EnterpriseThreatEngine.inspectRequest(massAssignReq);
  assert(massRes.isBlocked && massRes.threatCategory?.includes('Mass Assignment'), "Blocked unauthorized is_admin DTO privilege key injection");

  // 5. CSRF Defense
  console.log("\n[5. Website Defense: CSRF Attack Defense]");
  const csrfReq = new Request("https://protected-site.com/api/account/transfer", {
    method: "POST",
    headers: { "Origin": "https://malicious-attacker.com", "Sec-Fetch-Site": "cross-site" }
  });
  const csrfRes = await EnterpriseThreatEngine.inspectRequest(csrfReq);
  assert(csrfRes.isBlocked && csrfRes.threatCategory?.includes('CSRF'), "Blocked cross-site state-changing request without valid SameSite origin");

  // 6. Subscription Lifecycle & Automated Payment Cutoff
  console.log("\n[6. Subscription Lifecycle & Automated Payment Cutoff]");
  const activeClient = CLIENT_REGISTRY["client-acme"] || CLIENT_REGISTRY["guard.seosiri.com"];
  const activeStatus = SubscriptionLifecycleManager.evaluateStatus(activeClient);
  assert(activeStatus.hasActiveSubscription && activeStatus.status === 'ACTIVE', "Active client evaluated with valid operational duration");

  const lapsedClient = CLIENT_REGISTRY["client-lapsed-demo"] || CLIENT_REGISTRY["demo-lapsed.com"];
  const lapsedStatus = SubscriptionLifecycleManager.evaluateStatus(lapsedClient);
  assert(!lapsedStatus.hasActiveSubscription && lapsedStatus.status === 'EXPIRED_HALTED', "Lapsed client payment triggers automated proxy cutoff (HTTP 402)");

  // 7. Mobile Code Tampering & Hooking Detection
  console.log("\n[7. Mobile Security: Hooking & Anti-Tamper Mitigation]");
  const fridaReq = new Request("https://protected-site.com/api/mobile/login", {
    headers: { "User-Agent": "Mozilla/5.0 (iPhone; Frida; Debugger)" }
  });
  const fridaRes = await EnterpriseThreatEngine.inspectRequest(fridaReq);
  assert(fridaRes.isBlocked && fridaRes.threatCategory?.includes('Mobile Code Tampering'), "Blocked mobile request with Frida hooking signature");

  const jailbreakReq = new Request("https://protected-site.com/api/mobile/pay", {
    headers: { "X-Device-Integrity": "JAILBROKEN" }
  });
  const jailbreakRes = await EnterpriseThreatEngine.inspectRequest(jailbreakReq);
  assert(jailbreakRes.isBlocked && jailbreakRes.threatCategory?.includes('Compromised Mobile Device'), "Blocked mobile request from jailbroken device");

  // 8. Mobile Replay Attack: Stale Timestamp Sliding Window
  console.log("\n[8. Mobile Security: Replay Attack Sliding Window]");
  const staleUnix = Math.floor(Date.now() / 1000) - 120;
  const staleReplayReq = new Request("https://protected-site.com/api/mobile/checkout", {
    method: "POST",
    headers: { "X-App-Platform": "iOS", "X-App-Timestamp": String(staleUnix), "X-App-Nonce": "nonce_stale_101" }
  });
  const staleRes = await EnterpriseThreatEngine.inspectRequest(staleReplayReq);
  assert(staleRes.isBlocked && staleRes.threatCategory?.includes('Replay Attack Window Expired'), "Blocked mobile request exceeding 60-second sliding timestamp window");

  // 9. Mobile Replay Attack: Duplicate Nonce Anti-Replay
  console.log("\n[9. Mobile Security: Duplicate Nonce Anti-Replay]");
  const nowUnix = Math.floor(Date.now() / 1000);
  const validNonce = "nonce_unique_tx_9981";

  const firstReq = new Request("https://protected-site.com/api/mobile/checkout", {
    method: "POST",
    headers: { "X-App-Platform": "Android", "X-App-Timestamp": String(nowUnix), "X-App-Nonce": validNonce }
  });
  const firstRes = await EnterpriseThreatEngine.inspectRequest(firstReq);
  assert(!firstRes.isBlocked, "Permitted first-time unique nonce on mobile API call");

  const replayReq = new Request("https://protected-site.com/api/mobile/checkout", {
    method: "POST",
    headers: { "X-App-Platform": "Android", "X-App-Timestamp": String(nowUnix), "X-App-Nonce": validNonce }
  });
  const replayRes = await EnterpriseThreatEngine.inspectRequest(replayReq);
  assert(replayRes.isBlocked && replayRes.threatCategory?.includes('Duplicate Nonce Detected'), "Blocked replayed mobile request reusing identical nonce");

  // 10. Security Headers & TLS Mobile Pinning Signal
  console.log("\n[10. Security Headers & TLS Mobile Pinning Verification]");
  const testHeaders = new Headers();
  EnterpriseThreatEngine.applySecurityHeaders(testHeaders);
  assert(testHeaders.has('Strict-Transport-Security'), "Verified HSTS preloaded header presence");
  assert(testHeaders.has('Content-Security-Policy'), "Verified strict CSP header injection");
  assert(testHeaders.get('X-SEOSiri-Mobile-Shield')?.includes('TLS_PINNING_SUPPORTED'), "Verified Mobile Pinning & Hardware Keystore signal header");

  // 11. Google Identity RS256 Token Parser Engine
  console.log("\n[11. Authentication: Google Token Validator Engine]");
  const invalidTokenRes = await GoogleIdentityVerifier.verifyToken("not.enough.segments");
  assert(!invalidTokenRes.valid, "Successfully rejected invalid Google JWT identity token");

  // 12. GDPR Recital 49 & CCPA Forensic Audit Record
  console.log("\n[12. Compliance: GDPR Recital 49 Forensic Record Generation]");
  const auditRecord = ComplianceLegalShield.createAuditRecord(
    "SQLi Attack",
    "UNION SELECT query dropped",
    "198.51.100.22",
    "ASN: 13335 (Cloudflare)",
    "US"
  );
  assert(auditRecord.legalBasis.includes("Recital 49"), "Generated legally compliant GDPR Recital 49 forensic record");
  assert(auditRecord.retentionCap === "STRICT_30_DAY_AUTO_PURGE", "Verified mandatory 30-day data minimization retention cap");

  console.log("\n================================================================================");
  console.log("  ALL 12/12 TESTS PASSED: WEB, MOBILE & LIFECYCLE DEFENSE 100% CERTIFIED        ");
  console.log("================================================================================");
}

runMasterAudit().catch(err => {
  console.error("Test execution failed:", err);
  process.exit(1);
});
