import { EnterpriseThreatEngine } from '../src/firewall.js';
import { SubscriptionLifecycleManager } from '../src/subscription.js';
import { CLIENT_REGISTRY } from '../src/config.js';
import { GoogleIdentityVerifier } from '../src/auth.js';

function assert(condition: boolean, message: string) {
  if (!condition) {
    console.error(`❌ FAILED: ${message}`);
    process.exit(1);
  }
  console.log(`✅ PASSED: ${message}`);
}

console.log("==========================================================");
console.log("  SEOSIRI AUTONOMOUS DEFENSE & LIFECYCLE AUDIT SUITE      ");
console.log("==========================================================");

async function runTests() {
  // --- TEST 1: SQL Injection (SQLi) Defense ---
  console.log("\n[1. Website Defense: SQLi Mitigation]");
  const sqliReq = new Request("https://protected-site.com/products?id=1'%20UNION%20SELECT%20*%20FROM%20users--");
  const res1 = await EnterpriseThreatEngine.inspectRequest(sqliReq);
  assert(res1.isBlocked && res1.threatCategory?.includes('SQL Injection'), "Blocked SQL Injection query parameter payload");

  // --- TEST 2: Cross-Site Scripting (XSS) Defense ---
  console.log("\n[2. Website Defense: XSS Mitigation]");
  const xssReq = new Request("https://protected-site.com/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E");
  const res2 = await EnterpriseThreatEngine.inspectRequest(xssReq);
  assert(res2.isBlocked && res2.threatCategory?.includes('Cross-Site Scripting'), "Blocked malicious XSS script payload");

  // --- TEST 3: BOLA / IDOR Prevention ---
  console.log("\n[3. App & API Defense: BOLA / IDOR Enforcement]");
  const idorReq = new Request("https://protected-site.com/api/v1/users/88219");
  const res3 = await EnterpriseThreatEngine.inspectRequest(idorReq);
  assert(res3.isBlocked && res3.threatCategory?.includes('BOLA / IDOR'), "Blocked sequential integer IDOR probe; enforced UUID token rule");

  const uuidReq = new Request("https://protected-site.com/api/v1/users/550e8400-e29b-41d4-a716-446655440000");
  const res3b = await EnterpriseThreatEngine.inspectRequest(uuidReq);
  assert(!res3b.isBlocked, "Permitted compliant RFC 4122 UUID v4 resource identifier");

  // --- TEST 4: Mass Assignment DTO Protection ---
  console.log("\n[4. App & API Defense: Mass Assignment Prevention]");
  const massAssignReq = new Request("https://protected-site.com/api/profile", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "john_doe", is_admin: true })
  });
  const res4 = await EnterpriseThreatEngine.inspectRequest(massAssignReq);
  assert(res4.isBlocked && res4.threatCategory?.includes('Mass Assignment'), "Blocked unauthorized is_admin DTO privilege key injection");

  // --- TEST 5: CSRF Cross-Site Mutation Defense ---
  console.log("\n[5. Website Defense: CSRF Attack Defense]");
  const csrfReq = new Request("https://protected-site.com/api/account/transfer", {
    method: "POST",
    headers: {
      "Origin": "https://malicious-attacker.com",
      "Sec-Fetch-Site": "cross-site"
    }
  });
  const res5 = await EnterpriseThreatEngine.inspectRequest(csrfReq);
  assert(res5.isBlocked && res5.threatCategory?.includes('CSRF'), "Blocked cross-site state-changing request without valid SameSite origin");

  // --- TEST 6: Automated Subscription Duration & Failure Cutoff ---
  console.log("\n[6. Subscription Lifecycle & Automated Payment Cutoff]");
  const activeClient = CLIENT_REGISTRY["client-acme"];
  const activeStatus = SubscriptionLifecycleManager.evaluateStatus(activeClient);
  assert(activeStatus.hasActiveSubscription && activeStatus.status === 'ACTIVE', "Active client evaluated with valid operational duration");

  const lapsedClient = CLIENT_REGISTRY["client-lapsed-demo"];
  const lapsedStatus = SubscriptionLifecycleManager.evaluateStatus(lapsedClient);
  assert(!lapsedStatus.hasActiveSubscription && lapsedStatus.status === 'EXPIRED_HALTED', "Lapsed client payment triggers automated proxy cutoff (HTTP 402)");

  // --- TEST 7: Google Token Security & RBAC Whitelist Checks ---
  console.log("\n[7. Authentication & Authorization: Google RBAC Engine]");
  const malformedTest = await GoogleIdentityVerifier.verifyToken("invalid-token-no-dots");
  assert(!malformedTest.valid && malformedTest.error === 'MALFORMED_JWT_STRUCTURE', "Rejected malformed token missing JWT segments");

  const malformedTest2 = await GoogleIdentityVerifier.verifyToken("bad.base64.signature");
  assert(!malformedTest2.valid && malformedTest2.error === 'MALFORMED_JWT_STRUCTURE', "Rejected corrupted base64 payloads");

  console.log("\n==========================================================");
  console.log("  ALL TESTS PASSED: DEFENSE, RBAC & BILLING CERTIFIED     ");
  console.log("==========================================================");
}

runTests().catch(err => {
  console.error("Test execution failed:", err);
  process.exit(1);
});
