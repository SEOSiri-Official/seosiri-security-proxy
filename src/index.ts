import { CLIENT_REGISTRY } from './config.js';
import { EnterpriseThreatEngine } from './firewall.js';
import { SubscriptionLifecycleManager } from './subscription.js';
import { ComplianceLegalShield } from './legal.js';

export interface Env {
  GITHUB_ALERT_TOKEN?: string;
  ALERT_REPO?: string;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const clientIp = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
    const clientAsn = request.cf?.asn ? `ASN: ${request.cf.asn} (${request.cf.asOrganization || 'ISP'})` : 'Unknown Network';
    const clientCountry = typeof request.cf?.country === 'string' ? request.cf.country : 'GLOBAL';

    // 1. DPA Legal Document Route
    if (url.pathname === '/legal/dpa') {
      return new Response(ComplianceLegalShield.getDpaDocument(), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    // 2. Identify Client Subscription Profile via Hostname or Header
    const hostname = url.hostname;
    // Look up client by domain or fallback to demo client
    const client = CLIENT_REGISTRY[hostname] || CLIENT_REGISTRY['client-acme'];

    // 3. STAGE 1: Automated Subscription Lifecycle & Expiration Enforcement
    const subStatus = SubscriptionLifecycleManager.evaluateStatus(client);

    // HARD CUTOFF: If payment is lapsed/expired, stop routing to origin immediately!
    if (!subStatus.hasActiveSubscription) {
      return new Response(SubscriptionLifecycleManager.generateLapsedPage(client.clientDomain), {
        status: 402, // HTTP 402 Payment Required
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'X-SEOSiri-Subscription-Status': 'EXPIRED_HALTED',
          'Retry-After': '86400'
        }
      });
    }

    // 4. STAGE 2: Threat Defense Matrix Inspection (SQLi, XSS, BOLA, CSRF, Mass Assignment)
    const threat = await EnterpriseThreatEngine.inspectRequest(request);

    if (threat.isBlocked) {
      // Create Lawsuit-Proof Audit Record under GDPR Recital 49
      const auditLog = ComplianceLegalShield.createAuditRecord(
        threat.threatCategory || 'Unknown Threat',
        threat.details || '',
        clientIp,
        clientAsn,
        clientCountry
      );

      // Async GitOps Dispatch: Send Alert to GitHub Actions without latency penalty
      if (env.GITHUB_ALERT_TOKEN && env.ALERT_REPO) {
        ctx.waitUntil(
          fetch(`https://api.github.com/repos/${env.ALERT_REPO}/dispatches`, {
            method: 'POST',
            headers: {
              'Accept': 'application/vnd.github.v3+json',
              'Authorization': `Bearer ${env.GITHUB_ALERT_TOKEN}`,
              'User-Agent': 'SEOSiri-Threat-Shield'
            },
            body: JSON.stringify({
              event_type: 'security_incident',
              client_payload: {
                ...auditLog,
                clientDomain: client.clientDomain,
                alertRecipient: client.alertEmail
              }
            })
          })
        );
      }

      // Return 403 Security Intercept Response
      return new Response(JSON.stringify({
        error: 'ACCESS_DENIED_THREAT_INTERCEPTED',
        incident_id: auditLog.incidentId,
        threat: threat.threatCategory,
        timestamp: auditLog.timestamp,
        legal_notice: auditLog.legalBasis,
        message: 'Malicious exploit vector dropped at SEOSiri Edge Boundary.'
      }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 5. STAGE 3: Clean Traffic Reverse-Proxy Forwarding to Client Origin
    try {
      // Rewrite target URL to client's origin server
      const originUrl = new URL(url.pathname + url.search, client.originServerUrl);
      
      const proxyRequest = new Request(originUrl.toString(), {
        method: request.method,
        headers: request.headers,
        body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
        redirect: 'follow'
      });

      // Execute fetch to client origin
      const originResponse = await fetch(proxyRequest);
      const responseHeaders = new Headers(originResponse.headers);

      // Inject Mandatory Protective Headers (MitM HSTS, CSP, and Anti-Clickjacking)
      EnterpriseThreatEngine.applySecurityHeaders(responseHeaders);

      // If subscription is nearing expiration, inject proactive warning headers
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