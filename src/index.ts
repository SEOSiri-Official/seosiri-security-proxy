import { CLIENT_REGISTRY } from './config.js';
import { EnterpriseThreatEngine } from './firewall.js';
import { SubscriptionLifecycleManager } from './subscription.js';
import { ComplianceLegalShield } from './legal.js';
import { GoogleIdentityVerifier, GitHubAppService } from './auth.js';

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
    const clientIp = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
    const clientAsn = request.cf?.asn ? `ASN: ${request.cf.asn} (${request.cf.asOrganization || 'ISP'})` : 'Unknown Network';
    const clientCountry = typeof request.cf?.country === 'string' ? request.cf.country : 'GLOBAL';

    // 1. Legal DPA Route
    if (url.pathname === '/legal/dpa') {
      return new Response(ComplianceLegalShield.getDpaDocument(), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    // 2. Google OAuth2 Token Verification Endpoint (For Client Portal Login)
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

      return new Response(JSON.stringify({
        status: 'AUTHENTICATED',
        user: verification.payload?.email,
        sub: verification.payload?.sub
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // 3. Match Target Client by Domain
    const hostname = url.hostname;
    const client = CLIENT_REGISTRY[hostname] || CLIENT_REGISTRY['client-acme'];

    // 4. Subscription Lifecycle Evaluation (Automated Cutoff)
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

    // 5. Threat Defense Matrix (SQLi, XSS, BOLA, CSRF, Mass Assignment)
    const threat = await EnterpriseThreatEngine.inspectRequest(request);

    if (threat.isBlocked) {
      const auditLog = ComplianceLegalShield.createAuditRecord(
        threat.threatCategory || 'Unknown Threat',
        threat.details || '',
        clientIp,
        clientAsn,
        clientCountry
      );

      // Automated Production GitHub Dispatch via App Access Token
      if (env.GITHUB_APP_ID && env.GITHUB_APP_PRIVATE_KEY && env.GITHUB_INSTALLATION_ID && env.ALERT_REPO) {
        ctx.waitUntil((async () => {
          try {
            const token = await GitHubAppService.getInstallationToken(
              env.GITHUB_APP_ID!,
              env.GITHUB_APP_PRIVATE_KEY!,
              env.GITHUB_INSTALLATION_ID!
            );
            await GitHubAppService.dispatchSecurityIncident(token, env.ALERT_REPO!, {
              ...auditLog,
              clientDomain: client.clientDomain,
              alertRecipient: client.alertEmail
            });
          } catch (err) {
            console.error('GitHub App Dispatch Error:', err);
          }
        })());
      }

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

    // 6. Forward Clean Request to Upstream Origin Server
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
        message: 'Unable to establish secure connection with upstream origin server.'
      }), {
        status: 502,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
};
