// src/index.ts - SEOSiri Cloud Defense Modular Edge Router
import { CLIENT_REGISTRY, MONETIZATION_CONFIG } from './config.js';
import { EnterpriseThreatEngine } from './firewall.js';
import { SubscriptionLifecycleManager } from './subscription.js';
import { ComplianceLegalShield } from './legal.js';
import { GoogleIdentityVerifier, GitHubAppService } from './auth.js';
import { getSitemapXml } from './sitemap.js';
import { getRobotsTxt } from './robots.js';
import { getLlmTxt } from './llm.js';
import { getManualHtml } from './manual.js';
import { getStorefrontHtml } from './storefront.js';

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

    // 1. Dedicated System & Crawler Endpoints (Zero Subscriptions Check - Always 200 OK)
    if (url.pathname === '/robots.txt') {
      return new Response(getRobotsTxt(), {
        status: 200,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
      });
    }

    if (url.pathname === '/sitemap.xml') {
      return new Response(getSitemapXml(), {
        status: 200,
        headers: { 'Content-Type': 'application/xml; charset=utf-8' }
      });
    }

    if (url.pathname === '/llm.txt') {
      return new Response(getLlmTxt(), {
        status: 200,
        headers: { 'Content-Type': 'text/plain; charset=utf-8' }
      });
    }

    if (url.pathname === '/manual') {
      return new Response(getManualHtml(), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

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

    // 3. Storefront / Home / FAQ Views
    if ((url.pathname === '/' || url.pathname === '' || url.pathname === '/faq') && (hostname === 'guard.seosiri.com' || hostname.includes('workers.dev'))) {
      const accept = request.headers.get('Accept') || '';
      if (accept.includes('application/json')) {
        return new Response(JSON.stringify({
          status: 'ONLINE',
          service: 'SEOSiri Cloud Defense & Edge WAF',
          gateway: 'guard.seosiri.com',
          version: '1.0.0'
        }), { status: 200, headers: { 'Content-Type': 'application/json' } });
      }
      return new Response(getStorefrontHtml(), {
        status: 200,
        headers: { 'Content-Type': 'text/html; charset=utf-8' }
      });
    }

    // 4. Match Domain in Client Registry
    const client = CLIENT_REGISTRY[hostname] || CLIENT_REGISTRY['guard.seosiri.com'];

    // 5. DDoS Rate Limiter Check per Client Plan
    const rateCheck = checkDdosRateLimit(clientIp, client.rateLimitPerMinute);
    if (!rateCheck.allowed) {
      return new Response(JSON.stringify({
        error: 'RATE_LIMIT_EXCEEDED',
        message: `Edge rate limit exceeded (${client.rateLimitPerMinute} RPM cap for ${client.tier} Tier). Retry in ${rateCheck.resetSeconds}s.`,
        clientDomain: client.clientDomain,
        renewalDesk: MONETIZATION_CONFIG.payoneerEmail
      }), {
        status: 429,
        headers: {
          'Content-Type': 'application/json',
          'Retry-After': String(rateCheck.resetSeconds),
          'X-RateLimit-Limit': String(client.rateLimitPerMinute),
          'X-RateLimit-Remaining': '0'
        }
      });
    }

    // 6. Threat Defense Matrix Inspection (SQLi, XSS, BOLA, CSRF, Mass Assignment, Mobile)
    const threat = await EnterpriseThreatEngine.inspectRequest(request);
    if (threat.isBlocked) {
      const auditLog = ComplianceLegalShield.createAuditRecord(
        threat.threatCategory || 'Unknown Threat',
        threat.details || '',
        clientIp,
        clientAsn,
        clientCountry
      );

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

    // 7. Automated Subscription Lifecycle Cutoff
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

    // 8. Proxy Clean Traffic to Upstream Origin Server
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

// Cache-Buster-Timestamp: 1789801405
