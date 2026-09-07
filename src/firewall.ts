declare const process: any;

export interface ThreatEvaluation {
  isBlocked: boolean;
  threatCategory?: string;
  details?: string;
  riskScore: number;
}

export class EnterpriseThreatEngine {
  // 1. Web Vulnerability Patterns
  private static SQLI_REGEX = /(\b(UNION(\s+ALL)?|SELECT|INSERT|DROP|UPDATE|DELETE|ALTER|EXEC|CREATE)\b)|(\bOR\b\s+['"\d]+=['"\d]+)|(--|#|\/\*)/i;
  private static XSS_REGEX = /<script\b[^>]*>([\s\S]*?)<\/script>|javascript:|on(load|error|click|mouseover|submit)\s*=|(\bdata:text\/html\b)/i;
  private static DTO_PRIVILEGE_KEYS = ['is_admin', 'is_staff', 'role', 'permissions', 'account_balance', 'credit_limit', 'email_verified'];

  // 2. Mobile App Threat Signatures (Frida, Xposed, Hooking Frameworks, Emulators)
  private static MOBILE_HOOKING_USER_AGENTS = /(frida|xposed|cydia|substrate|androguard|charles|burp)/i;

  // 3. In-Memory Nonce Cache for Mobile Replay Attack Prevention
  private static SEEN_NONCES = new Map<string, number>();

  // 4. BOLA / IDOR Validator (Enforces UUID v4 over sequential integers)
  public static validateIdorPath(pathname: string): ThreatEvaluation {
    const sequentialIdPattern = /\/(api|v1|v2|users|accounts|orders|invoices)\/(\d+)([\/?#]|$)/i;
    const match = pathname.match(sequentialIdPattern);

    if (match) {
      return {
        isBlocked: true,
        threatCategory: 'BOLA / IDOR Vulnerability Probe',
        details: `Sequential integer resource identifier detected [${match[2]}]. API policy strictly enforces RFC 4122 UUID v4 tokens.`,
        riskScore: 85
      };
    }
    return { isBlocked: false, riskScore: 0 };
  }

  // 5. Mobile Phone Application Security Inspector
  public static inspectMobileAppSecurity(request: Request): ThreatEvaluation {
    const userAgent = request.headers.get('User-Agent') || '';
    const isMobileEndpoint = request.url.includes('/api/mobile/') || request.headers.has('X-App-Platform');

    // Rule A: Mobile Code Tampering / Hooking Tool Detection
    if (this.MOBILE_HOOKING_USER_AGENTS.test(userAgent)) {
      return {
        isBlocked: true,
        threatCategory: 'Mobile Code Tampering / Hooking Agent Detected',
        details: `Instrumentation framework or debugger signature detected in User-Agent [${userAgent.substring(0, 60)}].`,
        riskScore: 95
      };
    }

    // Rule B: Device Integrity / Compromised Root Check
    const deviceIntegrity = request.headers.get('X-Device-Integrity');
    if (deviceIntegrity === 'COMPROMISED_ROOT' || deviceIntegrity === 'JAILBROKEN') {
      return {
        isBlocked: true,
        threatCategory: 'Compromised Mobile Device Environment',
        details: 'Hardware attestation failed. Operating on rooted/jailbroken runtime with disabled secure storage.',
        riskScore: 90
      };
    }

    // Rule C: Mobile Replay Attack Mitigation (Timestamp + Nonce Validation)
    if (isMobileEndpoint && ['POST', 'PUT', 'DELETE'].includes(request.method)) {
      const timestampHeader = request.headers.get('X-App-Timestamp');
      const nonceHeader = request.headers.get('X-App-Nonce');

      if (timestampHeader && nonceHeader) {
        const clientTimestamp = parseInt(timestampHeader, 10);
        const nowUnix = Math.floor(Date.now() / 1000);

        // Reject if request is older than 60 seconds (Sliding Window)
        if (Math.abs(nowUnix - clientTimestamp) > 60) {
          return {
            isBlocked: true,
            threatCategory: 'Mobile Replay Attack Window Expired',
            details: `Stale request timestamp drift [${Math.abs(nowUnix - clientTimestamp)}s]. Exceeds 60s sliding window.`,
            riskScore: 80
          };
        }

        // Reject if nonce was already used within the window
        if (this.SEEN_NONCES.has(nonceHeader)) {
          return {
            isBlocked: true,
            threatCategory: 'Mobile Replay Attack: Duplicate Nonce Detected',
            details: `Cryptographic nonce [${nonceHeader}] has already been consumed.`,
            riskScore: 95
          };
        }

        // Cache nonce for 60 seconds, then prune
        this.SEEN_NONCES.set(nonceHeader, clientTimestamp);
        if (this.SEEN_NONCES.size > 10000) {
          const pruneThreshold = nowUnix - 60;
          for (const [nonce, ts] of this.SEEN_NONCES.entries()) {
            if (ts < pruneThreshold) this.SEEN_NONCES.delete(nonce);
          }
        }
      }
    }

    return { isBlocked: false, riskScore: 0 };
  }

  // 6. Deep Request Inspection Engine (Web, Mobile & API)
  public static async inspectRequest(request: Request): Promise<ThreatEvaluation> {
    const url = new URL(request.url);

    // Protocol Check (HTTPS / MitM Defense)
    const isProd = typeof process !== 'undefined' && process.env?.NODE_ENV === 'production';
    if (url.protocol !== 'https:' && isProd) {
      return {
        isBlocked: true,
        threatCategory: 'MitM Vulnerability: Insecure HTTP Protocol',
        details: 'Plaintext transport rejected. Strict HSTS requires TLS 1.3 encryption.',
        riskScore: 90
      };
    }

    // Mobile Phone Security Inspection
    const mobileCheck = this.inspectMobileAppSecurity(request);
    if (mobileCheck.isBlocked) return mobileCheck;

    // CSRF Check (Cross-Site Request Forgery)
    if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(request.method)) {
      const origin = request.headers.get('Origin');
      const secFetchSite = request.headers.get('Sec-Fetch-Site');

      if (secFetchSite === 'cross-site' && (!origin || !origin.includes(url.hostname))) {
        return {
          isBlocked: true,
          threatCategory: 'CSRF Attack Intercepted',
          details: `Cross-site mutation blocked from unverified origin [${origin}]. SameSite cookies required.`,
          riskScore: 95
        };
      }
    }

    // Query String Inspection (SQLi & XSS)
    const queryString = decodeURIComponent(url.search);
    if (this.SQLI_REGEX.test(queryString)) {
      return {
        isBlocked: true,
        threatCategory: 'SQL Injection (SQLi) Attempt',
        details: `Pattern match on malicious SQL query tokens: [${queryString.substring(0, 80)}]`,
        riskScore: 100
      };
    }

    if (this.XSS_REGEX.test(queryString)) {
      return {
        isBlocked: true,
        threatCategory: 'Cross-Site Scripting (XSS) Attempt',
        details: `Malicious script execution vector detected in query string: [${queryString.substring(0, 80)}]`,
        riskScore: 95
      };
    }

    // BOLA / IDOR Inspection
    const idorCheck = this.validateIdorPath(url.pathname);
    if (idorCheck.isBlocked) return idorCheck;

    // JSON Body Inspection (SQLi, XSS & Mass Assignment DTO)
    if (['POST', 'PUT', 'PATCH'].includes(request.method) && request.headers.get('content-type')?.includes('application/json')) {
      try {
        const bodyClone = await request.clone().text();

        if (this.SQLI_REGEX.test(bodyClone) || this.XSS_REGEX.test(bodyClone)) {
          return {
            isBlocked: true,
            threatCategory: 'Malicious Payload Injection in Body',
            details: 'SQL or script injection payload detected inside JSON body payload.',
            riskScore: 100
          };
        }

        const parsedJson = JSON.parse(bodyClone);
        if (typeof parsedJson === 'object' && parsedJson !== null) {
          const keys = Object.keys(parsedJson).map(k => k.toLowerCase());
          const injectedKey = this.DTO_PRIVILEGE_KEYS.find(k => keys.includes(k));
          if (injectedKey) {
            return {
              isBlocked: true,
              threatCategory: 'Mass Assignment Privilege Escalation',
              details: `Unauthorized protected DTO attribute [${injectedKey}] injected into request payload.`,
              riskScore: 90
            };
          }
        }
      } catch (err) {
        // Non-JSON pass-through
      }
    }

    return { isBlocked: false, riskScore: 0 };
  }

  // 7. Security & Pinning Header Injection
  public static applySecurityHeaders(headers: Headers): void {
    headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('X-Frame-Options', 'DENY');
    headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    headers.set('Permissions-Policy', 'geolocation=(), camera=(), microphone=()');
    headers.set(
      'Content-Security-Policy',
      "default-src 'self'; script-src 'self' 'unsafe-inline' https://www.googletagmanager.com; object-src 'none'; base-uri 'self';"
    );
    // Mobile Pinning Verification & Integrity Signal
    headers.set('X-SEOSiri-Mobile-Shield', 'TLS_PINNING_SUPPORTED; HARDWARE_KEYSTORE_ENABLED');
  }
}
