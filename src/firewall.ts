export interface ThreatEvaluation {
  isBlocked: boolean;
  threatCategory?: string;
  details?: string;
  riskScore: number; // 0 (Clean) to 100 (Critical)
}

export class EnterpriseThreatEngine {
  // 1. SQLi Patterns (Tautologies, UNION, Stored Procs, Comment Truncation)
  private static SQLI_REGEX = /(\b(UNION(\s+ALL)?|SELECT|INSERT|DROP|UPDATE|DELETE|ALTER|EXEC|CREATE)\b)|(\bOR\b\s+['"\d]+=['"\d]+)|(--|#|\/\*)/i;

  // 2. XSS Patterns (Script tags, event handlers, javascript: protocol, SVG payload vectors)
  private static XSS_REGEX = /<script\b[^>]*>([\s\S]*?)<\/script>|javascript:|on(load|error|click|mouseover|submit)\s*=|(\bdata:text\/html\b)/i;

  // 3. Mass Assignment Patterns (Interception of un-whitelisted DTO keys)
  private static DTO_PRIVILEGE_KEYS = ['is_admin', 'is_staff', 'role', 'permissions', 'account_balance', 'credit_limit', 'email_verified'];

  // 4. BOLA / IDOR Validator (Flags sequential integers; enforces secure UUIDs)
  public static validateIdorPath(pathname: string): ThreatEvaluation {
    // Detects REST patterns like /api/v1/users/123 or /orders/45678 (Insecure Direct Object References)
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

  // 5. Deep Request Inspection Engine
  public static async inspectRequest(request: Request): Promise<ThreatEvaluation> {
    const url = new URL(request.url);

    // Rule A: MitM & Protocol Security Enforcement (Enforce HTTPS)
    if (url.protocol !== 'https:' && typeof process !== 'undefined' && process.env?.NODE_ENV === 'production') {
      return {
        isBlocked: true,
        threatCategory: 'MitM Vulnerability: Insecure HTTP Protocol',
        details: 'Plaintext transport rejected. HSTS requires TLS 1.3 encryption.',
        riskScore: 90
      };
    }

    // Rule B: Cross-Site Request Forgery (CSRF) for State-Mutating Methods
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

    // Rule C: URL Query String Inspection (SQLi & XSS)
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

    // Rule D: BOLA / IDOR Inspection
    const idorCheck = this.validateIdorPath(url.pathname);
    if (idorCheck.isBlocked) return idorCheck;

    // Rule E: JSON Body Inspection (Mass Assignment & Code Tampering)
    if (['POST', 'PUT', 'PATCH'].includes(request.method) && request.headers.get('content-type')?.includes('application/json')) {
      try {
        const bodyClone = await request.clone().text();
        
        // Check for SQLi / XSS in Body
        if (this.SQLI_REGEX.test(bodyClone) || this.XSS_REGEX.test(bodyClone)) {
          return {
            isBlocked: true,
            threatCategory: 'Malicious Payload Injection in Body',
            details: 'SQL or script injection payload detected inside JSON body payload.',
            riskScore: 100
          };
        }

        // Check for Mass Assignment (Privilege Escalation DTO injection)
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
        // Non-JSON or malformed payload pass-through
      }
    }

    return { isBlocked: false, riskScore: 0 };
  }

  // 6. Security Header Injection (MitM, XSS, and Clickjacking Defense)
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
  }
}