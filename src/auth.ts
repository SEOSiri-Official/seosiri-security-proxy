// src/auth.ts - Production Google Identity & GitHub App Authentication Engine

export interface GoogleTokenPayload {
  iss: string;
  sub: string;
  email?: string;
  email_verified?: boolean;
  aud: string;
  exp: number;
}

export class GoogleIdentityVerifier {
  private static CERTS_CACHE: { keys: any[]; expiresAt: number } | null = null;

  // Fetches and caches Google's public RS256 keys (JWKS)
  private static async getGooglePublicKeys(): Promise<any[]> {
    const now = Date.now();
    if (this.CERTS_CACHE && this.CERTS_CACHE.expiresAt > now) {
      return this.CERTS_CACHE.keys;
    }

    const res = await fetch('https://www.googleapis.com/oauth2/v3/certs');
    const data = (await res.json()) as { keys: any[] };
    this.CERTS_CACHE = {
      keys: data.keys,
      expiresAt: now + 3600 * 1000 // Cache for 1 hour
    };
    return data.keys;
  }

  // Verifies Google OAuth2 ID / Identity Token at the Edge
  public static async verifyToken(idToken: string, expectedAudience?: string): Promise<{ valid: boolean; payload?: GoogleTokenPayload; error?: string }> {
    try {
      const parts = idToken.split('.');
      if (parts.length !== 3) {
        return { valid: false, error: 'MALFORMED_JWT_STRUCTURE' };
      }

      const header = JSON.parse(new TextDecoder().decode(this.base64UrlDecode(parts[0])));
      const payload = JSON.parse(new TextDecoder().decode(this.base64UrlDecode(parts[1]))) as GoogleTokenPayload;

      // Check Expiration
      const nowUnix = Math.floor(Date.now() / 1000);
      if (payload.exp < nowUnix) {
        return { valid: false, error: 'TOKEN_EXPIRED' };
      }

      // Check Issuer
      if (!['accounts.google.com', 'https://accounts.google.com'].includes(payload.iss)) {
        return { valid: false, error: 'INVALID_ISSUER' };
      }

      // Check Audience if supplied
      if (expectedAudience && payload.aud !== expectedAudience) {
        return { valid: false, error: 'AUDIENCE_MISMATCH' };
      }

      // Verify RS256 Cryptographic Signature via Web Crypto
      const keys = await this.getGooglePublicKeys();
      const matchedKey = keys.find((k: any) => k.kid === header.kid);
      if (!matchedKey) {
        return { valid: false, error: 'UNKNOWN_SIGNING_KEY' };
      }

      const cryptoKey = await crypto.subtle.importKey(
        'jwk',
        matchedKey,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
        false,
        ['verify']
      );

      const signedContent = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
      const signature = this.base64UrlDecode(parts[2]);

      const isValid = await crypto.subtle.verify(
        'RSASSA-PKCS1-v1_5',
        cryptoKey,
        signature,
        signedContent
      );

      if (!isValid) {
        return { valid: false, error: 'INVALID_SIGNATURE' };
      }

      return { valid: true, payload };
    } catch (err: any) {
      return { valid: false, error: err.message || 'VERIFICATION_EXCEPTION' };
    }
  }

  private static base64UrlDecode(input: string): Uint8Array {
    let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) {
      base64 += '=';
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
}

export class GitHubAppService {
  // Converts standard PEM PKCS#8 or PKCS#1 private key to CryptoKey
  private static async importPrivateKey(pem: string): Promise<CryptoKey> {
    const cleanPem = pem
      .replace(/-----BEGIN (RSA )?PRIVATE KEY-----/g, '')
      .replace(/-----END (RSA )?PRIVATE KEY-----/g, '')
      .replace(/\s+/g, '');

    const binary = atob(cleanPem);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }

    return await crypto.subtle.importKey(
      'pkcs8',
      bytes.buffer,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign']
    );
  }

  // Generates short-lived RS256 JWT for GitHub App Authentication (Valid for 10 min)
  public static async generateAppJwt(appId: string, privateKeyPem: string): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const header = { alg: 'RS256', typ: 'JWT' };
    const payload = {
      iat: now - 60, // Issued 60 seconds ago to account for clock drift
      exp: now + 600, // Valid for 10 minutes max
      iss: appId
    };

    const b64Header = this.base64UrlEncode(JSON.stringify(header));
    const b64Payload = this.base64UrlEncode(JSON.stringify(payload));
    const signingInput = `${b64Header}.${b64Payload}`;

    const key = await this.importPrivateKey(privateKeyPem);
    const signature = await crypto.subtle.sign(
      'RSASSA-PKCS1-v1_5',
      key,
      new TextEncoder().encode(signingInput)
    );

    const b64Signature = this.base64UrlEncode(new Uint8Array(signature));
    return `${signingInput}.${b64Signature}`;
  }

  // Requests an Ephemeral Installation Token (Auto-rotates hourly, zero manual PAT renewal)
  public static async getInstallationToken(appId: string, privateKeyPem: string, installationId: string): Promise<string> {
    const appJwt = await this.generateAppJwt(appId, privateKeyPem);

    const res = await fetch(`https://api.github.com/app/installations/${installationId}/access_tokens`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${appJwt}`,
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'SEOSiri-Security-Agent'
      }
    });

    const data = (await res.json()) as { token: string };
    return data.token;
  }

  // Dispatches incident alerts or opens automated issues
  public static async dispatchSecurityIncident(
    token: string,
    ownerRepo: string,
    incidentPayload: Record<string, any>
  ): Promise<boolean> {
    const res = await fetch(`https://api.github.com/repos/${ownerRepo}/dispatches`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github.v3+json',
        'User-Agent': 'SEOSiri-Security-Agent'
      },
      body: JSON.stringify({
        event_type: 'security_incident',
        client_payload: incidentPayload
      })
    });

    return res.status === 204;
  }

  private static base64UrlEncode(input: string | Uint8Array): string {
    let str = '';
    if (typeof input === 'string') {
      str = btoa(input);
    } else {
      let binary = '';
      for (let i = 0; i < input.byteLength; i++) {
        binary += String.fromCharCode(input[i]);
      }
      str = btoa(binary);
    }
    return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
}
