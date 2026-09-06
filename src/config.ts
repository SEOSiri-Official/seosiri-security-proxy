export interface ClientSubscription {
  clientId: string;
  clientDomain: string;
  originServerUrl: string; // The client's real backend (WordPress, AWS, Next.js)
  alertEmail: string;
  tier: 'STARTER' | 'PRO' | 'ENTERPRISE';
  activeSince: string;
  expiresAtUnix: number; // Unix timestamp in seconds
  isActive: boolean;
  rateLimitPerMinute: number;
}

export const MONETIZATION_CONFIG = {
  payoneerEmail: "badhan_pbn@yahoo.com",
  portalUrl: "https://developers.seosiri.com",
  renewalBaseUrl: "https://developers.seosiri.com/key-issuer",
  supportDesk: "info@seosiri.com"
};

// Client Profiles (Can be populated from KV, D1, or deterministic tokens)
export const CLIENT_REGISTRY: Record<string, ClientSubscription> = {
  "client-acme": {
    clientId: "client-acme",
    clientDomain: "acme-store.com",
    originServerUrl: "https://origin.acme-store.com",
    alertEmail: "security@acme-store.com",
    tier: "PRO",
    activeSince: "2026-08-01T00:00:00Z",
    // Active for 30 days from reference epoch
    expiresAtUnix: Math.floor(Date.now() / 1000) + (15 * 86400), // 15 Days Remaining
    isActive: true,
    rateLimitPerMinute: 1000
  },
  "client-lapsed-demo": {
    clientId: "client-lapsed-demo",
    clientDomain: "demo-lapsed.com",
    originServerUrl: "https://origin.demo-lapsed.com",
    alertEmail: "admin@demo-lapsed.com",
    tier: "STARTER",
    activeSince: "2026-07-01T00:00:00Z",
    expiresAtUnix: Math.floor(Date.now() / 1000) - 3600, // Expired 1 hour ago
    isActive: true,
    rateLimitPerMinute: 100
  }
};