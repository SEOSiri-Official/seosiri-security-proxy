// src/config.ts - Enterprise Client Registry & Commercial Pricing Tiers

export interface ClientSubscription {
  clientId: string;
  clientDomain: string;
  originServerUrl: string;
  alertEmail: string;
  tier: 'STARTER' | 'PRO' | 'ENTERPRISE';
  activeSince: string;
  expiresAtUnix: number;
  isActive: boolean;
  rateLimitPerMinute: number;
}

export const MONETIZATION_CONFIG = {
  payoneerEmail: "badhan_pbn@yahoo.com",
  portalUrl: "https://developers.seosiri.com",
  supportDesk: "info@seosiri.com"
};

// 365 Days Active for Primary Gateways (Never accidentally trips 402)
const ACTIVE_ONE_YEAR = Math.floor(Date.now() / 1000) + (365 * 86400);

export const CLIENT_REGISTRY: Record<string, ClientSubscription> = {
  "client-lapsed-demo": {
    clientId: "client-lapsed-demo",
    clientDomain: "demo-lapsed.com",
    originServerUrl: "https://developers.seosiri.com",
    alertEmail: "admin@demo-lapsed.com",
    tier: "STARTER",
    activeSince: "2026-07-01T00:00:00Z",
    expiresAtUnix: Math.floor(Date.now() / 1000) - 3600,
    isActive: true,
    rateLimitPerMinute: 100
  },
  // Primary Gateway Profile
  "guard.seosiri.com": {
    clientId: "seosiri-core-gateway",
    clientDomain: "guard.seosiri.com",
    originServerUrl: "https://developers.seosiri.com",
    alertEmail: "info@seosiri.com",
    tier: "ENTERPRISE",
    activeSince: "2026-08-01T00:00:00Z",
    expiresAtUnix: ACTIVE_ONE_YEAR,
    isActive: true,
    rateLimitPerMinute: 5000
  },
  // Enterprise Demo Client
  "client-acme": {
    clientId: "client-acme",
    clientDomain: "acme-store.com",
    originServerUrl: "https://developers.seosiri.com",
    alertEmail: "security@acme-store.com",
    tier: "PRO",
    activeSince: "2026-08-01T00:00:00Z",
    expiresAtUnix: ACTIVE_ONE_YEAR,
    isActive: true,
    rateLimitPerMinute: 1000
  },
  // Simulated Lapsed Demo Account
  "demo-lapsed.com": {
    clientId: "client-lapsed-demo",
    clientDomain: "demo-lapsed.com",
    originServerUrl: "https://developers.seosiri.com",
    alertEmail: "admin@demo-lapsed.com",
    tier: "STARTER",
    activeSince: "2026-07-01T00:00:00Z",
    expiresAtUnix: Math.floor(Date.now() / 1000) - 3600, // Expired 1 hour ago
    isActive: true,
    rateLimitPerMinute: 100
  }
};
