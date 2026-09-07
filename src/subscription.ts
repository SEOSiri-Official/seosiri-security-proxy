import { ClientSubscription, MONETIZATION_CONFIG } from './config.js';

export interface SubscriptionStatus {
  hasActiveSubscription: boolean;
  status: 'ACTIVE' | 'WARNING_EXPIRING_SOON' | 'EXPIRED_HALTED';
  daysRemaining: number;
  message: string;
}

export class SubscriptionLifecycleManager {
  // 1. Evaluates live subscription duration and enforces automated cutoff
  public static evaluateStatus(subscription?: ClientSubscription): SubscriptionStatus {
    if (!subscription) {
      return {
        hasActiveSubscription: false,
        status: "EXPIRED_HALTED",
        daysRemaining: 0,
        message: "No active subscription profile found. Access halted."
      };
    }
    const nowUnix = Math.floor(Date.now() / 1000);
    const secondsRemaining = subscription.expiresAtUnix - nowUnix;
    const daysRemaining = Math.ceil(secondsRemaining / 86400);

    // FAILURE STATE: Payment Lapsed / Duration Expired -> Hard Cutoff
    if (secondsRemaining <= 0 || !subscription.isActive) {
      return {
        hasActiveSubscription: false,
        status: 'EXPIRED_HALTED',
        daysRemaining: 0,
        message: `Subscription for ${subscription.clientDomain} has expired. Proxy routing halted. Contact ${MONETIZATION_CONFIG.payoneerEmail} to renew.`
      };
    }

    // WARNING STATE: Active, but expiring within 7 days
    if (daysRemaining <= 7) {
      return {
        hasActiveSubscription: true,
        status: 'WARNING_EXPIRING_SOON',
        daysRemaining,
        message: `Notice: Subscription for ${subscription.clientDomain} expires in ${daysRemaining} day(s). Renew to avoid traffic interruption.`
      };
    }

    // HEALTHY STATE
    return {
      hasActiveSubscription: true,
      status: 'ACTIVE',
      daysRemaining,
      message: `Active ${subscription.tier} License. Valid for ${daysRemaining} days.`
    };
  }

  // 2. Returns HTML for Lapsed Subscription (Shown to visitors if client bill fails)
  public static generateLapsedPage(domain: string): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Security Gateway Suspended | SEOSiri Enterprise</title>
  <style>
    body { background: #0f172a; color: #f8fafc; font-family: -apple-system, sans-serif; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
    .card { background: #1e293b; border: 1px solid #334155; padding: 40px; border-radius: 16px; max-width: 500px; text-align: center; box-shadow: 0 20px 25px -5px rgba(0,0,0,0.5); }
    h1 { color: #f43f5e; font-size: 24px; margin-top: 0; }
    p { font-size: 14px; line-height: 1.6; color: #cbd5e1; }
    .email-box { background: #0f172a; border: 1px solid #475569; padding: 12px; border-radius: 8px; font-family: monospace; color: #38bdf8; margin: 20px 0; word-break: break-all; }
    .btn { display: inline-block; background: #0284c7; color: white; text-decoration: none; padding: 12px 24px; border-radius: 8px; font-weight: bold; font-size: 13px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>⚠️ Protection Suspended</h1>
    <p>The SEOSiri Active Security Proxy for <strong>${domain}</strong> has expired due to lapsed subscription payment.</p>
    <p>To restore active edge defense and resume traffic routing, submit subscription renewal via Payoneer:</p>
    <div class="email-box">Payoneer Desk: ${MONETIZATION_CONFIG.payoneerEmail}</div>
    <a href="${MONETIZATION_CONFIG.portalUrl}" class="btn">SEOSiri Developer Portal &rarr;</a>
  </div>
</body>
</html>`;
  }
}