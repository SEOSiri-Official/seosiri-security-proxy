export interface SecurityAuditRecord {
  incidentId: string;
  timestamp: string;
  threatType: string;
  sourceIp: string;
  networkAsn: string;
  country: string;
  forensicDetails: string;
  legalBasis: string;
  retentionCap: string;
}

export class ComplianceLegalShield {
  // Generates compliant forensic incident log
  public static createAuditRecord(threatType: string, details: string, ip: string, asn: string, country: string): SecurityAuditRecord {
    return {
      incidentId: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      threatType,
      sourceIp: ip,
      networkAsn: asn,
      country,
      forensicDetails: details,
      legalBasis: 'EU GDPR Article 6(1)(f), Recital 49 & CCPA Sec. 1798.145 Security Exception',
      retentionCap: 'STRICT_30_DAY_AUTO_PURGE'
    };
  }

  // Self-Hosted Data Processing Addendum (DPA) Clause
  public static getDpaDocument(): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SEOSiri Security Proxy Data Processing Addendum (DPA)</title>
  <style>body { font-family: sans-serif; line-height: 1.7; color: #1e293b; max-width: 800px; margin: 40px auto; padding: 20px; }</style>
</head>
<body>
  <h1>Data Processing Addendum (DPA) &amp; Security Exemption Notice</h1>
  <p><strong>Effective Date:</strong> August 2026</p>
  <p>This Addendum governs all reverse proxy routing, packet inspection, and WAF telemetry provided by SEOSiri Enterprise Labs.</p>
  <h2>1. Roles of the Parties</h2>
  <p>The Client acts as the <strong>Data Controller</strong>. SEOSiri acts strictly as a <strong>Data Processor</strong> providing automated network boundary defense.</p>
  <h2>2. Clean Traffic Non-Retention</h2>
  <p>Legitimate, unflagged HTTP requests pass through edge memory without persistent disk logging. IP addresses of non-malicious visitors are never retained.</p>
  <h2>3. Cybersecurity Exemption (GDPR &amp; CCPA)</h2>
  <p>In the event of an active threat signature (SQLi, XSS, BOLA, CSRF, DDoS), telemetry including source IP, network ASN, and payload fragments is logged under <em>EU GDPR Article 6(1)(f) and Recital 49 (Legitimate Interest for Network Security)</em> and <em>California Consumer Privacy Act (CCPA) § 1798.145(a)(1)</em>.</p>
  <h2>4. Data Minimization &amp; Auto-Purge</h2>
  <p>All security incident records are automatically purged after thirty (30) calendar days. Security telemetry is strictly prohibited from being sold, leased, or utilized for behavioral targeting.</p>
</body>
</html>`;
  }
}