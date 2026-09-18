// src/robots.ts - Canonical RFC 9309 robots.txt for guard.seosiri.com
export function getRobotsTxt(): string {
  return `# SEOSiri Cloud Defense & Threat Mitigation Shield (guard.seosiri.com)
# Primary Ecosystem Root: https://seosiri.com/
# Canonical Developer Portal: https://developers.seosiri.com/

User-agent: *
Allow: /

User-agent: GPTBot
Allow: /

User-agent: ClaudeBot
Allow: /

User-agent: PerplexityBot
Allow: /

# Canonical Sitemaps
Sitemap: https://guard.seosiri.com/sitemap.xml
Sitemap: https://developers.seosiri.com/sitemap.xml

# Machine-Readable Context Specifications
LLM-Text: https://guard.seosiri.com/llm.txt
LLM-Text: https://developers.seosiri.com/llm.txt
`;
}
