// src/robots.ts - Dedicated robots.txt for guard.seosiri.com
export function getRobotsTxt(): string {
  return `User-agent: *
Allow: /

User-agent: GPTBot
Allow: /

User-agent: ClaudeBot
Allow: /

User-agent: PerplexityBot
Allow: /

Sitemap: https://guard.seosiri.com/sitemap.xml
LLM-Text: https://guard.seosiri.com/llm.txt
`;
}
