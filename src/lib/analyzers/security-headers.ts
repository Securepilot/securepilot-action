import { Rule, RuleMatch } from './types';

// ─── 1. Missing CSP header ───────────────────────────────────────────────────
const MISSING_CSP: Rule = {
  id: 'MISSING_CSP',
  title: 'Content-Security-Policy header not set',
  description: 'The absence of a Content-Security-Policy header leaves the application vulnerable to Cross-Site Scripting (XSS) and data injection attacks by allowing browsers to load resources from arbitrary origins. CSP is a critical defense-in-depth control that restricts which scripts, styles, and resources the browser may execute.',
  severity: 'MEDIUM',
  category: 'CONFIG',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    // Only flag Express/Next apps that don't set CSP
    const isWebApp = /express\(\)|app\.use\(|createServer|NextResponse|NextRequest/i.test(code);
    const hasHelmet = /helmet\s*\(\)|helmet\s*\(/i.test(code);
    const hasCSP = /(Content-Security-Policy|contentSecurityPolicy|csp)/i.test(code);

    if (!isWebApp || hasHelmet || hasCSP) return matches;

    lines.forEach((line, index) => {
      // Flag the app creation line
      if (/const\s+app\s*=\s*express\(\)|app\.listen/i.test(line)) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.65 });
      }
    });
    return matches;
  },
};

// ─── 2. Missing HSTS header ──────────────────────────────────────────────────
const MISSING_HSTS: Rule = {
  id: 'MISSING_HSTS',
  title: 'HTTP Strict-Transport-Security (HSTS) header not set',
  description: 'Without HSTS, browsers may complete the initial connection over plain HTTP before being redirected to HTTPS, creating a window for SSL stripping and man-in-the-middle attacks. HSTS instructs the browser to enforce HTTPS-only communication for a specified duration.',
  severity: 'MEDIUM',
  category: 'CONFIG',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const isWebApp = /express\(\)|app\.use\(|setHeader|res\.header/i.test(code);
    const hasHelmet = /helmet\s*\(\)|helmet\s*\(/i.test(code);
    const hasHSTS = /(Strict-Transport-Security|hsts|strictTransportSecurity)/i.test(code);

    if (!isWebApp || hasHelmet || hasHSTS) return matches;

    lines.forEach((line, index) => {
      if (/app\.listen|createServer/i.test(line)) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.60 });
      }
    });
    return matches;
  },
};

// ─── 3. Missing X-Frame-Options (Clickjacking) ───────────────────────────────
const MISSING_X_FRAME_OPTIONS: Rule = {
  id: 'MISSING_X_FRAME_OPTIONS',
  title: 'X-Frame-Options header missing — clickjacking risk',
  description: 'Missing X-Frame-Options or an equivalent frame-ancestors CSP directive allows attackers to embed the application in a hidden iframe and trick authenticated users into performing unintended actions (clickjacking). This can lead to unauthorized transactions, settings changes, or account takeover.',
  severity: 'MEDIUM',
  category: 'CONFIG',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const isWebApp = /express\(\)|app\.use\(|setHeader|res\.header/i.test(code);
    const hasHelmet = /helmet\s*\(\)|helmet\s*\(/i.test(code);
    const hasXFrame = /(X-Frame-Options|frameguard|frame-ancestors)/i.test(code);

    if (!isWebApp || hasHelmet || hasXFrame) return matches;

    lines.forEach((line, index) => {
      if (/app\.listen|createServer/i.test(line)) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.60 });
      }
    });
    return matches;
  },
};

// ─── 4. Referrer-Policy missing ──────────────────────────────────────────────
const MISSING_REFERRER_POLICY: Rule = {
  id: 'MISSING_REFERRER_POLICY',
  title: 'Referrer-Policy header not set — leaks sensitive URLs',
  description: 'Without a Referrer-Policy header, browsers send the full URL of the originating page in the Referer HTTP header to third-party destinations, potentially disclosing session tokens, user IDs, or other sensitive query parameters embedded in URLs.',
  severity: 'LOW',
  category: 'CONFIG',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const isWebApp = /express\(\)|app\.use\(/i.test(code);
    const hasHelmet = /helmet\s*\(\)|helmet\s*\(/i.test(code);
    const hasReferrer = /(Referrer-Policy|referrerPolicy)/i.test(code);

    if (!isWebApp || hasHelmet || hasReferrer) return matches;

    lines.forEach((line, index) => {
      if (/app\.listen/i.test(line)) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.55 });
      }
    });
    return matches;
  },
};

// ─── 5. Permissions-Policy missing ───────────────────────────────────────────
const MISSING_PERMISSIONS_POLICY: Rule = {
  id: 'MISSING_PERMISSIONS_POLICY',
  title: 'Permissions-Policy header missing — browser features unrestricted',
  description: 'The absence of a Permissions-Policy header leaves powerful browser features such as camera, microphone, geolocation, and payment APIs unrestricted for all frames and origins. Attackers exploiting XSS or malicious iframes can abuse these features without explicit user consent.',
  severity: 'LOW',
  category: 'CONFIG',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const isWebApp = /express\(\)|app\.use\(/i.test(code);
    const hasHelmet = /helmet\s*\(\)|helmet\s*\(/i.test(code);
    const hasPermissions = /(Permissions-Policy|permissionsPolicy|Feature-Policy)/i.test(code);

    if (!isWebApp || hasHelmet || hasPermissions) return matches;

    lines.forEach((line, index) => {
      if (/app\.listen/i.test(line)) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.50 });
      }
    });
    return matches;
  },
};

export const securityHeadersRules: Rule[] = [
  MISSING_CSP,
  MISSING_HSTS,
  MISSING_X_FRAME_OPTIONS,
  MISSING_REFERRER_POLICY,
  MISSING_PERMISSIONS_POLICY,
];
