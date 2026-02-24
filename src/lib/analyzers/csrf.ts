import { Rule, RuleMatch } from './types';

function findMatches(regex: RegExp, code: string, lines: string[], confidence: number = 0.90): RuleMatch[] {
  const matches: RuleMatch[] = [];
  const globalRegex = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : regex.flags + 'g');
  lines.forEach((line, index) => {
    for (const match of line.matchAll(globalRegex)) {
      matches.push({ line: index + 1, column: match.index, codeSnippet: line.trim(), confidence });
    }
  });
  return matches;
}

// ─── 1. Express POST/PUT/DELETE route with no CSRF middleware ────────────────
const CSRF_NO_MIDDLEWARE: Rule = {
  id: 'CSRF_NO_MIDDLEWARE',
  title: 'State-changing route missing CSRF protection',
  description: 'Cross-Site Request Forgery allows an attacker to trick an authenticated user into unknowingly submitting state-changing requests; without CSRF middleware, every POST/PUT/PATCH/DELETE route is vulnerable to forged requests from any origin.',
  severity: 'HIGH',
  category: 'AUTH',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    // Only flag if there's NO csrf/csurf/edge-csrf in the whole file
    const hasCsrf = /(csrf|csurf|edge-csrf|@edge-csrf|doubleCsrf|csrfSync|verifyCsrf)/i.test(code);
    if (hasCsrf) return matches;

    lines.forEach((line, index) => {
      const isStateRoute = /app\.(post|put|patch|delete)\s*\(/i.test(line);
      if (isStateRoute) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.70 });
      }
    });
    return matches;
  },
};

// ─── 2. Cookie set without SameSite attribute ────────────────────────────────
const CSRF_COOKIE_NO_SAMESITE: Rule = {
  id: 'CSRF_COOKIE_NO_SAMESITE',
  title: 'Cookie set without SameSite attribute (CSRF risk)',
  description: 'Session cookies without the SameSite attribute are automatically included in cross-site requests, enabling CSRF attacks where a malicious page silently performs authenticated actions on behalf of the victim.',
  severity: 'MEDIUM',
  category: 'AUTH',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      const hasCookieSet = /res\.cookie\s*\(|Set-Cookie|cookie\s*:\s*\{/i.test(line);
      if (hasCookieSet) {
        // Look for sameSite in the next 5 lines
        const ctx = lines.slice(index, Math.min(lines.length, index + 6)).join('\n');
        const hasSameSite = /sameSite|SameSite/i.test(ctx);
        if (!hasSameSite) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.75 });
        }
      }
    });
    return matches;
  },
};

// ─── 3. Form submission without CSRF token field ─────────────────────────────
const CSRF_FORM_NO_TOKEN: Rule = {
  id: 'CSRF_FORM_NO_TOKEN',
  title: 'HTML form without CSRF token hidden field',
  description: 'HTML forms that submit to state-changing endpoints without an unpredictable CSRF token can be replayed from attacker-controlled pages, allowing unauthorized actions to be performed in the context of an authenticated session.',
  severity: 'HIGH',
  category: 'AUTH',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      const hasForm = /<form[^>]*(method\s*=\s*['"]post['"]|action\s*=)/i.test(line);
      if (hasForm) {
        // Check next 15 lines for csrf token input
        const ctx = lines.slice(index, Math.min(lines.length, index + 15)).join('\n');
        const hasToken = /(csrf|_token|authenticity_token)\s*['"]?\s*:/i.test(ctx) ||
          /type\s*=\s*['"]hidden['"][^>]*(csrf|_token)/i.test(ctx) ||
          /name\s*=\s*['"](_csrf|csrf_token|authenticity_token)['"]/i.test(ctx);
        if (!hasToken) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.65 });
        }
      }
    });
    return matches;
  },
};

// ─── 4. fetch/axios POST without CSRF token header ───────────────────────────
const CSRF_FETCH_NO_TOKEN: Rule = {
  id: 'CSRF_FETCH_NO_TOKEN',
  title: 'State-changing fetch/axios call missing CSRF token header',
  description: 'Fetch or Axios calls that mutate server state without sending a CSRF token header are vulnerable to cross-site request forgery, as browsers will automatically attach cookies to cross-origin requests even without the token.',
  severity: 'MEDIUM',
  category: 'AUTH',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    // Only flag if file has NO csrf token usage at all
    const hasCsrfToken = /(csrf|csrfToken|x-csrf-token|X-CSRF-Token)/i.test(code);
    if (hasCsrfToken) return matches;

    lines.forEach((line, index) => {
      const hasFetch = /fetch\s*\([^)]*,\s*\{|axios\.(post|put|patch|delete)\s*\(/i.test(line);
      const isStateChange = /(method\s*:\s*['"](?:POST|PUT|PATCH|DELETE)['"]|axios\.(post|put|patch|delete))/i.test(line);
      if (hasFetch && isStateChange) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.60 });
      }
    });
    return matches;
  },
};

// ─── 5. Next.js API route with no origin/referer check ───────────────────────
const CSRF_NEXTJS_NO_ORIGIN_CHECK: Rule = {
  id: 'CSRF_NEXTJS_NO_ORIGIN_CHECK',
  title: 'Next.js API route accepts cross-origin POST without origin check',
  description: 'Next.js API route handlers that accept POST or mutation requests without validating the Origin or Referer header have no defence against CSRF attacks originating from attacker-controlled domains.',
  severity: 'MEDIUM',
  category: 'AUTH',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const isNextApiRoute = /export\s+(async\s+)?function\s+(handler|POST|PUT|PATCH|DELETE)/i.test(code) ||
      /export\s+default\s+(async\s+)?function/i.test(code);
    const hasCsrfProtection = /(csrf|origin|referer|x-csrf|samesite)/i.test(code);

    if (!isNextApiRoute || hasCsrfProtection) return matches;

    lines.forEach((line, index) => {
      const isHandler = /export\s+(async\s+)?function\s+(POST|PUT|PATCH|DELETE|handler)/i.test(line);
      if (isHandler) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.60 });
      }
    });
    return matches;
  },
};

export const csrfRules: Rule[] = [
  CSRF_NO_MIDDLEWARE,
  CSRF_COOKIE_NO_SAMESITE,
  CSRF_FORM_NO_TOKEN,
  CSRF_FETCH_NO_TOKEN,
  CSRF_NEXTJS_NO_ORIGIN_CHECK,
];
