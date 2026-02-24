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

// ─── 1. Server Component / getServerSideProps returning sensitive env vars ───
const NEXTJS_ENV_LEAK: Rule = {
  id: 'NEXTJS_ENV_LEAK',
  title: 'Server-side secret environment variable may leak to client',
  description: 'Returning non-NEXT_PUBLIC_ environment variables in server-rendered props or API responses causes secrets such as database credentials, API keys, and signing secrets to be serialized into the client-side JavaScript bundle or HTTP response. This exposes sensitive configuration to any user who inspects page source or network traffic.',
  severity: 'CRITICAL',
  category: 'SECRETS',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      // Detect non-NEXT_PUBLIC_ env vars being returned in props or passed to components
      const hasEnvVar = /process\.env\.(?!NEXT_PUBLIC_)([A-Z_]+)/g;
      const envMatches = [...line.matchAll(hasEnvVar)];
      if (envMatches.length === 0) return;

      // Check if this is inside a return / props context (client-visible)
      const ctx = lines.slice(Math.max(0, index - 5), Math.min(lines.length, index + 5)).join('\n');
      const isClientVisible = /(return\s*\{|props\s*:\s*\{|getServerSideProps|json\s*\(|NextResponse\.json|res\.json)/i.test(ctx);

      if (isClientVisible) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.72 });
      }
    });
    return matches;
  },
};

// ─── 2. Next.js middleware.ts not protecting auth routes ─────────────────────
const NEXTJS_NO_MIDDLEWARE_AUTH: Rule = {
  id: 'NEXTJS_NO_MIDDLEWARE_AUTH',
  title: 'Next.js app without auth middleware protecting routes',
  description: 'Next.js applications that serve authenticated data via getServerSideProps without verifying the session in middleware or within the function itself allow unauthenticated users to access protected pages and their associated data. Route-level authentication must be enforced server-side on every request.',
  severity: 'HIGH',
  category: 'AUTH',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    // Only relevant if this looks like a Next.js page/route with auth patterns
    const isNextPage = /(getServerSideProps|export default function|'use client')/i.test(code);
    const hasProtectedData = /(session|user|auth|token|profile|dashboard|account)/i.test(code);
    const hasMidlewareCheck = /(middleware|NextResponse\.redirect|getToken|getServerSession)/i.test(code);

    if (!isNextPage || !hasProtectedData || hasMidlewareCheck) return matches;

    lines.forEach((line, index) => {
      if (/export\s+(async\s+)?function\s+getServerSideProps/i.test(line)) {
        const ctx = lines.slice(index, Math.min(lines.length, index + 15)).join('\n');
        const hasAuthCheck = /(getServerSession|getToken|session\s*=|redirect.*login|req\.user)/i.test(ctx);
        if (!hasAuthCheck) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.65 });
        }
      }
    });
    return matches;
  },
};

// ─── 3. Server Action with no auth check ─────────────────────────────────────
const NEXTJS_SERVER_ACTION_NO_AUTH: Rule = {
  id: 'NEXTJS_SERVER_ACTION_NO_AUTH',
  title: 'Next.js Server Action without authentication check',
  description: 'Next.js Server Actions that perform database mutations without first verifying the caller\'s identity can be invoked directly via HTTP POST by any unauthenticated user. The server-side execution context does not inherently restrict access, making explicit authentication checks mandatory.',
  severity: 'HIGH',
  category: 'AUTH',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    let inServerAction = false;
    let actionStart = 0;

    lines.forEach((line, index) => {
      // Detect 'use server' directive (Server Actions)
      if (/'use server'|"use server"/i.test(line)) {
        inServerAction = true;
        actionStart = index;
      }

      if (inServerAction && /export\s+(async\s+)?function\s+\w+/i.test(line)) {
        // Check next 10 lines for auth
        const ctx = lines.slice(index, Math.min(lines.length, index + 10)).join('\n');
        const hasAuth = /(getServerSession|getToken|auth\(\)|currentUser|session\s*=|redirect.*login|unauthorized)/i.test(ctx);
        const hasMutation = /(prisma\.|db\.|await.*update|await.*create|await.*delete|await.*insert)/i.test(ctx);

        if (hasMutation && !hasAuth) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.72 });
        }
      }
    });
    return matches;
  },
};

// ─── 4. next/image with unvalidated external domain ──────────────────────────
const NEXTJS_UNSAFE_IMAGE_SRC: Rule = {
  id: 'NEXTJS_UNSAFE_IMAGE_SRC',
  title: 'Next.js Image with user-controlled src — SSRF/content injection risk',
  description: 'Passing user-controlled URLs to the Next.js Image component without validating against an allowlist of trusted domains can enable Server-Side Request Forgery (SSRF) or cause the application to proxy and render attacker-hosted images. This may bypass network controls and expose internal services.',
  severity: 'MEDIUM',
  category: 'SSRF',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      const hasNextImage = /<Image[^>]*src\s*=\s*\{/i.test(line);
      const hasUserInput = /(req\.|user\.|params\.|query\.|props\.|state\.|\.avatar|\.photo|\.image|\.url)/i.test(line);
      if (hasNextImage && hasUserInput) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.70 });
      }
    });
    return matches;
  },
};

export const nextjsSecurityRules: Rule[] = [
  NEXTJS_ENV_LEAK,
  NEXTJS_NO_MIDDLEWARE_AUTH,
  NEXTJS_SERVER_ACTION_NO_AUTH,
  NEXTJS_UNSAFE_IMAGE_SRC,
];
