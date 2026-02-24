import { Rule, RuleMatch } from './types';

function findMatches(regex: RegExp, code: string, lines: string[], confidence: number = 0.95): RuleMatch[] {
  const matches: RuleMatch[] = [];
  const globalRegex = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : regex.flags + 'g');

  lines.forEach((line, index) => {
    const lineMatches = line.matchAll(globalRegex);
    for (const match of lineMatches) {
      matches.push({
        line: index + 1,
        column: match.index,
        codeSnippet: line.trim(),
        confidence,
      });
    }
  });

  return matches;
}

const NO_AUTH_MIDDLEWARE: Rule = {
  id: 'NO_AUTH_MIDDLEWARE',
  cwe: 'CWE-306',
  owasp: 'A01:2021',
  title: 'API route without authentication check',
  description: 'This API route lacks an authentication middleware or guard, allowing unauthenticated callers to access protected resources. Missing authentication is one of the most critical access-control failures and can lead to full data exposure or unauthorized operations.',
  severity: 'HIGH',
  category: 'AUTH',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const authKeywords = ['auth', 'authenticate', 'isAuthenticated', 'protect', 'requireAuth', 'verifyToken', 'getServerSession', 'getToken'];

    lines.forEach((line, index) => {
      // Check for Express route definitions
      const isExpressRoute = /app\.(get|post|put|delete|patch)\s*\(/i.test(line);

      if (isExpressRoute) {
        // Check if this line or nearby lines have auth middleware
        const contextStart = Math.max(0, index - 2);
        const contextEnd = Math.min(lines.length, index + 3);
        const context = lines.slice(contextStart, contextEnd).join('\n');

        const hasAuth = authKeywords.some(keyword =>
          new RegExp(keyword, 'i').test(context)
        );

        if (!hasAuth) {
          matches.push({
            line: index + 1,
            column: 0,
            codeSnippet: line.trim(),
            confidence: 0.70,
          });
        }
      }
    });

    return matches;
  },
};

const JWT_WEAK_SECRET: Rule = {
  id: 'JWT_WEAK_SECRET',
  cwe: 'CWE-326',
  owasp: 'A07:2021',
  title: 'JWT signed with weak/short secret',
  description: 'A short or easily guessable secret is used to sign JSON Web Tokens, making them vulnerable to offline brute-force and dictionary attacks. An attacker who recovers the secret can forge arbitrary tokens and impersonate any user, including privileged accounts.',
  severity: 'CRITICAL',
  category: 'AUTH',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const jwtSignRegex = /jwt\.sign\s*\([^)]*,\s*['"]([^'"]{1,20})['"]/gi;

    lines.forEach((line, index) => {
      const lineMatches = line.matchAll(jwtSignRegex);
      for (const match of lineMatches) {
        const secretLength = match[1]?.length || 0;
        if (secretLength < 20) {
          matches.push({
            line: index + 1,
            column: match.index,
            codeSnippet: line.trim(),
            confidence: 0.95,
          });
        }
      }
    });

    return matches;
  },
};

const JWT_NO_EXPIRY: Rule = {
  id: 'JWT_NO_EXPIRY',
  cwe: 'CWE-613',
  owasp: 'A07:2021',
  title: 'JWT created without expiration',
  description: 'JWTs issued without an expiration claim (`exp`) remain valid indefinitely, so a stolen or leaked token can be replayed at any future time. Long-lived tokens significantly increase the window of opportunity for session hijacking and replay attacks.',
  severity: 'HIGH',
  category: 'AUTH',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      const hasJwtSign = /jwt\.sign\s*\(/i.test(line);

      if (hasJwtSign) {
        const hasExpiry = /(expiresIn|exp)/.test(line);

        if (!hasExpiry) {
          matches.push({
            line: index + 1,
            column: 0,
            codeSnippet: line.trim(),
            confidence: 0.85,
          });
        }
      }
    });

    return matches;
  },
};

const JWT_ALGO_NONE: Rule = {
  id: 'JWT_ALGO_NONE',
  cwe: 'CWE-347',
  owasp: 'A07:2021',
  title: 'JWT with algorithm "none"',
  description: 'Setting the JWT algorithm to `"none"` disables cryptographic signature verification entirely, allowing an attacker to craft or modify tokens without a secret. Any server that accepts unsigned tokens can be completely compromised through token forgery.',
  severity: 'CRITICAL',
  category: 'AUTH',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const regex = /algorithm:\s*['"]none['"]/gi;
    return findMatches(regex, code, lines, 0.99);
  },
};

const IDOR_PATTERN: Rule = {
  id: 'IDOR_PATTERN',
  cwe: 'CWE-639',
  owasp: 'A01:2021',
  title: 'Direct object reference from URL params',
  description: "User-supplied identifiers from URL parameters are used directly in database queries without verifying that the requesting user owns or is authorized to access the referenced object. This Insecure Direct Object Reference (IDOR) flaw enables horizontal privilege escalation, allowing one user to read or modify another user's data.",
  severity: 'MEDIUM',
  category: 'ACCESS_CONTROL',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      const hasParamUsage = /(params|query)\.(id|userId|user_id|accountId)/i.test(line);
      const hasDbQuery = /(find|findOne|findById|get|query|where)/i.test(line);

      if (hasParamUsage && hasDbQuery) {
        // Check if there's an ownership check nearby
        const contextStart = Math.max(0, index - 3);
        const contextEnd = Math.min(lines.length, index + 3);
        const context = lines.slice(contextStart, contextEnd).join('\n');

        const hasOwnershipCheck = /(userId\s*===|user\.id\s*===|owner|belongs)/i.test(context);

        if (!hasOwnershipCheck) {
          matches.push({
            line: index + 1,
            column: 0,
            codeSnippet: line.trim(),
            confidence: 0.65,
          });
        }
      }
    });

    return matches;
  },
};

const BCRYPT_LOW_ROUNDS: Rule = {
  id: 'BCRYPT_LOW_ROUNDS',
  cwe: 'CWE-916',
  owasp: 'A07:2021',
  title: 'bcrypt with low salt rounds',
  description: 'Using fewer than 10 bcrypt cost rounds produces hashes that can be cracked significantly faster with modern hardware. Insufficient work factor reduces the computational cost for attackers performing offline brute-force or dictionary attacks against a stolen password database.',
  severity: 'MEDIUM',
  category: 'AUTH',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const bcryptRegex = /bcrypt\.(hash|genSalt)\s*\([^,]*,\s*([0-9]+)\)/gi;

    lines.forEach((line, index) => {
      const lineMatches = line.matchAll(bcryptRegex);
      for (const match of lineMatches) {
        const rounds = parseInt(match[2] || '0', 10);
        if (rounds < 10) {
          matches.push({
            line: index + 1,
            column: match.index,
            codeSnippet: line.trim(),
            confidence: 0.90,
          });
        }
      }
    });

    return matches;
  },
};

const HARDCODED_ADMIN_CHECK: Rule = {
  id: 'HARDCODED_ADMIN_CHECK',
  title: 'Admin check using hardcoded values',
  description: 'Privilege decisions based on hardcoded role literals can be bypassed if an attacker can influence the compared value or if the logic is duplicated inconsistently across the codebase. Role checks should be enforced server-side using authoritative data retrieved from a trusted store, not literal comparisons.',
  severity: 'HIGH',
  category: 'AUTH',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const patterns = [
      /(isAdmin|role)\s*===?\s*['"]admin['"]/gi,
      /(isAdmin|role)\s*===?\s*true/gi,
    ];

    lines.forEach((line, index) => {
      patterns.forEach(pattern => {
        const lineMatches = line.matchAll(pattern);
        for (const match of lineMatches) {
          // Lower confidence if there's a DB lookup nearby
          const hasDbLookup = /(find|findOne|query|select)/i.test(line);
          const confidence = hasDbLookup ? 0.60 : 0.85;

          matches.push({
            line: index + 1,
            column: match.index,
            codeSnippet: line.trim(),
            confidence,
          });
        }
      });
    });

    return matches;
  },
};

const SESSION_NO_SECURE: Rule = {
  id: 'SESSION_NO_SECURE',
  title: 'Session cookie without secure flag',
  description: 'Session cookies configured without the `Secure` flag will be transmitted over unencrypted HTTP connections, exposing the session identifier to network interception. An attacker on the same network can capture the cookie and hijack the authenticated session.',
  severity: 'MEDIUM',
  category: 'AUTH',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      const hasSessionConfig = /session\s*\(|cookie\s*:\s*\{/i.test(line);

      if (hasSessionConfig) {
        // Check next few lines for secure flag
        const contextEnd = Math.min(lines.length, index + 5);
        const context = lines.slice(index, contextEnd).join('\n');

        const hasSecure = /secure:\s*true/i.test(context);

        if (!hasSecure) {
          matches.push({
            line: index + 1,
            column: 0,
            codeSnippet: line.trim(),
            confidence: 0.75,
          });
        }
      }
    });

    return matches;
  },
};

const PASSWORD_PLAIN_TEXT: Rule = {
  id: 'PASSWORD_PLAIN_TEXT',
  cwe: 'CWE-256',
  owasp: 'A07:2021',
  title: 'Storing password without hashing',
  description: "Storing passwords in plain text means a single database breach exposes every user's credentials immediately, with no computational barrier for the attacker. Passwords must be hashed using a purpose-built, slow hashing algorithm such as bcrypt, Argon2, or scrypt before persistence.",
  severity: 'CRITICAL',
  category: 'AUTH',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      const hasPasswordField = /password\s*[:=]/i.test(line);
      const hasDbOperation = /(insert|create|save|update|set)\s*\(/i.test(line);
      const hasReqBody = /req\.(body|params|query)/i.test(line);

      if (hasPasswordField && (hasDbOperation || hasReqBody)) {
        // Check if there's hashing nearby
        const contextStart = Math.max(0, index - 5);
        const contextEnd = Math.min(lines.length, index + 2);
        const context = lines.slice(contextStart, contextEnd).join('\n');

        const hasHashing = /(bcrypt|argon2|scrypt|hash|pbkdf2)/i.test(context);

        if (!hasHashing) {
          matches.push({
            line: index + 1,
            column: 0,
            codeSnippet: line.trim(),
            confidence: 0.80,
          });
        }
      }
    });

    return matches;
  },
};

// ─── Timing attack — string equality on secrets/tokens ───────────────────────
// Comparing tokens/secrets with === leaks timing info, enabling token forgery.
// Fix: use crypto.timingSafeEqual() for constant-time comparison.
const TIMING_ATTACK: Rule = {
  id: 'TIMING_ATTACK',
  cwe: 'CWE-208',
  owasp: 'A07:2021',
  title: 'Secret/token compared with === — timing attack risk, use crypto.timingSafeEqual()',
  description: 'Using the `===` operator to compare security-sensitive strings such as tokens, secrets, or HMACs is vulnerable to timing side-channel attacks, because the comparison short-circuits on the first differing byte. An attacker who can measure response times can iteratively infer the correct value; use `crypto.timingSafeEqual()` for constant-time comparison.',
  severity: 'HIGH',
  category: 'AUTH',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      if (!/===|==/.test(line)) return;

      // Must involve a security-sensitive variable name
      const hasSecretVar = /\b(token|secret|apiKey|api_key|apiSecret|password|passwd|signature|hmac|digest|hash|authToken|accessToken|sessionToken|csrfToken)\b/i.test(line);
      if (!hasSecretVar) return;

      // Must not already use constant-time comparison
      const hasSafeCompare = /(timingSafeEqual|safeCompare|constantTimeCompare|crypto\.timingSafe|scmp|compare\.equal)/i.test(line);
      if (hasSafeCompare) return;

      // Must compare with a variable (not just a type check like === 'string')
      const isMeaningfulCompare = /===\s*\w+|==\s*\w+/.test(line) && !/===\s*['"]undefined|===\s*null|===\s*typeof/.test(line);

      if (isMeaningfulCompare) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.82 });
      }
    });

    return matches;
  },
};

// ─── JWT signature verification disabled (Python PyJWT) ─────────────────────
const JWT_NO_VERIFY: Rule = {
  id: 'JWT_NO_VERIFY',
  cwe: 'CWE-347',
  owasp: 'A07:2021',
  title: 'JWT decoded without signature verification',
  description: 'Decoding a JWT with `verify_signature: False` or `options={"verify_signature": False}` skips cryptographic validation of the token\'s signature. This allows any attacker to craft arbitrary JWT payloads and pass authentication checks, because the server never confirms the token was signed with the expected secret.',
  severity: 'CRITICAL',
  category: 'AUTH',
  languages: ['python', 'javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const patterns = [
      /verify_signature['":\s]*False/gi,
      /options\s*=\s*\{\s*["']verify_signature["']\s*:\s*False/gi,
      /jwt\.decode\s*\([^)]*verify\s*=\s*False/gi,
      /decode\s*\([^)]*options.*verify_signature.*False/gi,
    ];
    lines.forEach((line, index) => {
      if (patterns.some(p => p.test(line))) {
        matches.push({ line: index + 1, codeSnippet: line.trim(), confidence: 0.99 });
      }
      // Reset lastIndex for global patterns
      patterns.forEach(p => { p.lastIndex = 0; });
    });
    return matches;
  },
};

export const authRules: Rule[] = [
  NO_AUTH_MIDDLEWARE,
  JWT_WEAK_SECRET,
  JWT_NO_EXPIRY,
  JWT_ALGO_NONE,
  JWT_NO_VERIFY,
  IDOR_PATTERN,
  BCRYPT_LOW_ROUNDS,
  HARDCODED_ADMIN_CHECK,
  SESSION_NO_SECURE,
  PASSWORD_PLAIN_TEXT,
  TIMING_ATTACK,
];
