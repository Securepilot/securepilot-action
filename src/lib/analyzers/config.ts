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

const CORS_WILDCARD: Rule = {
  id: 'CORS_WILDCARD',
  title: 'CORS allows all origins',
  description: "A wildcard CORS policy (Access-Control-Allow-Origin: *) permits any origin to read responses from your API, eliminating the browser's same-origin protection. Attackers can exploit this to exfiltrate sensitive data from authenticated endpoints via cross-site JavaScript.",
  severity: 'HIGH',
  category: 'CONFIG',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const patterns = [
      /cors\s*\(\s*\)/gi,  // No config = defaults to *
      /origin:\s*['"]?\*['"]?/gi,
      /Access-Control-Allow-Origin['"]\s*:\s*['"]\*/gi,
    ];

    lines.forEach((line, index) => {
      patterns.forEach(pattern => {
        const lineMatches = line.matchAll(pattern);
        for (const match of lineMatches) {
          matches.push({
            line: index + 1,
            column: match.index,
            codeSnippet: line.trim(),
            confidence: 0.90,
          });
        }
      });
    });

    return matches;
  },
};

const DEBUG_MODE_ON: Rule = {
  id: 'DEBUG_MODE_ON',
  title: 'Debug mode enabled',
  description: 'Running an application with debug mode enabled exposes verbose stack traces, internal configuration, and diagnostic endpoints that reveal sensitive implementation details to potential attackers. This significantly lowers the effort required to identify and exploit other vulnerabilities in the system.',
  severity: 'HIGH',
  category: 'CONFIG',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const patterns = [
      /DEBUG\s*=\s*True/gi,  // Python
      /debug:\s*true/gi,      // Node
      /app\.debug\s*=\s*True/gi,  // Flask
    ];

    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      patterns.forEach(pattern => {
        const lineMatches = line.matchAll(pattern);
        for (const match of lineMatches) {
          matches.push({
            line: index + 1,
            column: match.index,
            codeSnippet: line.trim(),
            confidence: 0.85,
          });
        }
      });
    });

    return matches;
  },
};

const HTTPS_DISABLED: Rule = {
  id: 'HTTPS_DISABLED',
  title: 'No HTTPS enforcement',
  description: 'Transmitting data over unencrypted HTTP exposes all traffic to interception by on-path attackers, enabling credential theft, session hijacking, and data tampering. Production services must enforce TLS to ensure confidentiality and integrity of communications.',
  severity: 'MEDIUM',
  category: 'CONFIG',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      // Look for http:// in production-looking URLs
      if (/http:\/\/(?!localhost|127\.0\.0\.1)/gi.test(line)) {
        const isProdUrl = /(api|prod|production|\.com|\.io|\.net)/i.test(line);
        if (isProdUrl) {
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

const DEFAULT_DB_CREDS: Rule = {
  id: 'DEFAULT_DB_CREDS',
  title: 'Default database credentials',
  description: 'Hardcoded default or weak database credentials are trivially guessable and frequently targeted by automated scanners and botnets. A successful authentication bypass gives an attacker full read/write access to the database, potentially leading to total data compromise.',
  severity: 'CRITICAL',
  category: 'CONFIG',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const defaultUsers = ['root', 'admin', 'postgres', 'sa', 'Administrator'];
    const weakPasswords = ['', 'password', 'Password123', '123456', 'admin', 'root'];

    lines.forEach((line, index) => {
      defaultUsers.forEach(user => {
        const hasDefaultUser = new RegExp(`(user|username)\\s*[:=]\\s*['"]${user}['"]`, 'i').test(line);
        if (hasDefaultUser) {
          // Check for weak password nearby
          const contextStart = Math.max(0, index - 2);
          const contextEnd = Math.min(lines.length, index + 3);
          const context = lines.slice(contextStart, contextEnd).join('\n');

          const hasWeakPassword = weakPasswords.some(pwd =>
            new RegExp(`(password|pass)\\s*[:=]\\s*['"]${pwd}['"]`, 'i').test(context)
          );

          if (hasWeakPassword || /password\s*[:=]\s*['"]['"]/.test(context)) {
            matches.push({
              line: index + 1,
              column: 0,
              codeSnippet: line.trim(),
              confidence: 0.95,
            });
          }
        }
      });
    });

    return matches;
  },
};

const MISSING_HELMET: Rule = {
  id: 'MISSING_HELMET',
  title: 'Express app without security headers',
  description: 'An Express application running without the helmet middleware omits critical HTTP security headers such as Content-Security-Policy, X-Frame-Options, and Strict-Transport-Security. The absence of these headers leaves the application vulnerable to clickjacking, cross-site scripting, and MIME-type sniffing attacks.',
  severity: 'MEDIUM',
  category: 'CONFIG',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const hasExpress = /express\s*\(\)/.test(code);
    const hasHelmet = /(helmet|app\.use\s*\(\s*helmet)/i.test(code);

    if (hasExpress && !hasHelmet) {
      // Return a single finding at the express() line
      for (let i = 0; i < lines.length; i++) {
        if (/express\s*\(\)/.test(lines[i])) {
          return [{
            line: i + 1,
            column: 0,
            codeSnippet: lines[i].trim(),
            confidence: 0.70,
          }];
        }
      }
    }

    return [];
  },
};

const MISSING_RATE_LIMIT: Rule = {
  id: 'MISSING_RATE_LIMIT',
  title: 'No rate limiting on sensitive routes',
  description: 'Authentication and account-creation endpoints without rate limiting are susceptible to brute-force and credential-stuffing attacks, where adversaries submit thousands of guessed credentials in rapid succession. Unrestricted request rates also enable account enumeration and denial-of-service against login infrastructure.',
  severity: 'MEDIUM',
  category: 'CONFIG',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const hasAuthRoutes = /(\/login|\/signup|\/register|\/api\/auth)/i.test(code);
    const hasRateLimit = /(express-rate-limit|rate-limit|ratelimit|@upstash\/ratelimit)/i.test(code);

    if (hasAuthRoutes && !hasRateLimit) {
      // Find the first auth route
      for (let i = 0; i < lines.length; i++) {
        if (/(\/login|\/signup|\/register|\/api\/auth)/i.test(lines[i])) {
          return [{
            line: i + 1,
            column: 0,
            codeSnippet: lines[i].trim(),
            confidence: 0.65,
          }];
        }
      }
    }

    return [];
  },
};

const VERBOSE_ERRORS: Rule = {
  id: 'VERBOSE_ERRORS',
  title: 'Detailed error messages sent to client',
  description: 'Returning raw error objects, stack traces, or internal exception messages to clients leaks architectural details such as file paths, library versions, and database schema information. Attackers use this information to refine exploits and identify additional attack surfaces.',
  severity: 'MEDIUM',
  category: 'CONFIG',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const patterns = [
      /res\.(json|send)\s*\([^)]*err\.(message|stack)/gi,
      /return\s+.*error\s*:\s*err\./gi,
      /res\.status\([^)]*\)\.json\([^)]*err\./gi,
    ];

    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      patterns.forEach(pattern => {
        const lineMatches = line.matchAll(pattern);
        for (const match of lineMatches) {
          matches.push({
            line: index + 1,
            column: match.index,
            codeSnippet: line.trim(),
            confidence: 0.80,
          });
        }
      });
    });

    return matches;
  },
};

const OPEN_REDIRECT: Rule = {
  id: 'OPEN_REDIRECT',
  title: 'Unvalidated redirect — user-controlled URL',
  description: 'An open redirect occurs when an application redirects users to a destination URL derived from unvalidated request parameters, allowing attackers to weaponize trusted domain URLs for phishing and OAuth token hijacking. Without strict allowlist validation, any user-supplied path can redirect victims to attacker-controlled infrastructure.',
  severity: 'HIGH',
  category: 'CONFIG',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    // Track variables assigned from redirect-related req params
    const redirectVars = new Set<string>();
    const redirectParamNames = /\b(next|redirect|url|return_to|returnTo|goto|target|callback|redir)\b/i;

    lines.forEach((line, index) => {
      // Collect variables assigned from redirect-like query/body params
      const assignMatch = line.match(/(?:const|let|var)\s+(\w+)\s*=\s*req\.(query|body|params)\.(\w+)/);
      if (assignMatch && redirectParamNames.test(assignMatch[3])) {
        redirectVars.add(assignMatch[1]);
      }
      // Also catch destructuring: const { next } = req.query
      const destructure = line.match(/(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*req\.(query|body|params)/);
      if (destructure) {
        destructure[1].split(',').forEach(v => {
          const varName = v.trim().split(':')[0].trim();
          if (redirectParamNames.test(varName)) redirectVars.add(varName);
        });
      }

      // Pattern 1: Direct res.redirect(req.query.*)
      const directPatterns = [
        /res\.redirect\s*\(\s*req\.(query|body|params)/gi,
        /window\.location\s*=\s*.*\b(params|query|search)\b/gi,
        /location\.href\s*=\s*.*\b(params|query)\b/gi,
      ];
      directPatterns.forEach(pattern => {
        const lineMatches = line.matchAll(pattern);
        for (const match of lineMatches) {
          matches.push({ line: index + 1, column: match.index, codeSnippet: line.trim(), confidence: 0.90 });
        }
      });

      // Pattern 2: res.redirect(varFromReq) — variable was assigned from req.query.next etc.
      if (/res\.redirect\s*\(/.test(line)) {
        const argMatch = line.match(/res\.redirect\s*\(\s*(\w+)/);
        if (argMatch && redirectVars.has(argMatch[1])) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.88 });
        }
        // res.redirect(req.query.next || '/') — still dangerous if unvalidated
        if (/res\.redirect\s*\([^)]*req\.(query|body|params)/.test(line)) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.90 });
        }
      }
    });

    return matches;
  },
};

// ─── Insecure cookie — missing httpOnly and/or Secure flags ──────────────────
const INSECURE_COOKIE: Rule = {
  id: 'INSECURE_COOKIE',
  title: 'Cookie set without httpOnly and/or Secure flags',
  description: 'Cookies lacking the httpOnly flag are accessible to JavaScript, making them directly stealable via XSS attacks, while omitting the Secure flag allows the cookie to be transmitted over unencrypted HTTP connections. Together, these omissions expose session tokens and authentication credentials to interception and theft.',
  severity: 'HIGH',
  category: 'CONFIG',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      if (!/res\.cookie\s*\(/.test(line)) return;

      // Check the options object — either on this line or in the next few lines
      const ctx = lines.slice(index, Math.min(lines.length, index + 6)).join('\n');

      const hasHttpOnly = /httpOnly\s*:\s*true/i.test(ctx);
      const hasSecure = /secure\s*:\s*true/i.test(ctx);
      const hasOptions = /\{/.test(ctx.split('res.cookie')[1] || '');

      // If no options object at all, or options lack httpOnly/Secure flags
      if (!hasOptions || !hasHttpOnly || !hasSecure) {
        const missingFlags = [];
        if (!hasHttpOnly) missingFlags.push('httpOnly');
        if (!hasSecure) missingFlags.push('secure');
        matches.push({
          line: index + 1,
          column: 0,
          codeSnippet: line.trim(),
          confidence: 0.85,
        });
      }
    });

    return matches;
  },
};

// ─── Timing attack — string equality on secrets/tokens ───────────────────────
const TIMING_ATTACK: Rule = {
  id: 'TIMING_ATTACK',
  title: 'Secret or token compared with === (timing attack risk) — use crypto.timingSafeEqual',
  description: 'Using standard equality operators to compare secrets or tokens is vulnerable to timing side-channel attacks, where an attacker can infer correct bytes by measuring subtle differences in comparison duration. Constant-time comparison functions such as crypto.timingSafeEqual must be used for all secret material to eliminate this oracle.',
  severity: 'HIGH',
  category: 'AUTH',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      // Must have a string equality operator
      if (!/===|==/.test(line)) return;
      // Must involve a secret/token/password/key variable
      const hasSecret = /(token|secret|apiKey|api_key|password|signature|hmac|hash|digest)\b/i.test(line);
      // Must not already be using timingSafeEqual or similar
      const hasSafeCompare = /(timingSafeEqual|safeCompare|constantTimeCompare|crypto\.timingSafe)/i.test(line);

      if (hasSecret && !hasSafeCompare) {
        // Higher confidence if we see === with variables on both sides (not just a literal check)
        const confidence = /===\s*\w/.test(line) ? 0.82 : 0.72;
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence });
      }
    });

    return matches;
  },
};

// ─── Prisma / TypeORM mass assignment via spread/req.body ─────────────────────
const PRISMA_MASS_ASSIGNMENT: Rule = {
  id: 'PRISMA_MASS_ASSIGNMENT',
  title: 'ORM update/create with entire req.body — mass assignment risk',
  description: 'Passing the raw request body directly to ORM create or update operations allows attackers to inject arbitrary fields, including privileged attributes such as role, isAdmin, or accountBalance, that were not intended to be user-modifiable. This mass assignment vulnerability can result in unauthorized privilege escalation and data integrity violations.',
  severity: 'HIGH',
  category: 'ACCESS_CONTROL',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      // prisma.*.update/create/upsert with data: req.body
      const hasPrismaOp = /prisma\.\w+\.(update|create|upsert|updateMany|createMany)\s*\(/.test(line);
      // typeorm/sequelize save with req.body
      const hasOrmOp = /(\.save\s*\(|repository\.(save|update|insert)\s*\(|Model\.(update|create)\s*\()/.test(line);
      // mongoose findOneAndUpdate / updateOne / update with req.body
      const hasMongooseSpread = /(findOneAndUpdate|updateOne|updateMany|findByIdAndUpdate)\s*\([^)]*req\.body/.test(line);

      if (!hasPrismaOp && !hasOrmOp && !hasMongooseSpread) return;

      // Check if the data/update argument comes directly from req.body
      const ctx = lines.slice(index, Math.min(lines.length, index + 6)).join('\n');
      const hasReqBody = /data\s*:\s*req\.body|data\s*:\s*\{\s*\.\.\.req\.body|\bupdate\s*\(\s*[^)]*req\.body|\bsave\s*\(\s*req\.body/.test(ctx);

      if (hasReqBody || (hasPrismaOp && /req\.body/.test(ctx))) {
        // Check if there's explicit field selection (allowlist) — reduces false positives
        const hasAllowlist = /(pick|omit|select|whitelist|allowedFields|\.name\s*:|\.email\s*:)/.test(ctx);
        if (!hasAllowlist) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.87 });
        }
      }
    });

    return matches;
  },
};

// ─── Prototype pollution via Object.assign / spread with user input ───────────
const PROTOTYPE_POLLUTION: Rule = {
  id: 'PROTOTYPE_POLLUTION',
  title: 'Object.assign or spread with user input — prototype pollution risk',
  description: 'Merging user-supplied objects into existing objects via Object.assign, spread, or deep-merge utilities can allow attackers to inject properties onto Object.prototype, affecting all objects in the application. Prototype pollution can be chained to achieve remote code execution, authentication bypass, or denial of service depending on how polluted properties are consumed downstream.',
  severity: 'HIGH',
  category: 'INJECTION',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      // Object.assign(target, req.body) — if target is an existing object (not {})
      const objectAssignPattern = /Object\.assign\s*\(\s*(?!\s*\{)(\w+)\s*,\s*req\.(body|query|params)/.test(line);
      // Spread into existing object: { ...existingObj, ...req.body }
      // Only flag if spread is NOT into a plain new object literal at top level
      const spreadIntoExisting = /\.\.\.\s*req\.(body|query|params)/.test(line) &&
        !/^\s*(const|let|var)\s+\w+\s*=\s*\{/.test(line); // not a fresh assignment to plain literal
      // _.merge / deepmerge / merge with req.body — known prototype pollution vectors
      const mergeWithInput = /(_\.merge|deepmerge|merge|extend)\s*\([^)]*req\.(body|query|params)/.test(line);

      if (objectAssignPattern || mergeWithInput) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.87 });
      } else if (spreadIntoExisting) {
        // Lower confidence for spread — more likely to be intentional
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.72 });
      }
    });

    return matches;
  },
};

const DOCKER_ROOT: Rule = {
  id: 'DOCKER_ROOT',
  title: 'Docker container running as root',
  description: 'A Docker container that runs as the root user grants any process inside full administrative privileges within the container, dramatically increasing the blast radius of a container escape or code execution vulnerability. Specifying a non-root USER in the Dockerfile enforces least privilege and limits the impact of a compromised container.',
  severity: 'MEDIUM',
  category: 'CONFIG',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const hasDockerfile = /FROM\s+\w/.test(code);
    const hasUserInstruction = /USER\s+\w/i.test(code);

    if (hasDockerfile && !hasUserInstruction) {
      // Find the FROM line
      for (let i = 0; i < lines.length; i++) {
        if (/FROM\s+\w/.test(lines[i])) {
          matches.push({
            line: i + 1,
            column: 0,
            codeSnippet: lines[i].trim(),
            confidence: 0.75,
          });
          break;
        }
      }
    }

    return matches;
  },
};

export const configRules: Rule[] = [
  CORS_WILDCARD,
  DEBUG_MODE_ON,
  HTTPS_DISABLED,
  DEFAULT_DB_CREDS,
  MISSING_HELMET,
  MISSING_RATE_LIMIT,
  VERBOSE_ERRORS,
  OPEN_REDIRECT,
  DOCKER_ROOT,
  INSECURE_COOKIE,
  PRISMA_MASS_ASSIGNMENT,
  PROTOTYPE_POLLUTION,
];
