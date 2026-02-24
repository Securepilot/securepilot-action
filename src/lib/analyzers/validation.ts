import { Rule, RuleMatch } from './types';

const NO_INPUT_VALIDATION: Rule = {
  id: 'NO_INPUT_VALIDATION',
  title: 'Request body used without validation',
  description: 'Using request body, query, or parameter values directly in database operations without prior schema validation allows attackers to supply unexpected data types, overflow fields, or inject malicious values. Lack of input validation is a foundational weakness that amplifies the impact of injection, mass assignment, and business logic vulnerabilities.',
  severity: 'HIGH',
  category: 'VALIDATION',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      const hasReqBody = /req\.(body|params|query)\./i.test(line);
      const hasDbOp = /(create|insert|update|save|set|find|where)\s*\(/i.test(line);

      if (hasReqBody && hasDbOp) {
        // Check for validation libraries nearby
        const contextStart = Math.max(0, index - 10);
        const contextEnd = Math.min(lines.length, index + 2);
        const context = lines.slice(contextStart, contextEnd).join('\n');

        const hasValidation = /(zod|joi|yup|class-validator|validate|parse|safeParse|typeof|instanceof)/i.test(context);

        if (!hasValidation) {
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

const FILE_UPLOAD_NO_CHECK: Rule = {
  id: 'FILE_UPLOAD_NO_CHECK',
  title: 'File upload without type/size validation',
  description: 'Accepting file uploads without enforcing MIME type and file size restrictions enables attackers to upload malicious executables, web shells, or excessively large files that exhaust server resources. Without fileFilter and limits configuration, the application is susceptible to remote code execution and denial-of-service via storage or memory exhaustion.',
  severity: 'HIGH',
  category: 'VALIDATION',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      const hasMulter = /multer\s*\(/i.test(line);
      const hasFormidable = /formidable|busboy/i.test(line);

      if (hasMulter || hasFormidable) {
        // Check for fileFilter or limits
        const contextEnd = Math.min(lines.length, index + 5);
        const context = lines.slice(index, contextEnd).join('\n');

        const hasFileFilter = /fileFilter|limits|maxFileSize/i.test(context);

        if (!hasFileFilter) {
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

const PATH_TRAVERSAL: Rule = {
  id: 'PATH_TRAVERSAL',
  title: 'File path from user input',
  description: 'Constructing file system paths from user-supplied input without canonicalization or sanitization allows attackers to use directory traversal sequences (e.g., ../../etc/passwd) to read, write, or delete files outside the intended directory. This can lead to sensitive data disclosure, configuration file tampering, or complete server compromise.',
  severity: 'CRITICAL',
  category: 'VALIDATION',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const fileOps = ['readFile', 'writeFile', 'createReadStream', 'unlink', 'open', 'rm', 'rmdir'];

    lines.forEach((line, index) => {
      const hasFileOp = fileOps.some(op => new RegExp(`\\b${op}\\s*\\(`).test(line));
      const hasUserInput = /req\.(body|query|params)/i.test(line);

      if (hasFileOp && hasUserInput) {
        // Check if there's path sanitization
        const hasSanitization = /(path\.basename|path\.resolve|path\.normalize|path\.join)/i.test(line);

        if (!hasSanitization) {
          matches.push({
            line: index + 1,
            column: 0,
            codeSnippet: line.trim(),
            confidence: 0.90,
          });
        }
      }
    });

    return matches;
  },
};

const MASS_ASSIGNMENT: Rule = {
  id: 'MASS_ASSIGNMENT',
  title: 'Entire request body spread into DB',
  description: 'Directly passing the full request body to ORM create or update operations allows an attacker to overwrite any database field, including privileged ones such as role, isAdmin, or passwordHash, that the application did not intend to expose. This mass assignment vulnerability can result in horizontal or vertical privilege escalation.',
  severity: 'HIGH',
  category: 'VALIDATION',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const patterns = [
      /\.(create|insert)\s*\(\s*req\.body\s*\)/gi,
      /\.(create|insert)\s*\(\s*\{[^}]*\.\.\.req\.body/gi,
      /\.(update|updateOne|updateMany)\s*\([^)]*req\.body\s*\)/gi,
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

const REGEX_DOS: Rule = {
  id: 'REGEX_DOS',
  title: 'Potentially catastrophic regex',
  description: 'Regular expressions with nested or ambiguous quantifiers such as (a+)+ are susceptible to catastrophic backtracking, where certain input strings cause exponential evaluation time that consumes 100% CPU. This is classified as a Regular Expression Denial of Service (ReDoS) and can render the application unresponsive.',
  severity: 'MEDIUM',
  category: 'VALIDATION',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    // Look for nested quantifiers that can cause ReDoS
    const dangerousPatterns = [
      /\([^)]*\+\s*\)\s*\+/g,  // (a+)+
      /\([^)]*\*\s*\)\s*\*/g,  // (a*)*
      /\([^|]*\|[^)]*\)\s*\*/g,  // (a|b|c)*
    ];

    lines.forEach((line, index) => {
      dangerousPatterns.forEach(pattern => {
        const lineMatches = line.matchAll(pattern);
        for (const match of lineMatches) {
          matches.push({
            line: index + 1,
            column: match.index,
            codeSnippet: line.trim(),
            confidence: 0.70,
          });
        }
      });
    });

    return matches;
  },
};

// ─── ReDoS via user-controlled RegExp ─────────────────────────────────────────
// new RegExp(userInput) or RegExp(req.query.*) allows attackers to supply
// catastrophic backtracking patterns that cause CPU exhaustion (DoS).
const REDOS_USER_INPUT: Rule = {
  id: 'REDOS_USER_INPUT',
  title: 'RegExp constructed from user input — ReDoS (Denial of Service) risk',
  description: 'Constructing a RegExp object directly from user-supplied input allows an attacker to inject a crafted pattern with catastrophic backtracking characteristics, causing the JavaScript engine to spin at 100% CPU for an extended period. This is a trivially exploitable Denial of Service vector that requires no authentication.',
  severity: 'HIGH',
  category: 'VALIDATION',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    // Track variables assigned from req.*
    const userInputVars = new Set<string>();

    lines.forEach((line, index) => {
      // Collect user-input variable assignments
      const assignMatch = line.match(/(?:const|let|var)\s+(\w+)\s*=\s*req\.(query|body|params|headers)\b/);
      if (assignMatch) userInputVars.add(assignMatch[1]);
      const propAssign = line.match(/(?:const|let|var)\s+(\w+)\s*=\s*req\.(query|body|params)\.\w+/);
      if (propAssign) userInputVars.add(propAssign[1]);
      // Destructuring: const { pattern } = req.query
      const destructure = line.match(/(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*req\.(query|body|params)/);
      if (destructure) {
        destructure[1].split(',').forEach(v => userInputVars.add(v.trim().split(':')[0].trim()));
      }

      // Pattern 1: new RegExp(req.*) or RegExp(req.*) directly
      const directRegExp = /new\s+RegExp\s*\(\s*req\.(query|body|params|headers)|(?<!\w)RegExp\s*\(\s*req\.(query|body|params|headers)/.test(line);

      // Pattern 2: new RegExp(variable) where variable came from req.*
      const hasRegExpConstructor = /new\s+RegExp\s*\(\s*(\w+)/.test(line);
      if (hasRegExpConstructor) {
        const varName = line.match(/new\s+RegExp\s*\(\s*(\w+)/)?.[1];
        if (varName && userInputVars.has(varName)) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.90 });
          return;
        }
      }

      if (directRegExp) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.92 });
      }
    });

    return matches;
  },
};

// ─── GraphQL introspection enabled in production ─────────────────────────────
const GRAPHQL_INTROSPECTION: Rule = {
  id: 'GRAPHQL_INTROSPECTION',
  title: 'GraphQL introspection enabled — exposes full schema to attackers',
  description: 'Leaving GraphQL introspection enabled in production allows any unauthenticated client to enumerate every type, query, mutation, and field in the API schema. This detailed roadmap significantly accelerates reconnaissance by attackers seeking injection points, authorization bypasses, and sensitive data fields.',
  severity: 'MEDIUM',
  category: 'CONFIG',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      // introspection: true in Apollo/GraphQL config
      const hasIntrospection = /introspection\s*:\s*true\b/.test(line);
      // playground: true (exposes schema explorer)
      const hasPlayground = /playground\s*:\s*true\b/.test(line);

      if (hasIntrospection || hasPlayground) {
        // Check surrounding context (±3 lines) for env guard — if guarded, skip entirely
        const ctx = lines.slice(Math.max(0, index - 3), Math.min(lines.length, index + 2)).join('\n');
        const isConditional = /(NODE_ENV\s*[!=]==?\s*['"]production['"]|isDev\b|isProduction\b|process\.env\.(?:NODE_ENV|VERCEL_ENV|APP_ENV))/i.test(ctx);
        // If the introspection flag is clearly inside a dev/non-prod guard, skip
        if (isConditional) return;
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.85 });
      }
    });

    return matches;
  },
};

// ─── Missing Content-Type validation on JSON endpoints ───────────────────────
// Without Content-Type checks, CSRF is possible even with JSON APIs,
// and unexpected parsers can be triggered (text/plain bypasses CSRF protections).
const MISSING_CONTENT_TYPE_CHECK: Rule = {
  id: 'MISSING_CONTENT_TYPE_CHECK',
  title: 'POST/PUT route missing Content-Type validation — CSRF and type confusion risk',
  description: 'State-changing endpoints that do not validate the Content-Type header can be triggered by cross-origin form submissions or text/plain requests, bypassing CORS preflight protections and enabling Cross-Site Request Forgery (CSRF). Type confusion between expected JSON and received form-encoded data can also lead to parsing anomalies that defeat downstream security controls.',
  severity: 'MEDIUM',
  category: 'VALIDATION',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      // State-changing routes that process body data
      const isMutatingRoute = /app\.(post|put|patch)\s*\(/.test(line);
      if (!isMutatingRoute) return;

      // Look at surrounding context for Content-Type check
      const ctx = lines.slice(index, Math.min(lines.length, index + 12)).join('\n');

      // Check for content-type validation patterns
      const hasContentTypeCheck =
        // req.is("application/json") — Express content negotiation
        /req\.is\s*\(/.test(ctx) ||
        // Explicit header check
        (/(content-type|contentType|Content-Type)/i.test(ctx) &&
         /(check|validate|verify|includes|startsWith|===|!==)/i.test(ctx));
      // Check for middleware that handles this (helmet, express.json with strict, csurf)
      const hasProtectiveMiddleware = /(express\.json\s*\(\s*\{[^}]*strict|csurf|csrf|helmet)/i.test(ctx);
      // Check if it's a simple route likely to process untrusted body
      const processesBody = /req\.body/.test(ctx);

      if (processesBody && !hasContentTypeCheck && !hasProtectiveMiddleware) {
        // Only flag routes that explicitly process body without any type guard
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.68 });
      }
    });

    return matches;
  },
};

const UNSAFE_DESERIALIZATION: Rule = {
  id: 'UNSAFE_DESERIALIZATION',
  title: 'Unsafe deserialization of user input',
  description: 'Deserializing untrusted data using unsafe formats such as Python pickle or YAML without a restricted loader allows attackers to embed executable code within serialized payloads, leading to arbitrary remote code execution upon deserialization. This is one of the most critical vulnerability classes and can result in complete server compromise with no additional preconditions.',
  severity: 'CRITICAL',
  category: 'VALIDATION',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const patterns = [
      { regex: /pickle\.loads\s*\(/gi, confidence: 0.95 },  // Python pickle
      { regex: /yaml\.load\s*\(/gi, confidence: 0.80 },     // YAML without SafeLoader
      { regex: /JSON\.parse\s*\(\s*req\./gi, confidence: 0.60 }, // JSON.parse (lower risk)
    ];

    lines.forEach((line, index) => {
      patterns.forEach(({ regex, confidence }) => {
        const lineMatches = line.matchAll(regex);
        for (const match of lineMatches) {
          // For YAML, check if SafeLoader is used
          if (regex.source.includes('yaml') && /SafeLoader/.test(line)) {
            continue;
          }

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

export const validationRules: Rule[] = [
  NO_INPUT_VALIDATION,
  FILE_UPLOAD_NO_CHECK,
  PATH_TRAVERSAL,
  MASS_ASSIGNMENT,
  REGEX_DOS,
  REDOS_USER_INPUT,
  UNSAFE_DESERIALIZATION,
  GRAPHQL_INTROSPECTION,
  MISSING_CONTENT_TYPE_CHECK,
];
