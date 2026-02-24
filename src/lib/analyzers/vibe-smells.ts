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

const TODO_SECURITY: Rule = {
  id: 'TODO_SECURITY',
  title: 'TODO comment about security left unimplemented',
  description: 'Unfulfilled TODO or FIXME comments referencing security-critical operations indicate that protective logic was never implemented, leaving the application exposed to vulnerabilities the developer was already aware of.',
  severity: 'HIGH',
  category: 'VIBE_SMELL',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const regex = /(TODO|FIXME|HACK|XXX).*(auth|security|encrypt|sanitize|validate|permission|password|token|session)/gi;
    return findMatches(regex, code, lines, 0.90);
  },
};

const PLACEHOLDER_AUTH: Rule = {
  id: 'PLACEHOLDER_AUTH',
  title: 'Auth/security imports present but unused',
  description: 'Importing a security library without actually invoking it provides a false sense of protection; the security controls are not applied at runtime, leaving attack surfaces open despite the presence of the dependency.',
  severity: 'MEDIUM',
  category: 'VIBE_SMELL',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const securityLibs = ['bcrypt', 'helmet', 'cors', 'jsonwebtoken', 'passport'];

    securityLibs.forEach(lib => {
      const importRegex = new RegExp(`(import|require).*${lib}`, 'i');
      const usageRegex = new RegExp(`${lib}\\.|\\.use\\s*\\(\\s*${lib}`, 'i');

      const hasImport = lines.some(line => importRegex.test(line));
      const hasUsage = code.match(usageRegex);

      if (hasImport && !hasUsage) {
        // Find the import line
        for (let i = 0; i < lines.length; i++) {
          if (importRegex.test(lines[i])) {
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
    });

    return matches;
  },
};

const COMMENTED_OUT_SECURITY: Rule = {
  id: 'COMMENTED_OUT_SECURITY',
  title: 'Security code commented out',
  description: 'Commented-out security controls such as CSRF middleware, authentication, or password hashing mean those protections are not active, silently removing a layer of defence from the application.',
  severity: 'HIGH',
  category: 'VIBE_SMELL',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const patterns = [
      /\/\/\s*(app\.use\(helmet|app\.use\(cors|bcrypt\.hash|jwt\.verify)/gi,
      /#\s*(bcrypt|helmet|authenticate)/gi,
    ];

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

const CONSOLE_LOG_SENSITIVE: Rule = {
  id: 'CONSOLE_LOG_SENSITIVE',
  title: 'console.log with sensitive data',
  description: 'Logging sensitive values such as passwords, tokens, or session identifiers to the console can expose credentials in server logs, CI output, or monitoring systems accessible to unauthorized parties.',
  severity: 'MEDIUM',
  category: 'VIBE_SMELL',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      const hasConsoleLog = /console\.log/i.test(line);
      const hasSensitiveData = /(password|token|secret|key|authorization|cookie|session)/i.test(line);

      if (hasConsoleLog && hasSensitiveData) {
        matches.push({
          line: index + 1,
          column: 0,
          codeSnippet: line.trim(),
          confidence: 0.80,
        });
      }
    });

    return matches;
  },
};

const GENERIC_ERROR_HANDLER: Rule = {
  id: 'GENERIC_ERROR_HANDLER',
  title: 'Empty or generic catch block',
  description: 'Empty or silent catch blocks suppress exceptions, preventing proper error propagation and masking security failures such as failed authentication checks or invalid input, making incidents difficult to detect and debug.',
  severity: 'LOW',
  category: 'VIBE_SMELL',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      const isCatchBlock = /catch\s*\([^)]*\)\s*\{\s*\}/.test(line) ||
                          /except\s*[:\w]*\s*:\s*pass/.test(line);
      const hasConsoleOnly = /catch.*\{.*console\.log/.test(line) &&
                             !/(throw|res\.|return|error)/.test(line);

      if (isCatchBlock || hasConsoleOnly) {
        matches.push({
          line: index + 1,
          column: 0,
          codeSnippet: line.trim(),
          confidence: 0.70,
        });
      }
    });

    return matches;
  },
};

const HALLUCINATED_IMPORT: Rule = {
  id: 'HALLUCINATED_IMPORT',
  title: 'Import of commonly hallucinated or typosquatted packages (slopsquatting)',
  description: 'Importing packages with incorrect or hallucinated names can resolve to typosquatted packages published by malicious actors, which may execute arbitrary code at install time or inject backdoors into the application.',
  severity: 'HIGH',
  category: 'VIBE_SMELL',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const hallucinatedPackages = [
      // AI-hallucinated wrong package names (slopsquatting)
      { wrong: '@anthropic/sdk', correct: '@anthropic-ai/sdk' },
      { wrong: 'openai-node', correct: 'openai' },
      { wrong: 'openai-api', correct: 'openai' },
      { wrong: 'openai-client', correct: 'openai' },
      { wrong: 'express-auth', correct: 'passport or next-auth' },
      { wrong: 'mongo-sanitize', correct: 'express-mongo-sanitize' },
      { wrong: 'react-hooks', correct: 'react (hooks are built-in)' },
      { wrong: 'express-validators', correct: 'express-validator' },
      { wrong: 'express-validation', correct: 'express-validator' },
      { wrong: 'node-crypto', correct: 'crypto (built-in Node.js module)' },
      { wrong: 'node-fetch2', correct: 'node-fetch or native fetch' },
      { wrong: 'jsonwebtoken-node', correct: 'jsonwebtoken' },
      { wrong: 'bcryptjs-node', correct: 'bcryptjs or bcrypt' },
      { wrong: 'prisma-client', correct: '@prisma/client' },
      { wrong: 'next-auth2', correct: 'next-auth' },
      { wrong: 'stripe-node', correct: 'stripe' },
      { wrong: 'aws-sdk-v3', correct: '@aws-sdk/client-*' },
      { wrong: 'mongoose-validator', correct: 'mongoose-unique-validator or validator' },
      // Known typosquatted packages with malicious history
      { wrong: 'crossenv', correct: 'cross-env (typosquatted — was malware)' },
      { wrong: 'event-stream', correct: 'Use a maintained alternative (compromised in 2018)' },
      { wrong: 'lodash.utils', correct: 'lodash (typosquatted)' },
      { wrong: 'faker.js', correct: '@faker-js/faker' },
      { wrong: 'colors.js', correct: '@colors/colors or chalk' },
    ];

    lines.forEach((line, index) => {
      // Only process lines that look like import/require statements
      if (!/(import|require|from)\b/.test(line)) return;

      hallucinatedPackages.forEach(({ wrong, correct }) => {
        // Use simple string inclusion — check if the exact package name appears in quotes
        // This avoids dynamic regex escaping issues with scoped packages (@org/pkg)
        const inSingleQuotes = line.includes(`'${wrong}'`);
        const inDoubleQuotes = line.includes(`"${wrong}"`);

        if (inSingleQuotes || inDoubleQuotes) {
          matches.push({
            line: index + 1,
            column: 0,
            codeSnippet: line.trim() + ` // Should be: ${correct}`,
            confidence: 0.95,
          });
        }
      });
    });

    return matches;
  },
};

// ─── Logic inversion in auth/security checks (AI-specific bug) ───────────────
const AUTH_LOGIC_INVERSION: Rule = {
  id: 'AUTH_LOGIC_INVERSION',
  title: 'Potentially inverted auth/security check — passes when it should block',
  description: 'An inverted conditional in an authentication or authorization check can inadvertently permit access when it should be denied, effectively turning a security gate into an open door for unauthenticated or unprivileged users.',
  severity: 'HIGH',
  category: 'VIBE_SMELL',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      // Patterns like: if (!isAdmin) { return data; } — returns when NOT admin
      // or: if (!isAuthenticated) { proceed() }
      const hasNegatedAuth = /if\s*\(\s*!?\s*(isAdmin|isAuthenticated|isAuthorized|hasPermission|isLoggedIn|isValid|authenticated|authorized)\s*\)/i.test(line);
      if (!hasNegatedAuth) return;

      // Check if the body of this if-block does something that should only happen when authenticated
      const ctx = lines.slice(index, Math.min(lines.length, index + 5)).join('\n');
      const doesSomethingPositive = /(return\s+(data|result|user|resource)|res\.json|res\.send|next\(\))/i.test(ctx);
      const hasReturnOrThrow = /(return|throw|redirect|res\.status\(4)/i.test(ctx);

      // Flag if: !auth check leads to positive action (not a guard clause)
      const isNegated = /if\s*\(\s*!/i.test(line);
      if (isNegated && doesSomethingPositive && !hasReturnOrThrow) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.65 });
      }
    });
    return matches;
  },
};

// ─── Return value of security check ignored ──────────────────────────────────
const SECURITY_CHECK_RETURN_IGNORED: Rule = {
  id: 'SECURITY_CHECK_RETURN_IGNORED',
  title: 'Return value of security/validation function not checked',
  description: 'Calling a validation or authentication function without consuming its return value means the outcome of the security check is silently discarded, allowing execution to continue regardless of whether the check passed or failed.',
  severity: 'HIGH',
  category: 'VIBE_SMELL',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      // Standalone calls to security functions whose return value is critical
      const hasUncheckedSecurity = /^\s*(verifyToken|authenticate|authorize|validate|checkPermission|sanitize)\s*\(/i.test(line);
      const isAssigned = /(const|let|var|=|if\s*\(|return|await)/.test(line);
      if (hasUncheckedSecurity && !isAssigned) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.75 });
      }
    });
    return matches;
  },
};

// ─── Type coercion in security comparison (== vs ===) ────────────────────────
const LOOSE_EQUALITY_SECURITY: Rule = {
  id: 'LOOSE_EQUALITY_SECURITY',
  title: 'Loose equality (==) used in security/auth comparison',
  description: 'Using loose equality (==) in security-sensitive comparisons is vulnerable to type coercion attacks, where a crafted value of a different type may unexpectedly satisfy the comparison and bypass authentication or authorization logic.',
  severity: 'MEDIUM',
  category: 'VIBE_SMELL',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      const hasLooseEq = /[^=!]==[^=]/i.test(line);
      const isSecurityContext = /(password|token|secret|auth|admin|role|permission|userId|user_id)/i.test(line);
      if (hasLooseEq && isSecurityContext) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.80 });
      }
    });
    return matches;
  },
};

// ─── AI placeholder / stub that bypasses real logic ──────────────────────────
const AI_STUB_BYPASS: Rule = {
  id: 'AI_STUB_BYPASS',
  title: 'Stub/placeholder function returns success without real implementation',
  description: 'A stub or placeholder implementation that unconditionally returns a success value in place of real authentication or validation logic bypasses the intended security control entirely, granting access without performing any actual verification.',
  severity: 'HIGH',
  category: 'VIBE_SMELL',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      // Pattern: function with auth/validation name that just returns true
      const isTrueStub = /(function|=>|def)\s*(auth|validate|verify|checkAuth|isValid|authenticate|authorize)[^{]*\{?\s*(return\s+true|return True)/i.test(line);
      const isNextTwoLines = !isTrueStub && /return\s+true\s*;?\s*$|return True$/.test(line.trim());

      if (isTrueStub) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.85 });
      } else if (isNextTwoLines) {
        // Check if previous few lines define an auth function
        const ctx = lines.slice(Math.max(0, index - 3), index).join('\n');
        if (/(function|def|=>)\s*(auth|validate|verify|checkAuth|isValid)/i.test(ctx)) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.80 });
        }
      }
    });
    return matches;
  },
};

// ─── Always-true auth function — classic AI hallucination ────────────────────
// Catches: function isAuthenticated() { return true; }
//          const isAdmin = () => true;
//          def is_logged_in(): return True
const ALWAYS_TRUE_AUTH: Rule = {
  id: 'ALWAYS_TRUE_AUTH',
  title: 'Auth/permission check always returns true — bypasses security',
  description: 'An authentication or permission function that always returns true provides no security whatsoever; any caller will be treated as authenticated or authorized regardless of their actual identity or privileges, completely neutralizing the access control layer.',
  severity: 'CRITICAL',
  category: 'VIBE_SMELL',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    const authNamePattern = /\b(is(Auth(enticated)?|Admin|LoggedIn|Valid|Authorized|Permitted|Owner)|check(Auth|Permission|Access|Role)|has(Permission|Role|Access)|can(Access|Edit|View|Delete)|verify(Auth|Token|User)?|authenticate|authorize)\b/i;

    lines.forEach((line, index) => {
      // Pattern 1: Single-line — function with auth name that contains `return true`
      // e.g. function isAuthenticated() { return true; }
      // e.g. const isAdmin = () => { return true; }
      const singleLineTrue =
        authNamePattern.test(line) &&
        /(return\s+true\s*[;}]|=>\s*true\s*[;,]?\s*$|\breturn\s+True\b)/.test(line);

      if (singleLineTrue) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.92 });
        return;
      }

      // Pattern 2: Arrow shorthand on its own — const isAdmin = () => true
      const arrowTrue =
        /\b\w*(auth|Auth|Admin|admin|Permission|permission|Access|access|Login|login|Logged|logged)\w*\s*=\s*(\([^)]*\)|)\s*=>\s*true\b/.test(line);
      if (arrowTrue) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.93 });
        return;
      }

      // Pattern 3: Multi-line — auth function name on this line, body is just return true
      // Only scan 3 lines to avoid false suppression from unrelated code below the closing brace
      if (authNamePattern.test(line) && /(function|const|let|var|def|async)\b/.test(line)) {
        const body = lines.slice(index + 1, Math.min(lines.length, index + 4)).join('\n');
        const hasOnlyReturnTrue = /^\s*(return\s+true|return\s+True)\s*;?\s*\n?\s*\}?\s*$/m.test(body);
        const hasRealLogic = /(await|db\.|session|jwt|bcrypt|findUser|findOne|verify|decode|getSession)/i.test(body);
        if (hasOnlyReturnTrue && !hasRealLogic) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.90 });
        }
      }
    });

    return matches;
  },
};

// ─── Secrets hardcoded inside system prompt strings ──────────────────────────
// VIBE_SMELL — System prompts are often stored in source code and version control.
// Embedding API keys, passwords, or internal URLs directly in the prompt text
// leaks them to anyone who reads the code or gets model output about the system prompt.
const LLM_HARDCODED_SYSTEM_PROMPT_SECRET: Rule = {
  id: 'LLM_HARDCODED_SYSTEM_PROMPT_SECRET',
  title: 'Sensitive value hardcoded inside system prompt string',
  description: 'Embedding API keys, passwords, or confidential instructions directly in a system prompt string exposes them in source code, version control history, and potentially in model responses. Store secrets in environment variables and reference them separately from the prompt text.',
  severity: 'HIGH',
  category: 'VIBE_SMELL',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const systemPromptVarRegex = /(system_prompt|systemPrompt|SYSTEM_PROMPT|system_message|systemMessage)\s*[+]?=/i;
    const secretPatternRegex = /(sk-[a-zA-Z0-9]{20,}|password\s*[:=]\s*["'][^"']{4,}|secret\s*[:=]\s*["'][^"']{4,}|api[_-]?key\s*[:=]\s*["'][^"']{8,}|internal[-_.]url|confidential|do\s+not\s+share|bearer\s+[a-zA-Z0-9]{16,})/i;

    lines.forEach((line, index) => {
      if (!systemPromptVarRegex.test(line)) return;

      // Scan this line + next 20 lines (multi-line system prompts)
      const promptBody = lines.slice(index, Math.min(lines.length, index + 20)).join('\n');
      if (secretPatternRegex.test(promptBody)) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.85 });
      }
    });
    return matches;
  },
};

// ─── Agentic code performs irreversible action without human confirmation ─────
// VIBE_SMELL / LLM06:2025 — Autonomous agents that trigger payments, emails,
// or deletes from LLM output without a confirmation step are one bad prompt away
// from an irreversible mistake.
const AI_MISSING_HUMAN_IN_LOOP: Rule = {
  id: 'AI_MISSING_HUMAN_IN_LOOP',
  title: 'Agentic code performs irreversible action from LLM output without human confirmation',
  description: 'Code that takes irreversible real-world actions (sending email, charging a payment, deleting data, posting to social media) based directly on LLM output without a human review or confirmation step is dangerous. A single prompt injection or model hallucination can trigger unrecoverable consequences. Add a human-in-the-loop confirmation gate before executing such actions.',
  severity: 'MEDIUM',
  category: 'VIBE_SMELL',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const llmOutputVars = new Set<string>();

    // Pre-pass: collect LLM output variable names
    lines.forEach((line) => {
      const llmAssign = line.match(
        /(?:const|let|var|)\s*(\w+)\s*=\s*(?:await\s+)?(?:client|openai|anthropic|llm|model|chain|agent)\.(chat|messages|completions|generate|predict|run|invoke)/i
      );
      if (llmAssign) llmOutputVars.add(llmAssign[1]);

      const contentExtract = line.match(/(?:const|let|var|)\s*(\w+)\s*=\s*\w+\.(content|text|output|choices\[0\]\.message\.content)/i);
      if (contentExtract) {
        const sourceVar = line.match(/=\s*(\w+)\./)?.[1];
        if (sourceVar && llmOutputVars.has(sourceVar)) llmOutputVars.add(contentExtract[1]);
      }
    });

    const irreversibleActionRegex = /(send_email|sendEmail|transporter\.send|stripe\.charge|stripe\.payment|db\.delete|deleteOne|deleteMany|\.destroy\s*\(|post.*twitter|post.*social|publishPost|send_message|slack\.post|webhook\.send)\s*\(/i;
    const humanConfirmRegex = /(confirm|human_approval|humanApproval|user_confirms|userConfirms|await.*approve|requiresConfirmation|ask_user|askUser|human_in_loop|hitl)\b/i;

    lines.forEach((line, index) => {
      if (!irreversibleActionRegex.test(line)) return;

      // Check if LLM output is in the args or nearby context
      const ctx = lines.slice(Math.max(0, index - 15), Math.min(lines.length, index + 3)).join('\n');
      const hasLLMContext = [...llmOutputVars].some(v => new RegExp(`\\b${v}\\b`).test(ctx)) ||
        /(response|output|completion|llm_result|generated|ai_output)\b/i.test(ctx);

      if (hasLLMContext && !humanConfirmRegex.test(ctx)) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.70 });
      }
    });
    return matches;
  },
};

// ─── LLM API call inside client-side / browser code ──────────────────────────
// VIBE_SMELL / LLM07:2025 — Calling OpenAI/Anthropic directly from the browser
// exposes your API key to every user, allows unlimited usage at your cost,
// and leaks your system prompts to anyone with DevTools open.
const LLM_PROMPT_IN_CLIENT_CODE: Rule = {
  id: 'LLM_PROMPT_IN_CLIENT_CODE',
  title: "LLM API call in client-side code — exposes API key and system prompt to users",
  description: "Calling an LLM API (OpenAI, Anthropic, Gemini) directly from browser/client-side code exposes your API key in the JavaScript bundle, where any user can extract and abuse it at your expense. It also leaks your system prompt to users who inspect network requests. Always proxy LLM calls through a server-side API route.",
  severity: 'HIGH',
  category: 'VIBE_SMELL',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    // Check if this file contains 'use client' directive or browser-only APIs
    const isClientFile = /['"]use client['"]/i.test(code) ||
      /(window\.|document\.|localStorage\.|sessionStorage\.|navigator\.)/i.test(code);
    if (!isClientFile) return matches;

    const llmApiRegex = /(new\s+OpenAI\s*\(|new\s+Anthropic\s*\(|new\s+GoogleGenerativeAI\s*\(|openai\.chat\.|anthropic\.messages\.|openai\.completions\.|genai\.generate)/i;

    lines.forEach((line, index) => {
      if (llmApiRegex.test(line)) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.88 });
      }
    });
    return matches;
  },
};

// ─── TODO/FIXME adjacent to auth, payment, or authorization code ──────────────
// VIBE_SMELL — A TODO comment directly beside authentication, authorization,
// or payment logic is a critical indicator that the security control is incomplete.
// This is a high-severity escalation of the generic TODO_SECURITY rule.
const AI_TODO_SECURITY_CRITICAL: Rule = {
  id: 'AI_TODO_SECURITY_CRITICAL',
  title: 'TODO/FIXME comment adjacent to authentication, authorization, or payment code',
  description: 'A TODO or FIXME comment found immediately next to authentication, authorization, JWT verification, password hashing, or payment processing code is a strong signal that a critical security control is incomplete or placeholder. These unresolved markers adjacent to security boundaries can leave the application open to authentication bypass or financial fraud.',
  severity: 'HIGH',
  category: 'VIBE_SMELL',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const todoRegex = /\/\/\s*(TODO|FIXME|HACK|XXX)\b|#\s*(TODO|FIXME|HACK|XXX)\b/i;
    const criticalCodeRegex = /(authenticate|authorization|isAuthorized|hasPermission|jwt\.verify|jwtVerify|bcrypt\.compare|bcrypt\.hash|stripe\.(charge|payment|subscription)|checkPermission|verifyToken|validateToken|session\.create|signIn|signUp|createUser)\s*[(\{:=]/i;

    lines.forEach((line, index) => {
      if (!todoRegex.test(line)) return;

      // Check within ±3 lines for critical auth/payment code
      const nearby = lines.slice(Math.max(0, index - 3), Math.min(lines.length, index + 4)).join('\n');
      if (criticalCodeRegex.test(nearby)) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.82 });
      }
    });
    return matches;
  },
};

export const vibeSmellsRules: Rule[] = [
  TODO_SECURITY,
  PLACEHOLDER_AUTH,
  COMMENTED_OUT_SECURITY,
  CONSOLE_LOG_SENSITIVE,
  GENERIC_ERROR_HANDLER,
  HALLUCINATED_IMPORT,
  AUTH_LOGIC_INVERSION,
  SECURITY_CHECK_RETURN_IGNORED,
  LOOSE_EQUALITY_SECURITY,
  AI_STUB_BYPASS,
  ALWAYS_TRUE_AUTH,
  LLM_HARDCODED_SYSTEM_PROMPT_SECRET,
  AI_MISSING_HUMAN_IN_LOOP,
  LLM_PROMPT_IN_CLIENT_CODE,
  AI_TODO_SECURITY_CRITICAL,
];
