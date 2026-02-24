import { Rule, RuleMatch } from './types';

// ─── 1. findById with URL param — no ownership check ────────────────────────
const IDOR_FIND_BY_ID: Rule = {
  id: 'IDOR_FIND_BY_ID',
  title: 'findById() called with URL param — missing ownership verification',
  description: 'Fetching a record by a user-supplied URL parameter without verifying that the authenticated user owns or is authorized to access that record is a classic Insecure Direct Object Reference (IDOR) vulnerability. An attacker can enumerate or guess identifiers to access arbitrary resources belonging to other users.',
  severity: 'HIGH',
  category: 'ACCESS_CONTROL',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      const hasFindById = /\.(findById|findOne|findByPk|findUnique)\s*\(/i.test(line);
      const hasUrlParam = /(req\.params\.|params\.id|params\.userId|params\.accountId|params\.documentId)/i.test(line);
      if (hasFindById && hasUrlParam) {
        const ctx = lines.slice(Math.max(0, index - 5), Math.min(lines.length, index + 5)).join('\n');
        const hasCheck = /(userId\s*[=!]==?|user\.id\s*[=!]==?|\.userId\s*!==?|belongs|owner|authorize)/i.test(ctx);
        if (!hasCheck) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.72 });
        }
      }
    });
    return matches;
  },
};

// ─── 2. DB query using req.params with no auth context ───────────────────────
const IDOR_DB_PARAMS_NO_AUTH: Rule = {
  id: 'IDOR_DB_PARAMS_NO_AUTH',
  title: 'Database query using request parameter without auth context',
  description: 'Issuing database queries whose filter criteria are derived from request parameters without establishing an authenticated session context allows horizontal privilege escalation. Without tying the query to the authenticated user\'s identity, any authenticated or unauthenticated caller can access arbitrary records.',
  severity: 'HIGH',
  category: 'ACCESS_CONTROL',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      const hasQuery = /(\.where\s*\{|\.find\s*\{|WHERE\s+id\s*=|findFirst\s*\()/i.test(line);
      const hasParam = /(req\.params\.|req\.query\.id|params\.id\b)/i.test(line);
      if (hasQuery && hasParam) {
        const ctx = lines.slice(Math.max(0, index - 8), index + 1).join('\n');
        const hasAuth = /(session|req\.user|getToken|currentUser|isAuthenticated|verif)/i.test(ctx);
        if (!hasAuth) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.68 });
        }
      }
    });
    return matches;
  },
};

// ─── 3. File download served from user-supplied path ─────────────────────────
const IDOR_FILE_ACCESS: Rule = {
  id: 'IDOR_FILE_ACCESS',
  title: 'File served from user-supplied path — IDOR or path traversal risk',
  description: 'Serving files using paths derived from user input without both ownership verification and path canonicalization enables two attack classes: IDOR (accessing another user\'s files) and path traversal (escaping the intended directory to read arbitrary server files). Both can result in unauthorized disclosure of sensitive data.',
  severity: 'HIGH',
  category: 'ACCESS_CONTROL',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      const hasFileOp = /(sendFile|createReadStream|readFile|res\.download)\s*\(/i.test(line);
      const hasUserInput = /(req\.params\.|req\.query\.|req\.body\.)/i.test(line);
      if (hasFileOp && hasUserInput) {
        const ctx = lines.slice(Math.max(0, index - 5), index + 1).join('\n');
        const hasAuth = /(session|req\.user|verif|auth|permission)/i.test(ctx);
        const hasPathCheck = /(path\.normalize|startsWith|resolve.*__dirname|allowedPaths)/i.test(ctx);
        if (!hasAuth || !hasPathCheck) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.75 });
        }
      }
    });
    return matches;
  },
};

// ─── 4. Horizontal privilege escalation — userId from body not session ────────
const IDOR_USER_ID_FROM_BODY: Rule = {
  id: 'IDOR_USER_ID_FROM_BODY',
  title: 'userId taken from request body instead of authenticated session',
  description: 'Trusting a userId value sourced from the request body rather than the authenticated session allows an attacker to supply an arbitrary user identifier and perform actions or access data as any account. User identity for authorization decisions must always be derived from the server-verified session.',
  severity: 'CRITICAL',
  category: 'ACCESS_CONTROL',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      // userId/user_id destructured from req.body
      const hasBodyUserId = /(req\.body\.(userId|user_id|uid|account_id|accountId))/i.test(line);
      const hasDbWrite = /(\.update|\.save|\.create|\.insert|\.patch)/i.test(line);
      if (hasBodyUserId) {
        const ctx = lines.slice(Math.max(0, index - 3), Math.min(lines.length, index + 5)).join('\n');
        const hasSessionUserId = /(req\.user\.(id|userId)|session\.userId|currentUser\.id)/i.test(ctx);
        // Flag if body userId used in write operation without cross-checking session userId
        if (!hasSessionUserId || hasDbWrite) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.78 });
        }
      }
    });
    return matches;
  },
};

// ─── 5. Missing ownership check on update/delete ────────────────────────────
const IDOR_UPDATE_NO_OWNER_CHECK: Rule = {
  id: 'IDOR_UPDATE_NO_OWNER_CHECK',
  title: 'Record updated/deleted without verifying resource ownership',
  description: 'Performing update or delete operations using a resource identifier from the request without filtering by the authenticated user\'s ownership allows any authenticated user to modify or destroy records belonging to others. Ownership must be enforced in the database query predicate, not assumed from the application layer.',
  severity: 'HIGH',
  category: 'ACCESS_CONTROL',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      const hasUpdate = /\.(updateOne|deleteOne|updateMany|deleteMany|findByIdAndUpdate|findByIdAndDelete)\s*\(/i.test(line);
      const hasIdParam = /(req\.params\.|params\.id|params\.userId)/i.test(line);
      if (hasUpdate && hasIdParam) {
        const ctx = lines.slice(Math.max(0, index - 8), index + 1).join('\n');
        const hasOwner = /(userId\s*:|userId\s*=|owner:|req\.user\.id|session\.user)/i.test(ctx);
        if (!hasOwner) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.70 });
        }
      }
    });
    return matches;
  },
};

export const idorExpandedRules: Rule[] = [
  IDOR_FIND_BY_ID,
  IDOR_DB_PARAMS_NO_AUTH,
  IDOR_FILE_ACCESS,
  IDOR_USER_ID_FROM_BODY,
  IDOR_UPDATE_NO_OWNER_CHECK,
];
