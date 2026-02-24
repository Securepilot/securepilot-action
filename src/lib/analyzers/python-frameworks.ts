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

// ─── 1. Django raw() SQL with string formatting ──────────────────────────────
const DJANGO_RAW_SQL: Rule = {
  id: 'DJANGO_RAW_SQL',
  title: 'Django raw() query with string formatting — SQL injection risk',
  description: 'Using Django\'s raw() or execute() with Python string formatting instead of parameterized queries allows user-controlled input to alter the SQL statement structure. This is a direct SQL injection vulnerability that can lead to unauthorized data access, modification, or full database compromise.',
  severity: 'CRITICAL',
  category: 'INJECTION',
  languages: ['python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      const hasRaw = /\.raw\s*\(|\.execute\s*\(/i.test(line);
      const hasFormatting = /(f['"]|\.format\s*\(|%\s*[({]|['"].*%s)/i.test(line);
      if (hasRaw && hasFormatting) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.88 });
      }
    });
    return matches;
  },
};

// ─── 2. Flask debug=True in production code ───────────────────────────────────
const FLASK_DEBUG_TRUE: Rule = {
  id: 'FLASK_DEBUG_TRUE',
  title: 'Flask app running with debug=True — exposes interactive debugger',
  description: 'Running Flask with debug=True in a production environment activates the Werkzeug interactive debugger, which provides an authenticated-but-exploitable Python REPL accessible via the browser. If the debugger PIN is exposed or bypassed, this results in direct remote code execution on the server.',
  severity: 'CRITICAL',
  category: 'CONFIG',
  languages: ['python'],
  test: (code, lines) => {
    const regex = /app\.run\s*\([^)]*debug\s*=\s*True/gi;
    return findMatches(regex, code, lines, 0.97);
  },
};

// ─── 3. FastAPI route missing auth dependency ─────────────────────────────────
const FASTAPI_NO_AUTH: Rule = {
  id: 'FASTAPI_NO_AUTH',
  title: 'FastAPI route missing authentication Depends()',
  description: 'FastAPI routes that omit an authentication dependency are publicly accessible by default, regardless of the sensitivity of the data they expose or the actions they perform. Missing authentication on even a single route can serve as an entry point for unauthorized access or privilege escalation.',
  severity: 'HIGH',
  category: 'AUTH',
  languages: ['python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    // Only relevant in FastAPI apps
    if (!/fastapi|APIRouter|FastAPI/i.test(code)) return matches;

    lines.forEach((line, index) => {
      const isRoute = /@(app|router)\.(get|post|put|delete|patch)\s*\(/i.test(line);
      if (isRoute) {
        // Check if nearby function has Depends() for auth
        const ctx = lines.slice(index, Math.min(lines.length, index + 5)).join('\n');
        const hasAuth = /(Depends\s*\(|current_user|get_current_user|oauth2_scheme|verify_token|require_auth)/i.test(ctx);
        if (!hasAuth) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.68 });
        }
      }
    });
    return matches;
  },
};

// ─── 4. subprocess with shell=True and variable input ────────────────────────
const PYTHON_SUBPROCESS_SHELL: Rule = {
  id: 'PYTHON_SUBPROCESS_SHELL',
  title: 'subprocess with shell=True and dynamic input — command injection',
  description: 'Invoking subprocess with shell=True and incorporating user-controlled data into the command string allows an attacker to inject shell metacharacters that execute arbitrary OS commands. This is a critical OS command injection vulnerability that grants the attacker the full privileges of the server process.',
  severity: 'CRITICAL',
  category: 'INJECTION',
  languages: ['python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      const hasSubprocess = /subprocess\.(run|Popen|call|check_output|check_call)/i.test(line);
      const hasShellTrue = /shell\s*=\s*True/i.test(line);
      const hasFString = /f['"]|\.format\s*\(|%\s*[({]/i.test(line);
      if (hasSubprocess && hasShellTrue && hasFString) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.92 });
      } else if (hasSubprocess && hasShellTrue) {
        // Even without explicit formatting, shell=True alone is high risk
        const ctx = lines.slice(Math.max(0, index - 3), Math.min(lines.length, index + 2)).join('\n');
        const hasUserInput = /(request\.|input\(|argv|environ|body|query|param)/i.test(ctx);
        if (hasUserInput) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.80 });
        }
      }
    });
    return matches;
  },
};

// ─── 5. Django CSRF exempt on view ────────────────────────────────────────────
const DJANGO_CSRF_EXEMPT: Rule = {
  id: 'DJANGO_CSRF_EXEMPT',
  title: 'Django view decorated with @csrf_exempt — CSRF protection disabled',
  description: 'The @csrf_exempt decorator removes Django\'s built-in Cross-Site Request Forgery protection from the decorated view, allowing unauthenticated cross-origin requests to perform state-changing operations on behalf of authenticated users. This exposes any sensitive action on the endpoint to CSRF exploitation.',
  severity: 'HIGH',
  category: 'AUTH',
  languages: ['python'],
  test: (code, lines) => {
    const regex = /@csrf_exempt/gi;
    return findMatches(regex, code, lines, 0.95);
  },
};

// ─── 6. SQLAlchemy text() with string concatenation ──────────────────────────
const SQLALCHEMY_RAW_TEXT: Rule = {
  id: 'SQLALCHEMY_RAW_TEXT',
  title: 'SQLAlchemy text() with string formatting — SQL injection risk',
  description: 'Constructing SQLAlchemy text() expressions using Python string formatting or concatenation embeds user-controlled input directly into the SQL string, bypassing parameterization. This introduces a SQL injection vulnerability that can compromise the confidentiality, integrity, and availability of the database.',
  severity: 'CRITICAL',
  category: 'INJECTION',
  languages: ['python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      const hasText = /\btext\s*\(/i.test(line);
      const hasFormatting = /(f['"]|\.format\s*\(|%\s*[({]|['"].*\+.*['"]\s*\+)/i.test(line);
      if (hasText && hasFormatting) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.88 });
      }
    });
    return matches;
  },
};

export const pythonFrameworkRules: Rule[] = [
  DJANGO_RAW_SQL,
  FLASK_DEBUG_TRUE,
  FASTAPI_NO_AUTH,
  PYTHON_SUBPROCESS_SHELL,
  DJANGO_CSRF_EXEMPT,
  SQLALCHEMY_RAW_TEXT,
];
