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

// SQL INJECTION RULES

const SQL_INJECTION_CONCAT: Rule = {
  id: 'SQL_INJECTION_CONCAT',
  title: 'SQL query built with string concatenation',
  description: 'Unsanitized user input is interpolated or concatenated directly into a SQL query string. An attacker can manipulate the query to bypass authentication, exfiltrate sensitive data, or destroy the database.',
  severity: 'CRITICAL',
  category: 'INJECTION',
  cwe: 'CWE-89',
  owasp: 'A03:2021',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      // Check for template literals with SQL keywords and interpolation
      const templateLiteralRegex = /`[^`]*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^`]*\$\{[^}]+\}[^`]*`/gi;
      const templateMatches = line.matchAll(templateLiteralRegex);
      for (const match of templateMatches) {
        matches.push({
          line: index + 1,
          column: match.index,
          codeSnippet: line.trim(),
          confidence: 0.95,
        });
      }

      // Check for string concatenation with SQL keywords
      const concatRegex = /(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^;]*(\+|\.concat)/gi;
      const concatMatches = line.matchAll(concatRegex);
      for (const match of concatMatches) {
        matches.push({
          line: index + 1,
          column: match.index,
          codeSnippet: line.trim(),
          confidence: 0.90,
        });
      }
    });

    return matches;
  },
};

const SQL_INJECTION_FSTRING: Rule = {
  id: 'SQL_INJECTION_FSTRING',
  cwe: 'CWE-89',
  owasp: 'A03:2021',
  title: 'SQL query built with f-string (Python)',
  description: 'A Python f-string is used to embed user-controlled values directly into a SQL query. This allows an attacker to inject arbitrary SQL, enabling unauthorized data access, modification, or deletion.',
  severity: 'CRITICAL',
  category: 'INJECTION',
  languages: ['python'],
  test: (code, lines) => {
    const regex = /f["'][^"']*(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE)[^"']*\{[^}]+\}/gi;
    return findMatches(regex, code, lines, 0.95);
  },
};

const NOSQL_INJECTION: Rule = {
  id: 'NOSQL_INJECTION',
  cwe: 'CWE-943',
  owasp: 'A03:2021',
  title: 'Unsanitized input in MongoDB query',
  description: 'User-supplied request data is passed without sanitization into a MongoDB query operator. An attacker can inject query operators to bypass filters, access unauthorized documents, or perform unintended write operations.',
  severity: 'HIGH',
  category: 'INJECTION',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const patterns = [
      /\.(find|findOne)\s*\(\s*\{[^}]*req\.(body|query|params)/gi,
      /\.(updateOne|updateMany|deleteOne|deleteMany)\s*\(\s*\{[^}]*req\./gi,
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

const COMMAND_INJECTION: Rule = {
  id: 'COMMAND_INJECTION',
  cwe: 'CWE-78',
  owasp: 'A03:2021',
  title: 'User input in shell command',
  description: 'User-controlled input is passed unsanitized into a shell command execution function. An attacker can inject additional shell commands, leading to full remote code execution and server compromise.',
  severity: 'CRITICAL',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      // JavaScript/TypeScript patterns
      const jsPatterns = [
        /(exec|execSync|spawn)\s*\([^)]*(\$\{|req\.|input|args|user|params)/gi,
        /(exec|execSync|spawn)\s*\(`[^`]*\$\{/gi,
      ];

      // Python patterns
      const pyPatterns = [
        /(os\.system|subprocess\.run|subprocess\.call|popen)\s*\([^)]*f['"]/gi,
        /(os\.system|subprocess\.run|subprocess\.call|popen)\s*\([^)]*\+/gi,
      ];

      const allPatterns = [...jsPatterns, ...pyPatterns];

      allPatterns.forEach(pattern => {
        const lineMatches = line.matchAll(pattern);
        for (const match of lineMatches) {
          matches.push({
            line: index + 1,
            column: match.index,
            codeSnippet: line.trim(),
            confidence: 0.95,
          });
        }
      });
    });

    return matches;
  },
};

const EVAL_USAGE: Rule = {
  id: 'EVAL_USAGE',
  title: 'Use of eval() with dynamic input',
  description: 'The eval() function executes a string as code, and any user-influenced string passed to it becomes arbitrary code execution. This is one of the most dangerous patterns in JavaScript and Python, enabling complete application takeover.',
  severity: 'CRITICAL',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const evalRegex = /\beval\s*\(/gi;

    lines.forEach((line, index) => {
      const lineMatches = line.matchAll(evalRegex);
      for (const match of lineMatches) {
        // Higher confidence if we see user input indicators
        const hasUserInput = /(req\.|input|params|query|body|args|user)/i.test(line);
        const confidence = hasUserInput ? 0.98 : 0.85;

        matches.push({
          line: index + 1,
          column: match.index,
          codeSnippet: line.trim(),
          confidence,
        });
      }
    });

    return matches;
  },
};

// ─── eval() / new Function() with direct user input (RCE) ────────────────────
const EVAL_USER_INPUT: Rule = {
  id: 'EVAL_USER_INPUT',
  cwe: 'CWE-95',
  owasp: 'A03:2021',
  title: 'eval() or new Function() called with user-controlled input — Remote Code Execution',
  description: 'User-controlled input is directly passed to eval() or new Function(), which evaluates it as executable code at runtime. This constitutes a Remote Code Execution (RCE) vulnerability, giving an attacker full control over the server process.',
  severity: 'CRITICAL',
  category: 'INJECTION',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      // eval(req.*) or new Function(req.*)
      const hasEvalWithInput =
        /\beval\s*\(\s*(req\.(body|query|params|headers)|userInput|input)\b/.test(line) ||
        /new\s+Function\s*\([^)]*req\.(body|query|params|headers)/.test(line);

      // Also track: variable from req.* fed into eval on same or nearby lines
      const hasEvalVar = /\beval\s*\(\s*\w+\s*\)/.test(line) || /new\s+Function\s*\(/.test(line);
      if (hasEvalVar) {
        const ctx = lines.slice(Math.max(0, index - 5), index + 1).join('\n');
        const varName = line.match(/\beval\s*\(\s*(\w+)\s*\)/)?.[1] ||
                        line.match(/new\s+Function\s*\(\s*(\w+)/)?.[1];
        if (varName) {
          const isFromReq = new RegExp(`${varName}\\s*=.*req\\.(body|query|params)`).test(ctx);
          if (isFromReq) {
            matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.97 });
            return;
          }
        }
      }

      if (hasEvalWithInput) {
        matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.98 });
      }
    });

    return matches;
  },
};

// ─── __dirname / path.join with user input without bounds check ───────────────
// More specific variant of PATH_TRAVERSAL targeting __dirname patterns
const DIRNAME_USER_INPUT: Rule = {
  id: 'DIRNAME_USER_INPUT',
  title: 'File path built from __dirname + user input without traversal protection',
  description: 'A file path is constructed by joining __dirname with user-supplied input without validating that the resolved path stays within the intended directory. An attacker can supply sequences such as ../../etc/passwd to read arbitrary files outside the application root.',
  severity: 'HIGH',
  category: 'INJECTION',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      // Pattern: path.join(__dirname, ..., req.*/userVar) without normalize/bounds check
      const hasDirname = /__dirname/.test(line);
      const hasPathOp = /path\.(join|resolve)\s*\(/.test(line);
      const hasUserInput = /req\.(query|params|body|headers)/.test(line);

      if (hasDirname && hasPathOp && hasUserInput) {
        // Check if bounds check exists nearby
        const ctx = lines.slice(Math.max(0, index - 2), Math.min(lines.length, index + 4)).join('\n');
        const hasBoundsCheck = /(startsWith|normalize|\.includes\('\.\.'|path\.resolve.*startsWith)/i.test(ctx);
        if (!hasBoundsCheck) {
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

const TEMPLATE_INJECTION: Rule = {
  id: 'TEMPLATE_INJECTION',
  cwe: 'CWE-94',
  owasp: 'A03:2021',
  title: 'Unescaped template rendering',
  description: 'User-controlled data is rendered through an unescaped template syntax that outputs raw HTML. This enables reflected or stored cross-site scripting (XSS) attacks, allowing an attacker to execute malicious scripts in the victim\'s browser.',
  severity: 'HIGH',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const patterns = [
      /\{\{[^}]*\}\}/g,  // Handlebars/Jinja2 unescaped
      /<%[-=][^>]*%>/g,  // EJS unescaped
      /\{!![^}]*!!\}/g,  // Blade unescaped
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
            confidence: 0.75,
          });
        }
      });
    });

    return matches;
  },
};

const XPATH_INJECTION: Rule = {
  id: 'XPATH_INJECTION',
  cwe: 'CWE-643',
  owasp: 'A03:2021',
  title: 'XPath with user input',
  description: 'User-supplied input is concatenated into an XPath expression without escaping. An attacker can craft malicious XPath to bypass authentication checks or extract the full contents of an XML document, including sensitive fields.',
  severity: 'HIGH',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const patterns = [
      /xpath\s*\([^)]*\+/gi,
      /xpath\s*\([^)]*\$\{/gi,
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

const LDAP_INJECTION: Rule = {
  id: 'LDAP_INJECTION',
  cwe: 'CWE-90',
  owasp: 'A03:2021',
  title: 'LDAP query with unsanitized input',
  description: 'User input is embedded directly into an LDAP filter or distinguished name without sanitization. An attacker can inject LDAP metacharacters to bypass authentication logic or enumerate and extract entries from the directory.',
  severity: 'HIGH',
  category: 'INJECTION',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const regex = /(ldap|LDAP)[^;]*\([^)]*(\+|\$\{)/gi;
    return findMatches(regex, code, lines, 0.80);
  },
};

// XSS RULES

const XSS_INNERHTML: Rule = {
  id: 'XSS_INNERHTML',
  cwe: 'CWE-79',
  owasp: 'A03:2021',
  title: 'innerHTML with dynamic content',
  description: 'Dynamic content is assigned to innerHTML without HTML encoding, allowing arbitrary markup to be injected into the DOM. If user-controlled data reaches this sink, an attacker can execute JavaScript in the context of the victim\'s browser session.',
  severity: 'HIGH',
  category: 'XSS',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const regex = /\.innerHTML\s*=\s*(?!['"]<)/gi;

    lines.forEach((line, index) => {
      const lineMatches = line.matchAll(regex);
      for (const match of lineMatches) {
        // Check if it's not a static string
        const afterEquals = line.slice((match.index || 0) + match[0].length);
        const isStaticString = /^\s*['"]/.test(afterEquals);

        if (!isStaticString) {
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

const XSS_DANGEROUSLY_SET: Rule = {
  id: 'XSS_DANGEROUSLY_SET',
  cwe: 'CWE-79',
  owasp: 'A03:2021',
  title: 'dangerouslySetInnerHTML usage',
  description: 'React\'s dangerouslySetInnerHTML bypasses the framework\'s XSS protections by injecting raw HTML directly into the DOM. If the value contains unsanitized user input, an attacker can execute arbitrary scripts in the victim\'s browser.',
  severity: 'HIGH',
  category: 'XSS',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const regex = /dangerouslySetInnerHTML/gi;
    return findMatches(regex, code, lines, 0.85);
  },
};

const XSS_DOCUMENT_WRITE: Rule = {
  id: 'XSS_DOCUMENT_WRITE',
  cwe: 'CWE-79',
  owasp: 'A03:2021',
  title: 'document.write with variables',
  description: 'Dynamic values are written to the document using document.write, which can inject arbitrary HTML and script tags into the page. When user-controlled data flows into this call, it enables reflected cross-site scripting (XSS).',
  severity: 'HIGH',
  category: 'XSS',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const regex = /document\.write\s*\((?!['"])/gi;

    lines.forEach((line, index) => {
      const lineMatches = line.matchAll(regex);
      for (const match of lineMatches) {
        matches.push({
          line: index + 1,
          column: match.index,
          codeSnippet: line.trim(),
          confidence: 0.88,
        });
      }
    });

    return matches;
  },
};

const XSS_JQUERY_HTML: Rule = {
  id: 'XSS_JQUERY_HTML',
  cwe: 'CWE-79',
  owasp: 'A03:2021',
  title: 'jQuery .html() with dynamic content',
  description: 'jQuery\'s .html() method sets raw HTML content on matched elements without escaping. Passing user-controlled data to this method allows an attacker to inject and execute malicious scripts in the victim\'s browser.',
  severity: 'MEDIUM',
  category: 'XSS',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const regex = /\$\([^)]*\)\.html\s*\((?!['"])/gi;

    lines.forEach((line, index) => {
      const lineMatches = line.matchAll(regex);
      for (const match of lineMatches) {
        matches.push({
          line: index + 1,
          column: match.index,
          codeSnippet: line.trim(),
          confidence: 0.80,
        });
      }
    });

    return matches;
  },
};

const XSS_URL_PARAMS: Rule = {
  id: 'XSS_URL_PARAMS',
  title: 'URL parameters rendered without sanitization',
  description: 'Values read from URL search parameters or query strings are inserted into the DOM without encoding. An attacker can craft a malicious URL that, when visited, causes arbitrary JavaScript to execute in the victim\'s browser.',
  severity: 'MEDIUM',
  category: 'XSS',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      const hasUrlParam = /(searchParams|URLSearchParams|query\.)/.test(line);
      const hasDomInsertion = /(innerHTML|innerText|textContent|\.html\(|\.append|\.prepend)/.test(line);

      if (hasUrlParam && hasDomInsertion) {
        matches.push({
          line: index + 1,
          codeSnippet: line.trim(),
          confidence: 0.75,
        });
      }
    });

    return matches;
  },
};

// ─── Reflected XSS via res.send / res.write with template literal ─────────────
// Pattern: `<div>${req.query/body/params.*}</div>` passed to res.send/write
const XSS_REFLECTED_RESPONSE: Rule = {
  id: 'XSS_REFLECTED_RESPONSE',
  title: 'User input reflected into HTTP response without sanitization',
  description: 'User-controlled input from request parameters or body is embedded in the HTTP response body without encoding. This creates a reflected XSS vulnerability where an attacker can craft a request that causes a victim\'s browser to execute arbitrary scripts.',
  severity: 'CRITICAL',
  category: 'XSS',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    // Multi-line aware: look for template literals containing req.* on same line
    // or variable assignments that flow into res.send
    lines.forEach((line, index) => {
      // Pattern 1: res.send/write/end with a template literal containing req.*
      const directSend = /res\.(send|write|end|html)\s*\(.*`[^`]*\$\{[^}]*(req\.(query|body|params|headers)|userInput|searchParams)[^}]*\}/.test(line);

      // Pattern 2: template literal with req.* assigned to a variable used in res.send on same line
      const templateWithReq = /`[^`]*\$\{[^}]*(req\.(query|body|params|headers))[^}]*\}[^`]*`/.test(line)
        && /res\.(send|write|end|html)/.test(line);

      // Pattern 4: string concatenation with req.* inside res.send/write/end/html
      // e.g. res.send('<h1>' + req.query.name + '</h1>')
      const concatSend = /res\.(send|write|end|html)\s*\([^)]*(\+|concat)\s*(req\.(query|body|params|headers)|userInput)/.test(line)
        || /res\.(send|write|end|html)\s*\([^)]*(req\.(query|body|params|headers)|userInput)[^)]*(\+|concat)/.test(line);

      // Pattern 3: standalone template literal with req.* (flagged when res.send is within 3 lines)
      const hasTemplateReq = /const\s+\w+\s*=\s*`[^`]*\$\{[^}]*(req\.(query|body|params|headers))[^}]*\}/.test(line);
      if (hasTemplateReq) {
        // Look ahead for res.send within 3 lines
        const lookahead = lines.slice(index, Math.min(lines.length, index + 4)).join('\n');
        if (/res\.(send|write|end|html)\s*\(/.test(lookahead)) {
          matches.push({
            line: index + 1,
            column: 0,
            codeSnippet: line.trim(),
            confidence: 0.90,
          });
          return;
        }
      }

      if (directSend || templateWithReq || concatSend) {
        matches.push({
          line: index + 1,
          column: 0,
          codeSnippet: line.trim(),
          confidence: 0.92,
        });
      }
    });

    return matches;
  },
};

// ─── Path Traversal: user input flowing into file system operations ───────────
const PATH_TRAVERSAL: Rule = {
  id: 'PATH_TRAVERSAL',
  cwe: 'CWE-22',
  owasp: 'A01:2021',
  title: 'User input used in file path without sanitization — path traversal risk',
  description: 'User-supplied input is used to construct a file system path that is passed to a file operation without validating that it remains within the intended base directory. An attacker can supply path traversal sequences such as ../ to read, write, or delete arbitrary files on the server.',
  severity: 'CRITICAL',
  category: 'INJECTION',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    // Track variable names that hold req.query/params/body values
    const userInputVars = new Set<string>();

    lines.forEach((line, index) => {
      // Collect variables assigned from req.query/params/body
      const assignMatch = line.match(/(?:const|let|var)\s+(\w+)\s*=\s*req\.(query|params|body)\b/);
      if (assignMatch) {
        userInputVars.add(assignMatch[1]);
      }
      const destructureMatch = line.matchAll(/(?:const|let|var)\s*\{\s*([^}]+)\s*\}\s*=\s*req\.(query|params|body)/g);
      for (const m of destructureMatch) {
        m[1].split(',').forEach(v => userInputVars.add(v.trim().split(':')[0].trim()));
      }

      // Check for file operations with user input directly or via tracked vars
      const fileOps = /(sendFile|readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|rmdir|mkdir|access)\s*\(/i;
      const pathJoin = /path\.(join|resolve|normalize)\s*\(/i;

      if (!fileOps.test(line) && !pathJoin.test(line)) return;

      // Direct req.* in file op
      const hasDirectReq = /req\.(query|params|body)\b/.test(line);

      // Variable from req.* used in file op
      const hasTrackedVar = Array.from(userInputVars).some(v => {
        const varRegex = new RegExp(`\\b${v}\\b`);
        return varRegex.test(line);
      });

      // path.join without a subsequent bounds check — look for path.normalize + startsWith
      if ((hasDirectReq || hasTrackedVar) && (fileOps.test(line) || pathJoin.test(line))) {
        // Check if there's a bounds check in nearby lines
        const ctx = lines.slice(Math.max(0, index - 2), Math.min(lines.length, index + 5)).join('\n');
        const hasBoundsCheck = /(\.startsWith\(|path\.normalize|\.resolve\(|\.includes\('\.\.'|normalize.*startsWith)/i.test(ctx);

        if (!hasBoundsCheck) {
          matches.push({
            line: index + 1,
            column: 0,
            codeSnippet: line.trim(),
            confidence: 0.88,
          });
        }
      }
    });

    return matches;
  },
};

// ─── Python command injection: os.popen/os.system with variable from user input ─
const PYTHON_COMMAND_INJECTION_VAR: Rule = {
  id: 'PYTHON_CMD_INJECTION_VAR',
  cwe: 'CWE-78',
  owasp: 'A03:2021',
  title: 'Python command injection — variable from user input passed to os.popen/os.system',
  description: 'A variable holding user-supplied input is passed directly to `os.popen()`, `os.system()`, or `subprocess` without sanitization. This allows an attacker to inject arbitrary shell commands by appending semicolons, pipes, or backticks to the input.',
  severity: 'CRITICAL',
  category: 'INJECTION',
  languages: ['python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    // Track variables assigned from Flask/Django request input
    const userInputVars = new Set<string>();

    lines.forEach((line, index) => {
      // Collect variables from request.args/form/json/GET/POST
      const assignPatterns = [
        /(\w+)\s*=\s*request\.(args|form|json|get|post|data)\.(get\s*\(|['"]\w)/i,
        /(\w+)\s*=\s*request\.args\.get\s*\(/i,
        /(\w+)\s*=\s*(?:request|req)\.(args|form|json)\[/i,
      ];
      for (const pat of assignPatterns) {
        const m = line.match(pat);
        if (m) userInputVars.add(m[1]);
      }

      // Check for os.popen/os.system/subprocess with tracked variable
      const cmdPattern = /\b(os\.popen|os\.system|subprocess\.run|subprocess\.call|subprocess\.Popen)\s*\((\w+)/i;
      const cmdMatch = line.match(cmdPattern);
      if (cmdMatch) {
        const varName = cmdMatch[2];
        if (userInputVars.has(varName)) {
          matches.push({ line: index + 1, codeSnippet: line.trim(), confidence: 0.95 });
        }
      }
    });

    return matches;
  },
};

// ─── Python path traversal via os.path.join with user input variable ─────────
const PYTHON_PATH_TRAVERSAL: Rule = {
  id: 'PYTHON_PATH_TRAVERSAL',
  cwe: 'CWE-22',
  owasp: 'A01:2021',
  title: 'Python path traversal — user input used in os.path.join without sanitization',
  description: 'A variable holding user-supplied input is passed to `os.path.join()` or used to construct file paths without validating that the resulting path stays within the intended directory. An attacker can supply `../../etc/passwd` sequences to read arbitrary server files.',
  severity: 'HIGH',
  category: 'INJECTION',
  languages: ['python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const userInputVars = new Set<string>();

    lines.forEach((line, index) => {
      // Track request input variables
      const assignPatterns = [
        /(\w+)\s*=\s*request\.(args|form|json|get|post|data)\.(get\s*\(|['"]\w)/i,
        /(\w+)\s*=\s*request\.args\.get\s*\(/i,
      ];
      for (const pat of assignPatterns) {
        const m = line.match(pat);
        if (m) userInputVars.add(m[1]);
      }

      // Check os.path.join with tracked variable
      const pathPattern = /os\.path\.(join|abspath)\s*\([^)]+,\s*(\w+)\s*\)/;
      const pathMatch = line.match(pathPattern);
      if (pathMatch) {
        const varName = pathMatch[2];
        // Check context for basename/normpath sanitization
        const ctx = lines.slice(Math.max(0, index - 5), index + 2).join('\n');
        const hasSanitization = /(basename|normpath|\.startswith|os\.path\.abspath.*startswith)/i.test(ctx);
        if (userInputVars.has(varName) && !hasSanitization) {
          matches.push({ line: index + 1, codeSnippet: line.trim(), confidence: 0.88 });
        }
      }
    });

    return matches;
  },
};

export const injectionRules: Rule[] = [
  SQL_INJECTION_CONCAT,
  SQL_INJECTION_FSTRING,
  NOSQL_INJECTION,
  COMMAND_INJECTION,
  PYTHON_COMMAND_INJECTION_VAR,
  PYTHON_PATH_TRAVERSAL,
  EVAL_USAGE,
  EVAL_USER_INPUT,
  TEMPLATE_INJECTION,
  XPATH_INJECTION,
  LDAP_INJECTION,
  XSS_INNERHTML,
  XSS_DANGEROUSLY_SET,
  XSS_DOCUMENT_WRITE,
  XSS_JQUERY_HTML,
  XSS_URL_PARAMS,
  XSS_REFLECTED_RESPONSE,
  PATH_TRAVERSAL,
  DIRNAME_USER_INPUT,
];
