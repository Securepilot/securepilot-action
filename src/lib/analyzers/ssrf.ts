import { Rule, RuleMatch } from './types';

/**
 * SSRF (Server-Side Request Forgery) Detection Rules
 * Detects vulnerabilities where attackers can make the server perform requests
 */

export const ssrfRules: Rule[] = [
  {
    id: 'ssrf-fetch-user-input',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    title: 'SSRF via fetch() with user input',
    description: 'Server-Side Request Forgery occurs when user-controlled input is passed directly to fetch(), allowing attackers to make the server issue requests to arbitrary internal or external hosts. This can expose internal services, cloud metadata endpoints, and enable data exfiltration or network pivoting.',
    severity: 'HIGH',
    category: 'SSRF',
    languages: ['javascript', 'typescript'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];
      const pattern = /fetch\s*\(\s*(req\.(body|query|params)\.\w+|`\$\{req\.(body|query|params))/i;

      lines.forEach((line, index) => {
        if (pattern.test(line)) {
          matches.push({
            line: index + 1,
            codeSnippet: line.trim(),
            confidence: 90,
          });
        }
      });

      return matches;
    },
  },
  {
    id: 'ssrf-axios-user-input',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    title: 'SSRF via axios with user input',
    description: 'Passing unsanitized user input as the URL to axios requests allows attackers to redirect server-side HTTP calls to internal infrastructure, cloud metadata services, or other unintended targets. Exploitation can lead to unauthorized data access, internal port scanning, and lateral movement within the network.',
    severity: 'HIGH',
    category: 'SSRF',
    languages: ['javascript', 'typescript'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];
      const pattern = /axios\.(get|post|put|delete)\s*\(\s*(req\.(body|query|params)\.\w+|`\$\{req\.(body|query|params))/i;

      lines.forEach((line, index) => {
        if (pattern.test(line)) {
          matches.push({
            line: index + 1,
            codeSnippet: line.trim(),
            confidence: 90,
          });
        }
      });

      return matches;
    },
  },
  {
    id: 'ssrf-url-redirect',
    cwe: 'CWE-601',
    owasp: 'A01:2021',
    title: 'Open redirect vulnerability',
    description: 'An open redirect arises when a server-side redirect target is derived from unvalidated user input, enabling attackers to craft convincing phishing URLs that redirect victims to malicious sites. It is frequently exploited as a trust-abuse vector in OAuth flows and credential harvesting campaigns.',
    severity: 'MEDIUM',
    category: 'SSRF',
    languages: ['javascript', 'typescript'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];
      const pattern = /res\.(redirect|location)\s*\(\s*(req\.(body|query|params)|.*req\.(body|query|params))/i;

      lines.forEach((line, index) => {
        if (pattern.test(line) && !/^https?:\/\//.test(line)) {
          matches.push({
            line: index + 1,
            codeSnippet: line.trim(),
            confidence: 85,
          });
        }
      });

      return matches;
    },
  },
  {
    id: 'ssrf-python-requests',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    title: 'SSRF via Python requests with user input',
    description: 'Using request-supplied values as the URL in Python requests calls enables Server-Side Request Forgery, where an attacker forces the server to fetch arbitrary resources including internal services and cloud instance metadata endpoints. Successful exploitation may lead to credential theft, internal reconnaissance, or remote code execution in cloud environments.',
    severity: 'HIGH',
    category: 'SSRF',
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

        // Pattern 1: Direct inline — requests.get(f"...{request.args...}" or request.args in same call
        const directPattern = /requests\.(get|post|put|delete)\s*\(\s*f["']|requests\.(get|post|put|delete)\s*\(\s*\w+\s*\+/i;
        if (directPattern.test(line) && /request\.|form\.|args\.|json\./i.test(line)) {
          matches.push({ line: index + 1, codeSnippet: line.trim(), confidence: 0.90 });
          return;
        }

        // Pattern 2: Two-line — variable assigned from request input, then passed to requests.get/post
        const callPattern = /requests\.(get|post|put|delete)\s*\(\s*(\w+)\s*[,)]/i;
        const callMatch = line.match(callPattern);
        if (callMatch) {
          const varName = callMatch[2];
          if (userInputVars.has(varName)) {
            matches.push({ line: index + 1, codeSnippet: line.trim(), confidence: 0.92 });
          }
        }
      });

      return matches;
    },
  },
  {
    id: 'ssrf-urllib',
    cwe: 'CWE-918',
    owasp: 'A10:2021',
    title: 'SSRF via urllib with user input',
    description: 'Passing user-controlled data to urllib.request.urlopen() enables attackers to direct the server to issue HTTP or file-scheme requests to arbitrary destinations, including internal network hosts and local files. This constitutes a classic SSRF vulnerability that can expose sensitive infrastructure and bypass network-level access controls.',
    severity: 'HIGH',
    category: 'SSRF',
    languages: ['python'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];
      const pattern = /urllib\.request\.urlopen\s*\(/i;

      lines.forEach((line, index) => {
        if (pattern.test(line) && /request\.|form\.|args\.|json\./i.test(line)) {
          matches.push({
            line: index + 1,
            codeSnippet: line.trim(),
            confidence: 85,
          });
        }
      });

      return matches;
    },
  },
];
