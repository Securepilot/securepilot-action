import { Rule, RuleMatch } from './types';

/**
 * Information Disclosure Detection Rules
 * Detects leakage of sensitive information
 */

export const infoDisclosureRules: Rule[] = [
  {
    id: 'info-stack-trace',
    title: 'Stack trace exposed to client',
    description: 'Returning raw stack traces or exception details to the client reveals internal code structure, file paths, library versions, and logic flow that an attacker can use to refine exploits. Stack traces should be logged server-side only; clients should receive generic error messages.',
    severity: 'MEDIUM',
    category: 'INFO_DISCLOSURE',
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];

      lines.forEach((line, index) => {
        if (/res\.(send|json)\s*\(\s*(err|error|e)\.stack|print\s*\(\s*traceback/i.test(line)) {
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
    id: 'info-debug-enabled',
    title: 'Debug mode enabled in production code',
    description: 'Enabling debug mode in production exposes detailed error messages, internal state, interactive debugger consoles, and verbose logging that significantly reduce the cost of exploitation. In frameworks such as Flask, a remotely accessible debugger with code execution is activated.',
    severity: 'MEDIUM',
    category: 'INFO_DISCLOSURE',
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];

      lines.forEach((line, index) => {
        if (/debug\s*:\s*true|DEBUG\s*=\s*True|app\.set\(['"]debug['"],\s*true/i.test(line)) {
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
    id: 'info-sensitive-log',
    title: 'Logging sensitive information',
    description: 'Writing passwords, API keys, tokens, or personally identifiable information to logs creates a secondary exposure surface that is often less protected than primary data stores. Log files may be accessible to third-party log aggregators, developers, or attackers who compromise logging infrastructure.',
    severity: 'MEDIUM',
    category: 'INFO_DISCLOSURE',
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];

      lines.forEach((line, index) => {
        if (/console\.log|logger\.|print\s*\(/i.test(line)) {
          if (/password|token|secret|api[_-]?key|credit[_-]?card|ssn|private[_-]?key/i.test(line)) {
            matches.push({
              line: index + 1,
              codeSnippet: line.trim(),
              confidence: 85,
            });
          }
        }
      });

      return matches;
    },
  },
  {
    id: 'info-directory-listing',
    title: 'Directory listing enabled',
    description: 'An enabled directory listing allows unauthenticated users to enumerate all files and subdirectories served by the web server, exposing configuration files, backup archives, source code, and other sensitive assets. This is a reconnaissance aid that substantially lowers the barrier for further attacks.',
    severity: 'LOW',
    category: 'INFO_DISCLOSURE',
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];

      lines.forEach((line, index) => {
        if (/express\.static.*{.*directory.*:.*true|autoIndex.*:.*true/i.test(line)) {
          matches.push({
            line: index + 1,
            codeSnippet: line.trim(),
            confidence: 80,
          });
        }
      });

      return matches;
    },
  },
  {
    id: 'info-version-exposure',
    title: 'Version information exposed',
    description: 'Exposing server or framework version information via headers such as X-Powered-By allows attackers to quickly identify the exact software version in use and target known CVEs without active probing. Version disclosure is classified as a low-effort reconnaissance vulnerability.',
    severity: 'LOW',
    category: 'INFO_DISCLOSURE',
    languages: ['javascript', 'typescript'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];

      lines.forEach((line, index) => {
        if (/app\.disable\(['"]x-powered-by['"]\)/.test(line)) {
          return; // This is good - they're hiding it
        }
        if (!/app\.disable/.test(code) && /express\(\)|new\s+express/i.test(line)) {
          matches.push({
            line: index + 1,
            codeSnippet: line.trim(),
            confidence: 70,
          });
        }
      });

      return matches;
    },
  },
  {
    id: 'info-comments-secrets',
    title: 'Sensitive information in comments',
    description: 'Embedding credentials, API keys, or tokens in source code comments risks exposure through version control history, code review platforms, or static file serving. Even after removal, sensitive values committed to source control may persist indefinitely in repository history.',
    severity: 'MEDIUM',
    category: 'INFO_DISCLOSURE',
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];

      lines.forEach((line, index) => {
        if (/^[\s]*[/#]+/.test(line)) {
          if (/password|api[_-]?key|secret|token|credential/i.test(line) && /[:=]/.test(line)) {
            matches.push({
              line: index + 1,
              codeSnippet: line.trim(),
              confidence: 75,
            });
          }
        }
      });

      return matches;
    },
  },
  {
    id: 'info-git-folder',
    title: 'Exposing .git folder',
    description: 'Serving the .git directory over HTTP allows attackers to reconstruct the full source repository, including history, credentials, configuration files, and proprietary logic. This is a critical information disclosure vulnerability frequently exploited in automated attacks.',
    severity: 'MEDIUM',
    category: 'INFO_DISCLOSURE',
    languages: ['javascript', 'typescript'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];

      lines.forEach((line, index) => {
        if (/express\.static\s*\([^)]*\)|serve-static/i.test(line)) {
          // Check if there's any .git exclusion
          if (!/.git|dotfiles.*:.*ignore/i.test(code)) {
            matches.push({
              line: index + 1,
              codeSnippet: line.trim(),
              confidence: 70,
            });
          }
        }
      });

      return matches;
    },
  },
];
