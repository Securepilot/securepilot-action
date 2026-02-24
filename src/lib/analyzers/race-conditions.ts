import { Rule, RuleMatch } from './types';

/**
 * Race Condition Detection Rules
 * Detects TOCTOU (Time-of-check to time-of-use) and concurrent access issues
 */

export const raceConditionRules: Rule[] = [
  {
    id: 'race-file-check-use',
    title: 'TOCTOU vulnerability in file operations',
    description: 'Time-of-Check to Time-of-Use (TOCTOU) vulnerabilities occur when a program checks a resource condition and then acts on it after the state may have changed. An attacker can exploit the window between the check and the use to alter the file system, leading to unauthorized access, privilege escalation, or data corruption.',
    severity: 'MEDIUM',
    category: 'RACE_CONDITION',
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];
      let hasFileCheck = false;
      let checkLine = -1;

      lines.forEach((line, index) => {
        // Check for file existence check
        if (/fs\.existsSync|os\.path\.exists|os\.path\.isfile/i.test(line)) {
          hasFileCheck = true;
          checkLine = index;
        }

        // Look for file operations shortly after check
        if (hasFileCheck && index > checkLine && index <= checkLine + 5) {
          if (/fs\.(readFile|writeFile|unlink|rename)|open\s*\(.*['"]w|with\s+open\s*\(/i.test(line)) {
            matches.push({
              line: index + 1,
              codeSnippet: line.trim(),
              confidence: 70,
            });
            hasFileCheck = false; // Reset to avoid duplicate matches
          }
        }
      });

      return matches;
    },
  },
  {
    id: 'race-global-counter',
    title: 'Non-atomic increment on shared counter',
    description: 'Non-atomic read-modify-write operations on shared counters are susceptible to race conditions in concurrent environments, causing lost updates or incorrect state. In security-sensitive contexts such as rate limiters, usage quotas, or financial counters, this can be exploited to exceed intended limits.',
    severity: 'LOW',
    category: 'RACE_CONDITION',
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];

      lines.forEach((line, index) => {
        if (/(\w+)\s*=\s*\1\s*\+\s*1|\+\+\w+|\w+\+\+/i.test(line)) {
          // Check if it's a global or class variable (not inside function parameters)
          const prevLines = lines.slice(Math.max(0, index - 10), index).join('\n');
          if (!/let\s+\w+|const\s+\w+|var\s+\w+/.test(prevLines)) {
            matches.push({
              line: index + 1,
              codeSnippet: line.trim(),
              confidence: 60,
            });
          }
        }
      });

      return matches;
    },
  },
  {
    id: 'race-async-without-lock',
    title: 'Async operation on shared state without locking',
    description: 'Asynchronous functions that read and write shared mutable state without synchronization primitives are vulnerable to race conditions where interleaved execution produces inconsistent results. This can lead to data corruption, authentication bypass, or business logic violations depending on the shared resource.',
    severity: 'MEDIUM',
    category: 'RACE_CONDITION',
    languages: ['javascript', 'typescript'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];
      const hasSharedState = /let\s+\w+\s*=\s*\{|const\s+\w+\s*=\s*\{|var\s+\w+\s*=\s*\{/.test(code);

      if (hasSharedState) {
        lines.forEach((line, index) => {
          if (/async\s+(function|\()|=>\s*{/.test(line)) {
            // Check if it modifies shared state
            const nextLines = lines.slice(index, Math.min(index + 10, lines.length)).join('\n');
            if (/\w+\.\w+\s*=|Object\.assign|\.push\(|\.pop\(/.test(nextLines)) {
              matches.push({
                line: index + 1,
                codeSnippet: line.trim(),
                confidence: 65,
              });
            }
          }
        });
      }

      return matches;
    },
  },
];
