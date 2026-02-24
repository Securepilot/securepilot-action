import { secretsRules } from './secrets';
import { injectionRules } from './injection';
import { authRules } from './auth';
import { configRules } from './config';
import { validationRules } from './validation';
import { cryptoRules } from './crypto';
import { vibeSmellsRules } from './vibe-smells';
import { ssrfRules } from './ssrf';
import { xxeRules } from './xxe';
import { deserializationRules } from './insecure-deserialization';
import { raceConditionRules } from './race-conditions';
import { infoDisclosureRules } from './information-disclosure';
import { businessLogicRules } from './business-logic';
import { promptInjectionRules } from './prompt-injection';
import { csrfRules } from './csrf';
import { securityHeadersRules } from './security-headers';
import { vulnerableDepsRules } from './vulnerable-deps';
import { pythonFrameworkRules } from './python-frameworks';
import { nextjsSecurityRules } from './nextjs-security';
import { idorExpandedRules } from './idor-expanded';
import { sessionFixationRules } from './session-fixation';
import { Rule, Finding, AnalysisResult, Language } from './types';

// Combine all rules
const allRules: Rule[] = [
  ...secretsRules,
  ...injectionRules,
  ...authRules,
  ...configRules,
  ...validationRules,
  ...cryptoRules,
  ...vibeSmellsRules,
  ...ssrfRules,
  ...xxeRules,
  ...deserializationRules,
  ...raceConditionRules,
  ...infoDisclosureRules,
  ...businessLogicRules,
  // New analyzers
  ...promptInjectionRules,
  ...csrfRules,
  ...securityHeadersRules,
  ...vulnerableDepsRules,
  ...pythonFrameworkRules,
  ...nextjsSecurityRules,
  ...idorExpandedRules,
  ...sessionFixationRules,
];

/**
 * Main analyzer orchestrator
 * Runs all static analysis rules against the provided code
 */
export function analyzeCode(code: string, language: Language): AnalysisResult {
  const lines = code.split('\n');
  const findings: Finding[] = [];

  // Filter rules applicable to this language
  const applicableRules = allRules.filter(rule =>
    rule.languages.includes(language)
  );

  // Run each rule
  for (const rule of applicableRules) {
    try {
      const matches = rule.test(code, lines);

      // Convert matches to findings — carry through standards metadata if present
      for (const match of matches) {
        findings.push({
          severity: rule.severity,
          category: rule.category,
          ruleId: rule.id,
          title: rule.title,
          line: match.line,
          column: match.column,
          codeSnippet: match.codeSnippet,
          confidence: match.confidence,
          ...(rule.description ? { description: rule.description } : {}),
          ...(rule.cwe        ? { cwe:         rule.cwe       } : {}),
          ...(rule.owasp      ? { owasp:       rule.owasp     } : {}),
          ...(rule.owaspLLM   ? { owaspLLM:    rule.owaspLLM  } : {}),
        });
      }
    } catch (error) {
      // Log error but continue with other rules
      console.error(`Error running rule ${rule.id}:`, error);
    }
  }

  // Sort findings by severity (Critical first) and then by line number
  const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
  findings.sort((a, b) => {
    const severityDiff = severityOrder[a.severity] - severityOrder[b.severity];
    if (severityDiff !== 0) return severityDiff;
    return (a.line || 0) - (b.line || 0);
  });

  return {
    findings,
    linesOfCode: lines.length,
    language,
  };
}

// Export rules for testing
export { allRules };
