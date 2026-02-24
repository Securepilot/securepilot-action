import { AggregatedResult } from './scanner';
import { Finding } from './lib/analyzers/types';

// SARIF 2.1.0 — GitHub Code Scanning standard format
// https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning

const TOOL_VERSION = '1.0.0';
const SECUREPILOT_RULES_URL = 'https://www.securepilot.app/docs/rules';

type SarifLevel = 'error' | 'warning' | 'note' | 'none';

function severityToLevel(severity: string): SarifLevel {
  switch (severity) {
    case 'CRITICAL': return 'error';
    case 'HIGH':     return 'error';
    case 'MEDIUM':   return 'warning';
    case 'LOW':      return 'note';
    default:         return 'none';
  }
}

function severityToRank(severity: string): number {
  switch (severity) {
    case 'CRITICAL': return 100;
    case 'HIGH':     return 75;
    case 'MEDIUM':   return 50;
    case 'LOW':      return 25;
    default:         return 0;
  }
}

export function buildSarif(result: AggregatedResult, workspacePath: string): object {
  // Collect unique rules
  const ruleMap = new Map<string, Finding>();
  for (const finding of result.allFindings) {
    if (!ruleMap.has(finding.ruleId)) {
      ruleMap.set(finding.ruleId, finding);
    }
  }

  const rules = Array.from(ruleMap.values()).map(f => ({
    id: f.ruleId,
    name: f.ruleId,
    shortDescription: { text: f.title },
    fullDescription: { text: f.description ?? f.title },
    helpUri: `${SECUREPILOT_RULES_URL}/${f.ruleId.toLowerCase()}`,
    properties: {
      tags: [f.category, ...(f.cwe ? [f.cwe] : []), ...(f.owasp ? [f.owasp] : [])],
      precision: 'medium',
      'problem.severity': f.severity.toLowerCase(),
      'security-severity': String(severityToRank(f.severity) / 10), // CVSS-like 0–10
    },
  }));

  // Build results
  const sarifResults = result.allFindings.map(f => {
    const relPath = f.relativePath.replace(/\\/g, '/');
    const uri = relPath.startsWith('/') ? relPath.slice(1) : relPath;

    const result: Record<string, unknown> = {
      ruleId: f.ruleId,
      level: severityToLevel(f.severity),
      message: {
        text: f.description
          ? `${f.title}: ${f.description}`
          : f.title,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri,
              uriBaseId: '%SRCROOT%',
            },
            region: {
              startLine: f.line ?? 1,
              startColumn: f.column != null ? f.column + 1 : 1, // SARIF is 1-indexed
            },
          },
        },
      ],
    };

    if (f.codeSnippet) {
      (result as Record<string, unknown>).fingerprints = {
        'securepilot/v1': Buffer.from(`${f.ruleId}:${relPath}:${f.line}:${f.codeSnippet}`).toString('base64').slice(0, 40),
      };
    }

    return result;
  });

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'SecurePilot',
            version: TOOL_VERSION,
            informationUri: 'https://www.securepilot.app',
            rules,
          },
        },
        results: sarifResults,
        originalUriBaseIds: {
          '%SRCROOT%': {
            uri: `file://${workspacePath}/`,
          },
        },
      },
    ],
  };
}
