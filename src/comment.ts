import { AggregatedResult } from './scanner';
import { Finding } from './lib/analyzers/types';

const UTM = 'utm_source=github-action&utm_medium=pr-comment&utm_campaign=ci';
const DASHBOARD_URL = `https://www.securepilot.app?${UTM}`;
const SITE_URL = 'https://www.securepilot.app';

function scoreEmoji(score: number): string {
  if (score >= 90) return '🟢';
  if (score >= 70) return '🟡';
  if (score >= 50) return '🟠';
  return '🔴';
}

function scoreLabel(score: number): string {
  if (score >= 90) return 'Excellent';
  if (score >= 70) return 'Good';
  if (score >= 50) return 'Needs Work';
  if (score >= 25) return 'At Risk';
  return 'Critical';
}

function severityEmoji(severity: string): string {
  switch (severity) {
    case 'CRITICAL': return '🔴';
    case 'HIGH':     return '🟠';
    case 'MEDIUM':   return '🟡';
    case 'LOW':      return '🔵';
    default:         return '⚪';
  }
}

function formatFinding(f: Finding & { relativePath: string }, index: number): string {
  const emoji = severityEmoji(f.severity);
  const location = f.line ? ` (line ${f.line})` : '';
  const cwe = f.cwe ? ` · ${f.cwe}` : '';
  return `${index + 1}. ${emoji} **${f.title}** — \`${f.relativePath}\`${location}${cwe}`;
}

const COMMENT_MARKER = '<!-- securepilot-scan-result -->';

export function buildPrComment(result: AggregatedResult): string {
  const { overallScore, counts, allFindings, totalFiles } = result;
  const emoji = scoreEmoji(overallScore);
  const label = scoreLabel(overallScore);
  const totalIssues = counts.critical + counts.high + counts.medium + counts.low + counts.info;

  // Top findings (up to 5, prioritising critical/high)
  const topFindings = allFindings.slice(0, 5);
  const hiddenCount = allFindings.length - topFindings.length;

  let body = `${COMMENT_MARKER}\n`;
  body += `## 🛡️ SecurePilot Security Scan\n\n`;
  body += `**Score: ${overallScore}/100 ${emoji} ${label}** — ${totalFiles} file${totalFiles !== 1 ? 's' : ''} scanned\n\n`;

  if (totalIssues === 0) {
    body += `✅ **No security issues found.** Great work!\n\n`;
  } else {
    // Severity table
    body += `| Severity | Count |\n|----------|-------|\n`;
    if (counts.critical > 0) body += `| 🔴 Critical | **${counts.critical}** |\n`;
    if (counts.high > 0)     body += `| 🟠 High     | **${counts.high}** |\n`;
    if (counts.medium > 0)   body += `| 🟡 Medium   | ${counts.medium} |\n`;
    if (counts.low > 0)      body += `| 🔵 Low      | ${counts.low} |\n`;
    body += `\n`;

    if (topFindings.length > 0) {
      body += `**Top findings:**\n`;
      topFindings.forEach((f, i) => {
        body += `${formatFinding(f, i)}\n`;
      });
      body += '\n';
    }

    if (hiddenCount > 0) {
      body += `> 💡 *${hiddenCount} more finding${hiddenCount !== 1 ? 's' : ''} not shown.* `;
      body += `[Sign in free to see all findings + get AI-powered fix suggestions →](${DASHBOARD_URL})\n\n`;
    } else if (totalIssues > 0) {
      body += `[🔍 Get AI-powered fix suggestions →](${DASHBOARD_URL})\n\n`;
    }
  }

  body += `<sub>Powered by [SecurePilot](${SITE_URL}) · 165+ security rules including AI/LLM-specific checks · [Free scan](${SITE_URL})</sub>`;

  return body;
}

export { COMMENT_MARKER };
