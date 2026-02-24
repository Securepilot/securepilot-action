import { Finding, Severity, Category } from './analyzers/types';

const SEVERITY_DEDUCTIONS: Record<Severity, number> = {
  CRITICAL: 30,
  HIGH: 15,
  MEDIUM: 5,
  LOW: 2,
  INFO: 0,
};

// Categories that represent immediate exploitability and should penalize harder
// when multiple findings of the same category appear (compounding risk)
const HIGH_RISK_CATEGORIES: Set<Category> = new Set([
  'INJECTION',
  'SECRETS',
  'AUTH',
]);

export function calculateSecurityScore(findings: Finding[]): number {
  let score = 100;

  // Count how many findings per high-risk category for compounding penalty
  const categoryCount: Partial<Record<Category, number>> = {};
  for (const finding of findings) {
    categoryCount[finding.category] = (categoryCount[finding.category] ?? 0) + 1;
  }

  for (const finding of findings) {
    let deduction = SEVERITY_DEDUCTIONS[finding.severity];

    // Apply a compounding multiplier for high-risk categories with multiple findings
    // e.g. 3 INJECTION findings → each gets a 1.15× multiplier (15% extra penalty)
    if (HIGH_RISK_CATEGORIES.has(finding.category)) {
      const count = categoryCount[finding.category] ?? 1;
      if (count >= 3) deduction = Math.round(deduction * 1.20);
      else if (count === 2) deduction = Math.round(deduction * 1.10);
    }

    score -= deduction;
  }

  return Math.max(0, Math.min(100, score));
}

export function getScoreLabel(score: number): string {
  if (score >= 90) return 'Excellent';
  if (score >= 70) return 'Good';
  if (score >= 50) return 'Needs Work';
  if (score >= 25) return 'At Risk';
  return 'Critical';
}

export function getScoreColor(score: number): string {
  if (score >= 90) return 'text-success';
  if (score >= 70) return 'text-yellow-500';
  if (score >= 50) return 'text-medium';
  if (score >= 25) return 'text-high';
  return 'text-critical';
}

export function getSeverityCounts(findings: Finding[]) {
  return {
    critical: findings.filter(f => f.severity === 'CRITICAL').length,
    high: findings.filter(f => f.severity === 'HIGH').length,
    medium: findings.filter(f => f.severity === 'MEDIUM').length,
    low: findings.filter(f => f.severity === 'LOW').length,
    info: findings.filter(f => f.severity === 'INFO').length,
  };
}
