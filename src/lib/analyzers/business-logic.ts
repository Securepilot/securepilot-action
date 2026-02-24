import { Rule, RuleMatch } from './types';

/**
 * Business Logic Vulnerability Detection Rules
 * Detects flaws in application logic that can lead to abuse
 */

export const businessLogicRules: Rule[] = [
  {
    id: 'logic-price-manipulation',
    title: 'Client-controlled price/amount parameter',
    description: 'Accepting price, total, or amount values directly from client-supplied request parameters allows an attacker to manipulate payment amounts by submitting arbitrarily low or zero values. All financial figures must be computed server-side based on authoritative product data, never trusted from the client.',
    severity: 'CRITICAL',
    category: 'BUSINESS_LOGIC',
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];

      lines.forEach((line, index) => {
        if (/req\.(body|query|params)\.(price|amount|total|cost|quantity)/i.test(line)) {
          // Check if it's used directly in payment/order
          const nextLines = lines.slice(index, Math.min(index + 5, lines.length)).join('\n');
          if (/stripe|paypal|charge|payment|order\.create|transaction/i.test(nextLines)) {
            matches.push({
              line: index + 1,
              codeSnippet: line.trim(),
              confidence: 90,
            });
          }
        }
      });

      return matches;
    },
  },
  {
    id: 'logic-negative-quantity',
    title: 'No validation for negative quantities',
    description: 'Failing to validate that quantity and amount fields are positive integers allows attackers to submit negative values, which can invert transaction logic, generate fraudulent credits, or bypass inventory checks. This is a classic business logic vulnerability that bypasses technical security controls.',
    severity: 'HIGH',
    category: 'BUSINESS_LOGIC',
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];

      lines.forEach((line, index) => {
        if (/quantity|amount|count/i.test(line) && /req\.(body|query|params)/.test(line)) {
          // Check if there's validation in next few lines
          const nextLines = lines.slice(index, Math.min(index + 8, lines.length)).join('\n');
          if (!/>\s*0|>=\s*1|Math\.abs|isPositive/.test(nextLines)) {
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
    id: 'logic-unlimited-credits',
    title: 'No limit on credit/points generation',
    description: 'Credit, points, or balance operations without enforced maximum caps or rate limiting can be exploited to generate unlimited virtual currency through repeated requests or automated abuse. This directly undermines the economic model of the application.',
    severity: 'HIGH',
    category: 'BUSINESS_LOGIC',
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];

      lines.forEach((line, index) => {
        if (/credits?\s*[\+=]|points?\s*[\+=]|balance\s*[\+=]/i.test(line)) {
          // Check if there's rate limiting or max cap
          const contextLines = lines.slice(Math.max(0, index - 5), Math.min(index + 5, lines.length)).join('\n');
          if (!/limit|max|cap|throttle/i.test(contextLines)) {
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
  {
    id: 'logic-discount-stacking',
    title: 'Potential discount code stacking vulnerability',
    description: 'Applying multiple discount codes or promotions to a single transaction without enforcing mutual exclusivity can reduce order totals to zero or negative values, resulting in financial loss. Discount logic must track and enforce per-order and per-user redemption limits.',
    severity: 'MEDIUM',
    category: 'BUSINESS_LOGIC',
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];
      let discountApplications = 0;

      lines.forEach((line, index) => {
        if (/discount|coupon|promo/i.test(line) && /apply|calculate|-=/i.test(line)) {
          discountApplications++;
          if (discountApplications > 1 && !/used|applied|redeemed/.test(code)) {
            matches.push({
              line: index + 1,
              codeSnippet: line.trim(),
              confidence: 65,
            });
          }
        }
      });

      return matches;
    },
  },
  {
    id: 'logic-no-duplicate-check',
    title: 'Missing duplicate transaction check',
    description: 'Creating orders, payments, or bookings without idempotency checks allows attackers or network retries to submit the same transaction multiple times, leading to double-charges, duplicate fulfillment, or fraudulent account credits. Idempotency keys or unique constraint enforcement are required.',
    severity: 'MEDIUM',
    category: 'BUSINESS_LOGIC',
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];

      lines.forEach((line, index) => {
        if (/\.create\(|\.insert\(|\.save\(/i.test(line)) {
          if (/order|payment|transaction|booking|reservation/i.test(line)) {
            const prevLines = lines.slice(Math.max(0, index - 10), index).join('\n');
            if (!/idempotency|unique|duplicate|exists/i.test(prevLines)) {
              matches.push({
                line: index + 1,
                codeSnippet: line.trim(),
                confidence: 70,
              });
            }
          }
        }
      });

      return matches;
    },
  },
  {
    id: 'logic-email-loop',
    title: 'Potential infinite email/notification loop',
    description: 'Triggering email or notification dispatch inside an unbounded loop without a termination condition or send limit creates a denial-of-service risk against the mail infrastructure and recipients. Attackers can exploit this to spam users or exhaust external API quotas.',
    severity: 'MEDIUM',
    category: 'BUSINESS_LOGIC',
    languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];

      lines.forEach((line, index) => {
        if (/sendEmail|send_email|sendNotification|webhook/i.test(line)) {
          const contextLines = lines.slice(Math.max(0, index - 5), Math.min(index + 10, lines.length)).join('\n');
          if (/while|for.*in|forEach|map/.test(contextLines) && !/limit|max|break|return/i.test(contextLines)) {
            matches.push({
              line: index + 1,
              codeSnippet: line.trim(),
              confidence: 65,
            });
          }
        }
      });

      return matches;
    },
  },
];
