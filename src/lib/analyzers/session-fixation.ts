import { Rule, RuleMatch } from './types';

// ─── 1. Session not regenerated after login ───────────────────────────────────
const SESSION_FIXATION_NO_REGENERATE: Rule = {
  id: 'SESSION_FIXATION_NO_REGENERATE',
  title: 'Session not regenerated after successful login — session fixation risk',
  description: 'Failing to regenerate the session identifier upon successful authentication leaves the session ID unchanged before and after login, enabling session fixation attacks. An attacker who plants a known session ID in the victim\'s browser can hijack the authenticated session after the victim logs in.',
  severity: 'HIGH',
  category: 'AUTH',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      const hasLogin = /(login|signin|sign.in|authenticate)\s*\(/i.test(line) ||
        /(req\.session\.user|req\.session\.userId)\s*=/i.test(line);

      if (hasLogin) {
        // Check surrounding context for session.regenerate or session.destroy+create
        const ctx = lines.slice(Math.max(0, index - 3), Math.min(lines.length, index + 10)).join('\n');
        const hasRegenerate = /(session\.regenerate|session\.destroy.*session\.|regenerateSession)/i.test(ctx);
        if (!hasRegenerate) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.70 });
        }
      }
    });
    return matches;
  },
};

// ─── 2. Session ID not rotated on privilege escalation ───────────────────────
const SESSION_NO_ROTATE_ON_PRIVILEGE: Rule = {
  id: 'SESSION_NO_ROTATE_ON_PRIVILEGE',
  title: 'Session ID not rotated after privilege escalation',
  description: 'Elevating a session\'s privilege level without rotating the session ID allows an attacker who obtained the pre-escalation session token to inherit the elevated privileges. Session tokens must be invalidated and reissued whenever the security context of a session changes.',
  severity: 'MEDIUM',
  category: 'AUTH',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      // Detect role elevation without session rotation
      const hasRoleChange = /(req\.session\.role|session\.isAdmin|session\.role)\s*=\s*/i.test(line);
      if (hasRoleChange) {
        const ctx = lines.slice(Math.max(0, index - 2), Math.min(lines.length, index + 8)).join('\n');
        const hasRegenerate = /session\.regenerate/i.test(ctx);
        if (!hasRegenerate) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.68 });
        }
      }
    });
    return matches;
  },
};

// ─── 3. express-session with no resave/saveUninitialized configuration ────────
const SESSION_INSECURE_CONFIG: Rule = {
  id: 'SESSION_INSECURE_CONFIG',
  title: 'express-session with insecure default configuration',
  description: 'Misconfigured express-session options such as missing Secure or HttpOnly cookie flags, improper resave and saveUninitialized settings, or a weak secret can expose session tokens to interception, theft via XSS, or server-side session store exhaustion. Each option has direct security implications and must be explicitly set for production.',
  severity: 'MEDIUM',
  category: 'AUTH',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      const hasSession = /session\s*\(\s*\{/i.test(line);
      if (hasSession) {
        // Check the next 10 lines for secure config options
        const ctx = lines.slice(index, Math.min(lines.length, index + 10)).join('\n');
        const hasSecret = /secret\s*:/i.test(ctx);
        const hasResave = /resave\s*:/i.test(ctx);
        const hasSaveUninitialized = /saveUninitialized\s*:/i.test(ctx);
        const hasSecureCookie = /secure\s*:\s*true/i.test(ctx);
        const hasHttpOnly = /httpOnly\s*:\s*true/i.test(ctx);

        // Flag if missing critical security options
        if (hasSecret && (!hasResave || !hasSaveUninitialized || !hasSecureCookie || !hasHttpOnly)) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.72 });
        }
      }
    });
    return matches;
  },
};

export const sessionFixationRules: Rule[] = [
  SESSION_FIXATION_NO_REGENERATE,
  SESSION_NO_ROTATE_ON_PRIVILEGE,
  SESSION_INSECURE_CONFIG,
];
