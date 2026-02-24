import { Rule, RuleMatch } from './types';

// Known vulnerable package versions that AI commonly generates
// Format: package name + version pattern that is known-bad
interface VulnPackage {
  name: string;
  // regex to match a pinned version that is known vulnerable
  badVersionRegex: RegExp;
  cve: string;
  description: string;
  fixVersion: string;
}

const KNOWN_VULNERABLE_PACKAGES: VulnPackage[] = [
  {
    name: 'lodash',
    badVersionRegex: /['"]lodash['"]\s*:\s*['"][\^~]?(3\.|4\.[01][0-9]\.|4\.1[0-6]\.)/,
    cve: 'CVE-2021-23337',
    description: 'Prototype pollution via command injection',
    fixVersion: '4.17.21+',
  },
  {
    name: 'axios',
    badVersionRegex: /['"]axios['"]\s*:\s*['"][\^~]?(0\.|1\.[0-5]\.)/,
    cve: 'CVE-2023-45857',
    description: 'CSRF / credential leakage vulnerability',
    fixVersion: '1.6.0+',
  },
  {
    name: 'jsonwebtoken',
    badVersionRegex: /['"]jsonwebtoken['"]\s*:\s*['"][\^~]?([0-7]\.|8\.[0-4]\.)/,
    cve: 'CVE-2022-23529',
    description: 'Arbitrary file read via crafted JWT',
    fixVersion: '9.0.0+',
  },
  {
    name: 'express',
    badVersionRegex: /['"]express['"]\s*:\s*['"][\^~]?(3\.|4\.[01][0-8]\.)/,
    cve: 'CVE-2022-24999',
    description: 'Open redirect and prototype pollution',
    fixVersion: '4.19.0+',
  },
  {
    name: 'node-fetch',
    badVersionRegex: /['"]node-fetch['"]\s*:\s*['"][\^~]?(1\.|2\.[0-5]\.)/,
    cve: 'CVE-2022-0235',
    description: 'URL Redirection to Untrusted Site',
    fixVersion: '2.6.7+ or 3.x',
  },
  {
    name: 'minimist',
    badVersionRegex: /['"]minimist['"]\s*:\s*['"][\^~]?(0\.|1\.[0-1]\.|1\.2\.[0-5])/,
    cve: 'CVE-2021-44906',
    description: 'Prototype pollution',
    fixVersion: '1.2.6+',
  },
  {
    name: 'multer',
    badVersionRegex: /['"]multer['"]\s*:\s*['"][\^~]?(1\.[0-3]\.|1\.4\.[0-4]\.)/,
    cve: 'CVE-2022-24434',
    description: 'Improper input validation in file upload',
    fixVersion: '1.4.5+',
  },
  {
    name: 'qs',
    badVersionRegex: /['"]qs['"]\s*:\s*['"][\^~]?([0-5]\.|6\.[0-9]\.|6\.10\.)/,
    cve: 'CVE-2022-24999',
    description: 'Prototype pollution via crafted query string',
    fixVersion: '6.11.0+',
  },
  {
    name: 'sequelize',
    badVersionRegex: /['"]sequelize['"]\s*:\s*['"][\^~]?([0-4]\.|5\.[0-9]\.)/,
    cve: 'CVE-2019-10748',
    description: 'SQL injection via order parameter',
    fixVersion: '6.x+',
  },
  {
    name: 'moment',
    badVersionRegex: /['"]moment['"]\s*:\s*['"][\^~]?([01]\.|2\.[0-9]\.|2\.[12][0-9]\.)/,
    cve: 'CVE-2022-24785',
    description: 'Path traversal and ReDoS vulnerabilities — use date-fns or dayjs instead',
    fixVersion: '2.29.4+ (or migrate to date-fns/dayjs)',
  },
];

const VULNERABLE_PACKAGE_VERSION: Rule = {
  id: 'VULNERABLE_PACKAGE_VERSION',
  title: 'Known vulnerable package version in use',
  description: 'Using a dependency version with a publicly disclosed CVE exposes the application to known exploits for which proof-of-concept code is often readily available. Outdated packages are among the most commonly exploited attack vectors and should be upgraded to patched versions immediately.',
  severity: 'HIGH',
  category: 'DEPENDENCIES',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      for (const pkg of KNOWN_VULNERABLE_PACKAGES) {
        if (pkg.badVersionRegex.test(line)) {
          matches.push({
            line: index + 1,
            column: 0,
            codeSnippet: line.trim() + ` // ${pkg.cve}: ${pkg.description}. Fix: ${pkg.fixVersion}`,
            confidence: 0.90,
          });
        }
      }
    });
    return matches;
  },
};

// AI-hallucinated typosquatting packages that look real but aren't
const TYPOSQUATTED_PACKAGE: Rule = {
  id: 'TYPOSQUATTED_PACKAGE',
  title: 'Potentially typosquatted or fake package name',
  description: 'Typosquatted packages are malicious npm modules that mimic legitimate package names through slight misspellings, targeting developers and AI code generators that may suggest incorrect names. Installing such a package can result in supply chain compromise, credential theft, or remote code execution.',
  severity: 'HIGH',
  category: 'DEPENDENCIES',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const suspiciousPackages = [
      { bad: 'crossenv', correct: 'cross-env' },
      { bad: 'node-uuid', correct: 'uuid' },
      { bad: 'mongose', correct: 'mongoose' },
      { bad: 'expres', correct: 'express' },
      { bad: 'require-dir', correct: 'require-directory' },
      { bad: 'jsonwebtoken-express', correct: 'express-jwt' },
      { bad: 'bcryptjs-then', correct: 'bcryptjs' },
      { bad: 'socket-io', correct: 'socket.io' },
      { bad: 'eslint-config-airbnb-base-legacy', correct: 'eslint-config-airbnb-base' },
      { bad: 'react-router-v6', correct: 'react-router-dom' },
    ];

    lines.forEach((line, index) => {
      suspiciousPackages.forEach(({ bad, correct }) => {
        const regex = new RegExp(`(from|require|import)\\s*['"]${bad.replace(/-/g, '\\-')}['"]`, 'i');
        if (regex.test(line)) {
          matches.push({
            line: index + 1,
            column: 0,
            codeSnippet: line.trim() + ` // Did you mean: ${correct}?`,
            confidence: 0.88,
          });
        }
      });
    });
    return matches;
  },
};

// Unpinned wildcard versions in package.json (security risk)
const UNPINNED_CRITICAL_DEP: Rule = {
  id: 'UNPINNED_CRITICAL_DEP',
  title: 'Security-critical dependency with wildcard version (*)',
  description: 'Specifying a wildcard (*) version for security-critical packages means any future version — including ones with breaking changes or newly introduced vulnerabilities — may be installed automatically. Pinning exact versions or using ranges with a known minimum ensures reproducible and auditable dependency resolution.',
  severity: 'MEDIUM',
  category: 'DEPENDENCIES',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const criticalPackages = ['jsonwebtoken', 'bcrypt', 'bcryptjs', 'express', 'helmet', 'passport', 'cors'];

    lines.forEach((line, index) => {
      criticalPackages.forEach(pkg => {
        // Wildcard (*) or missing version for security packages
        const regex = new RegExp(`['"]${pkg}['"]\\s*:\\s*['"]\\*['"]`, 'i');
        if (regex.test(line)) {
          matches.push({
            line: index + 1,
            column: 0,
            codeSnippet: line.trim(),
            confidence: 0.85,
          });
        }
      });
    });
    return matches;
  },
};

export const vulnerableDepsRules: Rule[] = [
  VULNERABLE_PACKAGE_VERSION,
  TYPOSQUATTED_PACKAGE,
  UNPINNED_CRITICAL_DEP,
];
