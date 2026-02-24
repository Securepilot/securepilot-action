import { Rule, RuleMatch, Language } from './types';

// Helper function to find all regex matches with line numbers
function findMatches(regex: RegExp, code: string, lines: string[], confidence: number = 0.95): RuleMatch[] {
  const matches: RuleMatch[] = [];
  const globalRegex = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : regex.flags + 'g');

  lines.forEach((line, index) => {
    const lineMatches = line.matchAll(globalRegex);
    for (const match of lineMatches) {
      matches.push({
        line: index + 1,
        column: match.index,
        codeSnippet: line.trim(),
        confidence,
      });
    }
  });

  return matches;
}

const HARDCODED_AWS_KEY: Rule = {
  id: 'HARDCODED_AWS_KEY',
  cwe: 'CWE-798',
  owasp: 'A07:2021',
  title: 'AWS Access Key hardcoded',
  description: 'An AWS Access Key ID matching Amazon\'s known prefix format is hardcoded in source code. Anyone with read access to the repository can use this credential to authenticate to AWS services and access or modify cloud resources.',
  severity: 'CRITICAL',
  category: 'SECRETS',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const regex = /AKIA[0-9A-Z]{16}/g;
    return findMatches(regex, code, lines, 0.99);
  },
};

const HARDCODED_AWS_SECRET: Rule = {
  id: 'HARDCODED_AWS_SECRET',
  cwe: 'CWE-798',
  owasp: 'A07:2021',
  title: 'AWS Secret Key hardcoded',
  description: 'An AWS Secret Access Key is hardcoded in source code alongside its key identifier. Combined with the Access Key ID, this credential grants full programmatic access to AWS APIs, enabling resource theft, data exfiltration, or destructive actions.',
  severity: 'CRITICAL',
  category: 'SECRETS',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const regex = /aws_secret_access_key\s*[=:]\s*['"][A-Za-z0-9/+=]{40}['"]/gi;
    return findMatches(regex, code, lines, 0.99);
  },
};

const HARDCODED_GENERIC_SECRET: Rule = {
  id: 'HARDCODED_GENERIC_SECRET',
  cwe: 'CWE-798',
  owasp: 'A07:2021',
  title: 'Generic secret/password in code',
  description: 'A variable named password, secret, API key, or token is assigned a literal string value directly in source code. Hardcoded credentials are trivially extracted from version control history and can be exploited long after they appear to have been removed.',
  severity: 'HIGH',
  category: 'SECRETS',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const regex = /(password|secret|api_key|apikey|token|private_key)\s*[=:]\s*['"][^'"]{8,}['"]/gi;
    const matches: RuleMatch[] = [];

    // Exclude common false positives
    const falsePositives = [
      'placeholder', 'your-key-here', 'changeme', 'your-secret',
      'your-password', 'your-api-key', 'enter-your', 'xxx',
      'process.env', 'env.', '${', 'example', 'test', 'sample'
    ];

    lines.forEach((line, index) => {
      const lineMatches = line.matchAll(new RegExp(regex.source, regex.flags));
      for (const match of lineMatches) {
        const matchText = match[0].toLowerCase();
        const isFalsePositive = falsePositives.some(fp => matchText.includes(fp));

        if (!isFalsePositive) {
          matches.push({
            line: index + 1,
            column: match.index,
            codeSnippet: line.trim(),
            confidence: 0.85,
          });
        }
      }
    });

    return matches;
  },
};

const HARDCODED_JWT: Rule = {
  id: 'HARDCODED_JWT',
  cwe: 'CWE-798',
  owasp: 'A07:2021',
  title: 'JWT token hardcoded',
  description: 'A JSON Web Token is hardcoded in the source code, which may represent a long-lived session or service credential. An attacker who obtains this token can impersonate the associated identity or escalate privileges without needing to authenticate.',
  severity: 'HIGH',
  category: 'SECRETS',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const regex = /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/g;
    return findMatches(regex, code, lines, 0.95);
  },
};

const HARDCODED_PRIVATE_KEY: Rule = {
  id: 'HARDCODED_PRIVATE_KEY',
  cwe: 'CWE-321',
  owasp: 'A07:2021',
  title: 'Private key in source',
  description: 'A PEM-encoded private key (RSA, EC, or DSA) is embedded directly in source code. Exposure of a private key allows an attacker to impersonate the key owner, decrypt protected communications, or forge digital signatures.',
  severity: 'CRITICAL',
  category: 'SECRETS',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const regex = /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/g;
    return findMatches(regex, code, lines, 1.0);
  },
};

const HARDCODED_DB_CONNECTION: Rule = {
  id: 'HARDCODED_DB_CONNECTION',
  cwe: 'CWE-798',
  owasp: 'A07:2021',
  title: 'Database connection string with credentials',
  description: 'A database connection URI containing a username and password is hardcoded in source code. Anyone with access to the codebase can use these credentials to connect directly to the database and read, modify, or destroy its contents.',
  severity: 'CRITICAL',
  category: 'SECRETS',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const regex = /(mongodb|postgres|mysql|redis):\/\/[^:]+:[^@]+@/gi;
    return findMatches(regex, code, lines, 0.95);
  },
};

const GOOGLE_API_KEY: Rule = {
  id: 'GOOGLE_API_KEY',
  cwe: 'CWE-798',
  owasp: 'A07:2021',
  title: 'Google API key',
  description: 'A Google API key matching the known AIza prefix is hardcoded in source code. Exposed API keys can be abused to make authenticated requests on behalf of the key owner, potentially incurring significant financial charges or accessing restricted Google services.',
  severity: 'HIGH',
  category: 'SECRETS',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const regex = /AIza[0-9A-Za-z-_]{35}/g;
    return findMatches(regex, code, lines, 0.98);
  },
};

const STRIPE_SECRET_KEY: Rule = {
  id: 'STRIPE_SECRET_KEY',
  cwe: 'CWE-798',
  owasp: 'A07:2021',
  title: 'Stripe secret key',
  description: 'A Stripe secret API key is hardcoded in source code. This key provides full access to the Stripe account, enabling an attacker to initiate charges, issue refunds, access customer payment data, or exfiltrate financial information.',
  severity: 'CRITICAL',
  category: 'SECRETS',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const regex = /sk_(live|test)_[0-9a-zA-Z]{24,}/g;
    return findMatches(regex, code, lines, 0.99);
  },
};

const GITHUB_TOKEN: Rule = {
  id: 'GITHUB_TOKEN',
  cwe: 'CWE-798',
  owasp: 'A07:2021',
  title: 'GitHub personal access token',
  description: 'A GitHub personal access token (PAT) matching the ghp_ or ghs_ format is hardcoded in source code. This token can be used to access private repositories, modify code, read secrets, and perform administrative actions on GitHub organizations and accounts.',
  severity: 'CRITICAL',
  category: 'SECRETS',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const regex = /gh[ps]_[A-Za-z0-9_]{36,}/g;
    return findMatches(regex, code, lines, 0.99);
  },
};

// ─── OpenAI API key — dedicated CRITICAL rule (most common in AI-generated code) ─
const OPENAI_API_KEY: Rule = {
  id: 'OPENAI_API_KEY',
  cwe: 'CWE-798',
  owasp: 'A07:2021',
  title: 'OpenAI API key hardcoded in source',
  description: 'An OpenAI API key is hardcoded in source code rather than loaded from an environment variable or secret store. An attacker who obtains this key can consume API quota at the owner\'s expense and access any data processed through the associated account.',
  severity: 'CRITICAL',
  category: 'SECRETS',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    // OpenAI key formats: sk-<20+ chars>, sk-proj-<20+ chars>, sk-svcacct-<20+ chars>
    const openaiKeyRegex = /sk-(proj-|svcacct-)?[A-Za-z0-9_-]{20,}/g;

    lines.forEach((line, index) => {
      // Skip lines that look like env var usage or placeholders
      if (/process\.env|os\.environ|getenv|your[_\-]?key|<.*>|placeholder|example|sk_live|sk_test/i.test(line)) return;

      const lineMatches = line.matchAll(new RegExp(openaiKeyRegex.source, 'g'));
      for (const match of lineMatches) {
        matches.push({
          line: index + 1,
          column: match.index,
          codeSnippet: line.trim(),
          confidence: 0.97,
        });
      }
    });

    return matches;
  },
};

// ─── Anthropic API key ─────────────────────────────────────────────────────────
const ANTHROPIC_API_KEY: Rule = {
  id: 'ANTHROPIC_API_KEY',
  cwe: 'CWE-798',
  owasp: 'A07:2021',
  title: 'Anthropic API key hardcoded in source',
  description: 'An Anthropic API key is hardcoded in source code rather than loaded from an environment variable or secret store. Exposure allows unauthorized use of the API at the account owner\'s expense and potential access to conversation history or usage data.',
  severity: 'CRITICAL',
  category: 'SECRETS',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    // Anthropic keys: sk-ant-<api/admin/...>-<48+ chars>
    const regex = /sk-ant-[a-zA-Z0-9\-_]{40,}/g;
    return findMatches(regex, code, lines, 0.99);
  },
};

const ENV_IN_CODE: Rule = {
  id: 'ENV_IN_CODE',
  title: '.env values directly in code',
  description: 'An environment variable is accessed with a hardcoded fallback value that appears to be a real secret, rather than a safe default. This defeats the purpose of externalizing secrets and exposes the credential to anyone who reads the source code.',
  severity: 'MEDIUM',
  category: 'SECRETS',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const envRegex = /process\.env\.[A-Z_]+\s*\|\|\s*['"][^'"]{8,}['"]/g;

    lines.forEach((line, index) => {
      const lineMatches = line.matchAll(envRegex);
      for (const match of lineMatches) {
        // Check if the fallback looks like a real secret (not a generic default)
        const fallbackValue = match[0].match(/['"]([^'"]+)['"]/)?.[1] || '';
        const isGeneric = ['localhost', 'example', 'test', '0.0.0.0', '127.0.0.1', 'default'].some(
          term => fallbackValue.toLowerCase().includes(term)
        );

        if (!isGeneric && fallbackValue.length > 8) {
          matches.push({
            line: index + 1,
            column: match.index,
            codeSnippet: line.trim(),
            confidence: 0.75,
          });
        }
      }
    });

    return matches;
  },
};

export const secretsRules: Rule[] = [
  HARDCODED_AWS_KEY,
  HARDCODED_AWS_SECRET,
  HARDCODED_GENERIC_SECRET,
  HARDCODED_JWT,
  HARDCODED_PRIVATE_KEY,
  HARDCODED_DB_CONNECTION,
  GOOGLE_API_KEY,
  STRIPE_SECRET_KEY,
  GITHUB_TOKEN,
  ENV_IN_CODE,
  OPENAI_API_KEY,
  ANTHROPIC_API_KEY,
];
