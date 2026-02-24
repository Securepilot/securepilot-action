import { Rule, RuleMatch } from './types';

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

const WEAK_HASH_MD5: Rule = {
  id: 'WEAK_HASH_MD5',
  title: 'MD5 used for security purposes',
  description: 'MD5 is a cryptographically broken hash algorithm that is highly vulnerable to collision and preimage attacks, making it unsuitable for any security-sensitive operation. Using MD5 for integrity verification, digital signatures, or password storage can allow an attacker to produce colliding inputs or reverse hashes with commodity hardware.',
  severity: 'HIGH',
  category: 'CRYPTO',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const patterns = [
      /createHash\s*\(\s*['"]md5['"]\s*\)/gi,
      /hashlib\.md5/gi,
      /\bMD5\s*\(/gi,
    ];

    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      patterns.forEach(pattern => {
        const lineMatches = line.matchAll(pattern);
        for (const match of lineMatches) {
          matches.push({
            line: index + 1,
            column: match.index,
            codeSnippet: line.trim(),
            confidence: 0.90,
          });
        }
      });
    });

    return matches;
  },
};

const WEAK_HASH_SHA1: Rule = {
  id: 'WEAK_HASH_SHA1',
  title: 'SHA1 used for security purposes',
  description: 'SHA-1 has known practical collision vulnerabilities (demonstrated by the SHAttered attack) and is no longer considered secure for cryptographic use. Continuing to use SHA-1 for certificate signatures, HMAC, or data integrity checks exposes systems to collision-based forgery attacks.',
  severity: 'MEDIUM',
  category: 'CRYPTO',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const patterns = [
      /createHash\s*\(\s*['"]sha1['"]\s*\)/gi,
      /hashlib\.sha1/gi,
      /\bSHA1\s*\(/gi,
    ];

    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      patterns.forEach(pattern => {
        const lineMatches = line.matchAll(pattern);
        for (const match of lineMatches) {
          matches.push({
            line: index + 1,
            column: match.index,
            codeSnippet: line.trim(),
            confidence: 0.85,
          });
        }
      });
    });

    return matches;
  },
};

const INSECURE_RANDOM: Rule = {
  id: 'INSECURE_RANDOM',
  title: 'Math.random() for security purposes',
  description: '`Math.random()` is a pseudo-random number generator (PRNG) that is not cryptographically secure and produces predictable output. Using it to generate tokens, session identifiers, OTPs, or cryptographic keys allows an attacker who can observe or seed the PRNG state to predict future values.',
  severity: 'HIGH',
  category: 'CRYPTO',
  languages: ['javascript', 'typescript'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];

    lines.forEach((line, index) => {
      const hasMathRandom = /Math\.random\s*\(\)/i.test(line);

      if (hasMathRandom) {
        const securityKeywords = ['token', 'session', 'key', 'password', 'secret', 'otp', 'code', 'id'];
        // Check the current line for security context
        const lineIsSecure = securityKeywords.some(keyword =>
          new RegExp(keyword, 'i').test(line)
        );
        // Also check surrounding function/variable name (look back 3 lines for function declaration)
        const context = lines.slice(Math.max(0, index - 3), index + 1).join('\n');
        const contextIsSecure = securityKeywords.some(keyword =>
          new RegExp(keyword, 'i').test(context)
        );

        if (lineIsSecure || contextIsSecure) {
          matches.push({
            line: index + 1,
            column: 0,
            codeSnippet: line.trim(),
            confidence: lineIsSecure ? 0.90 : 0.80,
          });
        }
      }
    });

    return matches;
  },
};

const WEAK_ENCRYPTION: Rule = {
  id: 'WEAK_ENCRYPTION',
  title: 'DES or RC4 encryption',
  description: 'DES and RC4 are deprecated symmetric encryption algorithms with well-documented cryptanalytic weaknesses; DES has an exhaustively small 56-bit key space and RC4 produces biased keystreams. Data encrypted with these algorithms can be decrypted by a moderately resourced attacker.',
  severity: 'HIGH',
  category: 'CRYPTO',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const regex = /(des-|rc4|DES|RC4)/gi;
    return findMatches(regex, code, lines, 0.95);
  },
};

const HARDCODED_IV: Rule = {
  id: 'HARDCODED_IV',
  title: 'Hardcoded initialization vector',
  description: 'A hardcoded, static initialization vector (IV) causes the same plaintext to produce identical ciphertext across multiple encryption operations, breaking semantic security. Reusing IVs in CBC mode can enable chosen-plaintext attacks, and in CTR/GCM mode it leads to complete keystream recovery.',
  severity: 'HIGH',
  category: 'CRYPTO',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    const patterns = [
      /createCipheriv\s*\([^,]*,[^,]*,\s*['"]/gi,
      /AES\.new\s*\([^,]*,\s*['"]/gi,
    ];

    lines.forEach((line, index) => {
      patterns.forEach(pattern => {
        const lineMatches = line.matchAll(pattern);
        for (const match of lineMatches) {
          // Check if it's a static string (hardcoded IV)
          const afterMatch = line.slice((match.index || 0) + match[0].length);
          const hasStaticString = /^[a-zA-Z0-9]{16,}['"]/.test(afterMatch);

          if (hasStaticString) {
            matches.push({
              line: index + 1,
              column: match.index,
              codeSnippet: line.trim(),
              confidence: 0.90,
            });
          }
        }
      });
    });

    return matches;
  },
};

const HARDCODED_SALT: Rule = {
  id: 'HARDCODED_SALT',
  title: 'Hardcoded salt for hashing',
  description: 'A static, hardcoded salt eliminates the per-user randomness that salts are designed to provide, allowing a single precomputed rainbow table or dictionary attack to crack all hashes simultaneously. Salts must be randomly generated per credential to ensure each hash is unique.',
  severity: 'MEDIUM',
  category: 'CRYPTO',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const regex = /salt\s*=\s*['"]/gi;
    return findMatches(regex, code, lines, 0.80);
  },
};

// ─── ECB mode — deterministic, pattern-leaking encryption ────────────────────
const ECB_MODE_ENCRYPTION: Rule = {
  id: 'ECB_MODE_ENCRYPTION',
  title: 'AES-ECB mode used — deterministic and insecure',
  description: 'AES in ECB (Electronic Codebook) mode encrypts each block independently with the same key, producing identical ciphertext blocks for identical plaintext blocks. This deterministic property leaks plaintext structure, making it trivial for an attacker to identify repeated data patterns and mount block-rearrangement attacks.',
  severity: 'HIGH',
  category: 'CRYPTO',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const patterns = [
      /createCipheriv\s*\(\s*['"]aes-\d+-ecb['"]/gi,
      /AES\.new\s*\([^,]*,\s*AES\.MODE_ECB/gi,
      /Cipher\.getInstance\s*\(\s*['"]AES\/ECB/gi,
      /aes\.NewECBEncrypter|ecb\.NewEncrypter/gi,
      /['"]aes-ecb['"]/gi,
    ];
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      patterns.forEach(pattern => {
        for (const match of line.matchAll(pattern)) {
          matches.push({ line: index + 1, column: match.index, codeSnippet: line.trim(), confidence: 0.97 });
        }
      });
    });
    return matches;
  },
};

// ─── AES-128 where AES-256 should be used ────────────────────────────────────
const AES_128_WEAK_KEY: Rule = {
  id: 'AES_128_WEAK_KEY',
  title: 'AES-128 used — prefer AES-256 for sensitive data',
  description: 'AES-128 provides 128 bits of security, which, while not immediately broken, offers a smaller safety margin than AES-256 and is not recommended for protecting sensitive or long-lived data. Modern guidance from NIST and other standards bodies recommends AES-256 for new applications to future-proof against advances in cryptanalysis.',
  severity: 'MEDIUM',
  category: 'CRYPTO',
  languages: ['javascript', 'typescript', 'python', 'java', 'go', 'ruby', 'php', 'csharp', 'rust', 'kotlin'],
  test: (code, lines) => {
    const regex = /['"]aes-128-(cbc|cfb|ctr|gcm)['"]/gi;
    return findMatches(regex, code, lines, 0.80);
  },
};

// ─── Non-GCM AES (CBC without auth = malleable ciphertext) ───────────────────
const AES_CBC_NO_AUTH: Rule = {
  id: 'AES_CBC_NO_AUTH',
  title: 'AES-CBC without authentication tag — malleable ciphertext',
  description: 'AES-CBC without an accompanying message authentication code (MAC) or authenticated encryption tag provides no integrity guarantee, leaving ciphertext malleable. An attacker can perform padding oracle attacks or bitflip the ciphertext to manipulate the decrypted plaintext without knowledge of the key; use AES-GCM or append an HMAC to the ciphertext.',
  severity: 'HIGH',
  category: 'CRYPTO',
  languages: ['javascript', 'typescript', 'python'],
  test: (code, lines) => {
    const matches: RuleMatch[] = [];
    lines.forEach((line, index) => {
      const hasCBC = /['"]aes-\d+-cbc['"]|AES\.MODE_CBC/i.test(line);
      if (hasCBC) {
        // Check entire file for HMAC/auth tag usage
        const hasAuth = /(hmac|createHmac|HMAC|\.MODE_GCM|authTag|getAuthTag|verify.*mac)/i.test(code);
        if (!hasAuth) {
          matches.push({ line: index + 1, column: 0, codeSnippet: line.trim(), confidence: 0.72 });
        }
      }
    });
    return matches;
  },
};

export const cryptoRules: Rule[] = [
  WEAK_HASH_MD5,
  WEAK_HASH_SHA1,
  INSECURE_RANDOM,
  WEAK_ENCRYPTION,
  HARDCODED_IV,
  HARDCODED_SALT,
  ECB_MODE_ENCRYPTION,
  AES_128_WEAK_KEY,
  AES_CBC_NO_AUTH,
];
