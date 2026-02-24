import { Rule, RuleMatch } from './types';

/**
 * Insecure Deserialization Detection Rules
 * Detects unsafe object deserialization that can lead to RCE
 */

export const deserializationRules: Rule[] = [
  {
    id: 'deser-node-serialize',
    title: 'Unsafe use of node-serialize',
    description: 'The node-serialize library deserializes JavaScript objects using eval-like mechanisms, allowing an attacker who controls the serialized payload to achieve remote code execution on the server.',
    severity: 'CRITICAL',
    category: 'DESERIALIZATION',
    languages: ['javascript', 'typescript'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];

      lines.forEach((line, index) => {
        if (/require\(['"]node-serialize['"]\)|from\s+['"]node-serialize['"]/i.test(line)) {
          matches.push({
            line: index + 1,
            codeSnippet: line.trim(),
            confidence: 95,
          });
        }
      });

      return matches;
    },
  },
  {
    id: 'deser-pickle-loads',
    title: 'Unsafe pickle.loads() with untrusted data',
    description: 'Python\'s pickle.loads() executes arbitrary bytecode embedded in the serialized stream; deserializing attacker-controlled data with pickle can result in full remote code execution on the host system.',
    severity: 'CRITICAL',
    category: 'DESERIALIZATION',
    languages: ['python'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];

      lines.forEach((line, index) => {
        if (/pickle\.loads?\s*\(/i.test(line)) {
          matches.push({
            line: index + 1,
            codeSnippet: line.trim(),
            confidence: 90,
          });
        }
      });

      return matches;
    },
  },
  {
    id: 'deser-yaml-unsafe',
    title: 'Unsafe YAML deserialization',
    description: 'Using yaml.load() without a safe Loader (or using yaml.unsafe_load) allows YAML files to instantiate arbitrary Python objects, enabling remote code execution when parsing untrusted input.',
    severity: 'CRITICAL',
    category: 'DESERIALIZATION',
    languages: ['python'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];

      lines.forEach((line, index) => {
        if (/yaml\.load\s*\([^,)]*\)|yaml\.unsafe_load/i.test(line) && !/Loader\s*=/.test(line)) {
          matches.push({
            line: index + 1,
            codeSnippet: line.trim(),
            confidence: 90,
          });
        }
      });

      return matches;
    },
  },
  {
    id: 'deser-marshal',
    title: 'Unsafe use of marshal module',
    description: 'Python\'s marshal module deserializes raw bytecode objects and is explicitly documented as unsafe for untrusted data; a malicious payload can cause arbitrary code execution or interpreter crashes.',
    severity: 'HIGH',
    category: 'DESERIALIZATION',
    languages: ['python'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];

      lines.forEach((line, index) => {
        if (/marshal\.loads?\s*\(/i.test(line)) {
          matches.push({
            line: index + 1,
            codeSnippet: line.trim(),
            confidence: 85,
          });
        }
      });

      return matches;
    },
  },
  {
    id: 'deser-jsonp-callback',
    title: 'JSONP callback injection vulnerability',
    description: 'Reflecting an unsanitized user-supplied callback name in a JSONP response allows an attacker to inject arbitrary JavaScript, enabling cross-site scripting and potentially bypassing same-origin policy protections.',
    severity: 'MEDIUM',
    category: 'DESERIALIZATION',
    languages: ['javascript', 'typescript'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];

      lines.forEach((line, index) => {
        if (/res\.(jsonp|send)\s*\(\s*req\.(query|params)\.callback/i.test(line)) {
          matches.push({
            line: index + 1,
            codeSnippet: line.trim(),
            confidence: 75,
          });
        }
      });

      return matches;
    },
  },
];
