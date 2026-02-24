import { Rule, RuleMatch } from './types';

/**
 * XXE (XML External Entity) Detection Rules
 * Detects XML parsing vulnerabilities
 */

export const xxeRules: Rule[] = [
  {
    id: 'xxe-xml-parser',
    title: 'XML parser without disabling external entities',
    description: 'XML External Entity (XXE) injection occurs when an XML parser processes external entity references embedded in attacker-supplied input, enabling server-side file disclosure, SSRF, and in some configurations remote code execution.',
    severity: 'CRITICAL',
    category: 'XXE',
    languages: ['javascript', 'typescript'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];
      const hasXmlParser = /xml2js|libxmljs|fast-xml-parser|xml-parser/.test(code);
      const hasExternalEntityDisabled = /noent.*false|loadExternalDTD.*false/i.test(code);

      if (hasXmlParser && !hasExternalEntityDisabled) {
        lines.forEach((line, index) => {
          if (/parseString|parseXml|parse\(/i.test(line)) {
            matches.push({
              line: index + 1,
              codeSnippet: line.trim(),
              confidence: 80,
            });
          }
        });
      }

      return matches;
    },
  },
  {
    id: 'xxe-python-etree',
    title: 'Unsafe XML parsing with ElementTree',
    description: 'Python\'s xml.etree.ElementTree is vulnerable to XXE by default; without substituting defusedxml, parsing untrusted XML can expose arbitrary local files or trigger server-side request forgery through external entity expansion.',
    severity: 'CRITICAL',
    category: 'XXE',
    languages: ['python'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];
      const hasEtree = /from\s+xml\.etree|import\s+xml\.etree/i.test(code);
      const hasDefusedxml = /import\s+defusedxml/i.test(code);

      if (hasEtree && !hasDefusedxml) {
        lines.forEach((line, index) => {
          if (/ET\.parse|ET\.fromstring|ElementTree\.parse/i.test(line)) {
            matches.push({
              line: index + 1,
              codeSnippet: line.trim(),
              confidence: 85,
            });
          }
        });
      }

      return matches;
    },
  },
  {
    id: 'xxe-python-minidom',
    title: 'Unsafe XML parsing with minidom',
    description: 'The xml.dom.minidom parser expands XML external entities by default, making it susceptible to XXE attacks that can read sensitive files from the server filesystem or initiate outbound requests to internal network services.',
    severity: 'CRITICAL',
    category: 'XXE',
    languages: ['python'],
    test: (code, lines) => {
      const matches: RuleMatch[] = [];

      lines.forEach((line, index) => {
        if (/minidom\.parseString|minidom\.parse/i.test(line)) {
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
];
