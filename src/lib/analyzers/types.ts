export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type Category =
  | 'INJECTION'
  | 'SECRETS'
  | 'AUTH'
  | 'XSS'
  | 'CONFIG'
  | 'VALIDATION'
  | 'CRYPTO'
  | 'DEPENDENCIES'
  | 'VIBE_SMELL'
  | 'ACCESS_CONTROL'
  | 'DATA_EXPOSURE'
  | 'SSRF'
  | 'XXE'
  | 'DESERIALIZATION'
  | 'RACE_CONDITION'
  | 'INFO_DISCLOSURE'
  | 'BUSINESS_LOGIC';

export type Language = 'javascript' | 'typescript' | 'python' | 'java' | 'go' | 'ruby' | 'php' | 'csharp' | 'rust' | 'kotlin';

export interface RuleMatch {
  line: number;
  column?: number;
  codeSnippet: string;
  confidence: number; // 0.0 - 1.0
}

export interface Rule {
  id: string;
  title: string;
  description?: string;   // What this vulnerability means and why it's dangerous
  severity: Severity;
  category: Category;
  languages: Language[];
  test: (code: string, lines: string[]) => RuleMatch[];
  // Optional standards metadata — used for badge display and advisory cross-referencing
  cwe?: string;           // e.g. "CWE-89"  (links to cwe.mitre.org)
  owasp?: string;         // e.g. "A03:2021" (OWASP Top 10)
  owaspLLM?: string;      // e.g. "LLM01:2025" (OWASP LLM Top 10)
  addedInVersion?: string; // e.g. "1.2.0"
}

export interface Finding {
  severity: Severity;
  category: Category;
  ruleId: string;
  title: string;
  description?: string;   // Carried through from Rule for PDF + UI display
  line?: number;
  column?: number;
  codeSnippet?: string;
  confidence: number;
  // Carried through from Rule metadata for UI display
  cwe?: string;
  owasp?: string;
  owaspLLM?: string;
}

export interface AnalysisResult {
  findings: Finding[];
  linesOfCode: number;
  language: Language;
}
