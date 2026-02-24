import { readFileSync } from 'fs';
import { extname } from 'path';
import { glob } from 'glob';
import { analyzeCode } from './lib/analyzers';
import { calculateSecurityScore, getSeverityCounts } from './lib/scoring';
import { Language, Finding } from './lib/analyzers/types';

export interface FileScanResult {
  file: string;
  relativePath: string;
  language: Language;
  findings: Finding[];
  score: number;
  linesOfCode: number;
}

export interface AggregatedResult {
  files: FileScanResult[];
  allFindings: (Finding & { file: string; relativePath: string })[];
  overallScore: number;
  totalFiles: number;
  counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
}

const EXTENSION_TO_LANGUAGE: Record<string, Language> = {
  '.js':  'javascript',
  '.jsx': 'javascript',
  '.ts':  'typescript',
  '.tsx': 'typescript',
  '.py':  'python',
  '.java': 'java',
  '.go':  'go',
  '.rb':  'ruby',
  '.php': 'php',
  '.cs':  'csharp',
  '.rs':  'rust',
  '.kt':  'kotlin',
  '.kts': 'kotlin',
};

const IGNORE_PATTERNS = [
  '**/node_modules/**',
  '**/dist/**',
  '**/build/**',
  '**/.git/**',
  '**/vendor/**',
  '**/.next/**',
  '**/coverage/**',
  '**/__pycache__/**',
  '**/*.min.js',
  '**/*.bundle.js',
  '**/target/**',  // Java/Rust build dirs
];

const MAX_FILE_SIZE_BYTES = 500_000; // 500KB per file
const MAX_FILES = 500;

export function detectLanguage(filePath: string): Language | null {
  const ext = extname(filePath).toLowerCase();
  return EXTENSION_TO_LANGUAGE[ext] ?? null;
}

export function scanDirectory(rootPath: string, workspacePath: string): AggregatedResult {
  // Find all scannable files
  const patterns = Object.keys(EXTENSION_TO_LANGUAGE).map(ext => `${rootPath}/**/*${ext}`);

  let files: string[] = [];
  for (const pattern of patterns) {
    const found = glob.sync(pattern, { ignore: IGNORE_PATTERNS, nodir: true });
    files.push(...found);
  }

  // Deduplicate
  files = [...new Set(files)];

  // Cap at MAX_FILES to prevent timeouts
  if (files.length > MAX_FILES) {
    console.log(`Found ${files.length} files — limiting to ${MAX_FILES} to prevent timeout`);
    files = files.slice(0, MAX_FILES);
  }

  const fileResults: FileScanResult[] = [];
  const allFindings: (Finding & { file: string; relativePath: string })[] = [];

  for (const filePath of files) {
    const language = detectLanguage(filePath);
    if (!language) continue;

    try {
      const content = readFileSync(filePath, 'utf-8');

      // Skip empty or minified files
      if (content.trim().length === 0) continue;
      if (Buffer.byteLength(content, 'utf-8') > MAX_FILE_SIZE_BYTES) {
        console.log(`Skipping ${filePath} (file too large)`);
        continue;
      }

      const result = analyzeCode(content, language);
      const score = calculateSecurityScore(result.findings);

      const relativePath = filePath.startsWith(workspacePath)
        ? filePath.slice(workspacePath.length).replace(/^\//, '')
        : filePath;

      const fileResult: FileScanResult = {
        file: filePath,
        relativePath,
        language,
        findings: result.findings,
        score,
        linesOfCode: result.linesOfCode,
      };

      fileResults.push(fileResult);

      for (const finding of result.findings) {
        allFindings.push({ ...finding, file: filePath, relativePath });
      }
    } catch (err) {
      console.log(`Warning: Could not scan ${filePath}: ${(err as Error).message}`);
    }
  }

  // Overall score: average of file scores, or 100 if no files
  const overallScore = fileResults.length > 0
    ? Math.round(fileResults.reduce((sum, f) => sum + f.score, 0) / fileResults.length)
    : 100;

  // Aggregate severity counts
  const counts = getSeverityCounts(allFindings);

  return {
    files: fileResults,
    allFindings,
    overallScore,
    totalFiles: fileResults.length,
    counts,
  };
}
