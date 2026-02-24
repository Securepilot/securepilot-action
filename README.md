# 🛡️ SecurePilot Security Scan

**Scan your code for 140+ security vulnerabilities on every pull request — including AI/LLM-specific risks like prompt injection.**

[![GitHub Marketplace](https://img.shields.io/badge/GitHub-Marketplace-blue?logo=github)](https://github.com/marketplace/actions/securepilot-security-scan)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What It Does

SecurePilot runs on every PR and automatically:

- 🔍 **Scans every changed file** for 140+ security vulnerabilities
- 📊 **Posts a score (0–100)** directly in the PR comment — visible to the whole team
- 🤖 **Detects AI-era risks** — prompt injection, LLM output trust, unsafe eval patterns
- 📋 **Uploads SARIF** to GitHub Code Scanning — findings appear inline in "Files Changed"
- 🚫 **Blocks merging** if critical vulnerabilities are found (configurable)

### Example PR Comment

> 🛡️ **SecurePilot Security Scan**
>
> **Score: 64/100 🟠 Needs Work** — 12 files scanned
>
> | Severity | Count |
> |----------|-------|
> | 🔴 Critical | 2 |
> | 🟠 High | 4 |
> | 🟡 Medium | 3 |
>
> **Top findings:**
> 1. 🔴 **Hardcoded AWS Access Key** — `src/config.ts` (line 12) · CWE-798
> 2. 🔴 **SQL Injection via string concat** — `src/db/users.ts` (line 89) · CWE-89
> 3. 🟠 **JWT signed with weak secret** — `src/auth.ts` (line 103) · CWE-327
>
> [🔍 Get AI-powered fix suggestions →](https://www.securepilot.app)

---

## Quick Start

Add this to `.github/workflows/security.yml`:

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:

jobs:
  securepilot:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write       # needed to post PR comments
      security-events: write     # needed for SARIF upload

    steps:
      - uses: actions/checkout@v4

      - name: SecurePilot Security Scan
        uses: securepilot/securepilot-action@v1

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: securepilot-results.sarif
```

That's it. Push a PR and see the results.

---

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `path` | Directory to scan | `.` (repo root) |
| `fail-on-severity` | Fail workflow at this severity: `critical`, `high`, `medium`, `none` | `critical` |
| `token` | GitHub token for PR comments | `github.token` |
| `post-pr-comment` | Post summary comment on PRs | `true` |
| `upload-sarif` | Generate SARIF file for Code Scanning | `true` |

## Outputs

| Output | Description |
|--------|-------------|
| `score` | Security score 0–100 |
| `critical-count` | Number of critical findings |
| `high-count` | Number of high findings |
| `total-findings` | Total findings across all severities |
| `sarif-file` | Path to the SARIF report |

---

## Examples

### Informational only (never block PRs)
```yaml
- uses: securepilot/securepilot-action@v1
  with:
    fail-on-severity: none
```

### Block on high severity or worse
```yaml
- uses: securepilot/securepilot-action@v1
  with:
    fail-on-severity: high
```

### Scan a specific subdirectory
```yaml
- uses: securepilot/securepilot-action@v1
  with:
    path: src/
    fail-on-severity: critical
```

### Use the score in a downstream step
```yaml
- name: SecurePilot Scan
  id: scan
  uses: securepilot/securepilot-action@v1

- name: Print score
  run: echo "Security score is ${{ steps.scan.outputs.score }}"
```

---

## Rule Coverage (140+ Rules)

| Category | Examples |
|----------|---------|
| 🔴 Injection | SQL injection, NoSQL injection, command injection, XPath |
| 🔑 Secrets | Hardcoded API keys, AWS credentials, JWT secrets, passwords |
| 🔐 Authentication | Weak auth, plaintext passwords, JWT misuse, OAuth issues |
| 🤖 Prompt Injection | LLM input concatenation, system prompt leakage, jailbreak patterns |
| 🔒 Cryptography | Weak algorithms (MD5, SHA1), hardcoded keys, deprecated TLS |
| 🌐 SSRF | Server-side request forgery patterns |
| 🛡️ Access Control | IDOR, missing auth checks, privilege escalation |
| ⚙️ Configuration | Debug mode in production, exposed configs, env var leaks |
| + 13 more | CSRF, XXE, deserialization, race conditions, session fixation, ... |

**Unique to SecurePilot:** 21 AI/LLM-specific rules targeting "vibe coding" security patterns — the vulnerabilities AI code generators introduce that traditional scanners miss.

---

## Supported Languages

JavaScript · TypeScript · Python · Java · Go · Ruby · PHP · C# · Rust · Kotlin

---

## Free. No Sign-Up Required for CI.

The GitHub Action runs entirely locally in your CI — no code is sent to our servers, no API key required.

Want AI-powered fix explanations, team dashboards, and compliance exports? **[Get started free at securepilot.app →](https://www.securepilot.app)**

---

## License

MIT — see [LICENSE](LICENSE)
