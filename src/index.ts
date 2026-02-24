import * as core from '@actions/core';
import * as github from '@actions/github';
import { writeFileSync } from 'fs';
import { resolve } from 'path';
import { scanDirectory } from './scanner';
import { buildPrComment, COMMENT_MARKER } from './comment';
import { buildSarif } from './sarif';

const SARIF_OUTPUT_PATH = 'securepilot-results.sarif';

async function run(): Promise<void> {
  try {
    // ── Inputs ──────────────────────────────────────────────────────────
    const scanPath       = core.getInput('path') || '.';
    const failOnSeverity = (core.getInput('fail-on-severity') || 'critical').toLowerCase();
    const token          = core.getInput('token');
    const postComment    = core.getInput('post-pr-comment') !== 'false';
    const uploadSarif    = core.getInput('upload-sarif') !== 'false';

    const workspace = process.env.GITHUB_WORKSPACE ?? process.cwd();
    const absPath = resolve(workspace, scanPath);

    core.info(`🛡️  SecurePilot — scanning ${absPath}`);

    // ── Scan ─────────────────────────────────────────────────────────────
    const result = scanDirectory(absPath, workspace);

    core.info(`Scanned ${result.totalFiles} files`);
    core.info(`Score: ${result.overallScore}/100`);
    core.info(`Findings: ${result.counts.critical} critical, ${result.counts.high} high, ${result.counts.medium} medium, ${result.counts.low} low`);

    // ── Set outputs ───────────────────────────────────────────────────────
    core.setOutput('score',          String(result.overallScore));
    core.setOutput('critical-count', String(result.counts.critical));
    core.setOutput('high-count',     String(result.counts.high));
    core.setOutput('total-findings', String(result.allFindings.length));
    core.setOutput('sarif-file',     SARIF_OUTPUT_PATH);

    // ── SARIF output ──────────────────────────────────────────────────────
    const sarif = buildSarif(result, workspace);
    writeFileSync(SARIF_OUTPUT_PATH, JSON.stringify(sarif, null, 2), 'utf-8');
    core.info(`SARIF written to ${SARIF_OUTPUT_PATH}`);

    // Note: SARIF upload itself is handled in the caller's workflow via
    // github/codeql-action/upload-sarif — we just produce the file.
    if (!uploadSarif) {
      core.info('SARIF upload skipped (upload-sarif: false)');
    }

    // ── PR comment ────────────────────────────────────────────────────────
    const isPr = github.context.eventName === 'pull_request' ||
                 github.context.eventName === 'pull_request_target';

    if (postComment && isPr && token) {
      const octokit = github.getOctokit(token);
      const { owner, repo } = github.context.repo;
      const prNumber = github.context.payload.pull_request?.number;

      if (prNumber) {
        const commentBody = buildPrComment(result);

        // Find existing SecurePilot comment to update (avoid duplicate comments)
        const { data: existingComments } = await octokit.rest.issues.listComments({
          owner, repo, issue_number: prNumber,
        });

        const existing = existingComments.find(c =>
          c.body?.includes(COMMENT_MARKER) && c.user?.type === 'Bot'
        );

        if (existing) {
          await octokit.rest.issues.updateComment({
            owner, repo, comment_id: existing.id, body: commentBody,
          });
          core.info(`Updated existing PR comment #${existing.id}`);
        } else {
          await octokit.rest.issues.createComment({
            owner, repo, issue_number: prNumber, body: commentBody,
          });
          core.info(`Posted PR comment on PR #${prNumber}`);
        }
      }
    } else if (postComment && !isPr) {
      core.info('Not a pull request — skipping PR comment');
    }

    // ── Fail check ────────────────────────────────────────────────────────
    if (failOnSeverity !== 'none') {
      const shouldFail =
        (failOnSeverity === 'critical' && result.counts.critical > 0) ||
        (failOnSeverity === 'high'     && (result.counts.critical + result.counts.high) > 0) ||
        (failOnSeverity === 'medium'   && (result.counts.critical + result.counts.high + result.counts.medium) > 0);

      if (shouldFail) {
        const worst = result.counts.critical > 0 ? 'critical'
          : result.counts.high > 0 ? 'high' : 'medium';
        core.setFailed(
          `SecurePilot found ${result.counts.critical} critical, ${result.counts.high} high findings. ` +
          `Set fail-on-severity: none to allow ${worst} findings to pass. ` +
          `Visit https://www.securepilot.app for AI-powered fix suggestions.`
        );
        return;
      }
    }

    if (result.allFindings.length === 0) {
      core.info('✅ No security issues found!');
    } else {
      core.info(`⚠️  Found ${result.allFindings.length} issue(s). Check the PR comment or SARIF report for details.`);
    }

  } catch (error) {
    core.setFailed(`SecurePilot action failed: ${(error as Error).message}`);
  }
}

run();
