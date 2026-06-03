#!/usr/bin/env node
/**
 * index.js — auth-doctor
 * Security static analysis CLI for Next.js TypeScript codebases.
 * Built by NoctisNova — noctisnova.com
 */

import * as p from "@clack/prompts";
import boxen from "boxen";
import chalk from "chalk";
import clipboardy from "clipboardy";
import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { parseArgs } from "node:util";

import {
  scanUnprotectedRoutes,
  scanUnprotectedServerActions,
  scanLocalStorageSessionStorage,
  scanJwtWithoutVerification,
  scanMissingCsrf,
  collectSourceFiles,
  isDeadCode,
} from "./src/scanner.js";

import { runAdvancedScans } from "./src/advanced.js";
import { detectSecurityContext } from "./src/context.js";

import {
  renderProgressBar,
  renderScoreBadge,
  renderDashboard,
  renderContextLine,
  buildAgentPrompt,
} from "./src/ui.js";

// ---------------------------------------------------------------------------
// Middleware-aware false-positive suppression
// ---------------------------------------------------------------------------

/**
 * Drops "unprotected route" / "missing CSRF" findings for routes that are
 * actually gated by an auth middleware matcher — these are false positives.
 * Returns { issues, suppressed }.
 */
function applyMiddlewareSuppression(issues, ctx) {
  if (!ctx?.authMiddleware) return { issues, suppressed: 0 };
  let suppressed = 0;
  const kept = issues.filter((i) => {
    if ((i.rule === "unprotected-route" || i.rule === "csrf-missing") &&
        ctx.isRouteCoveredByAuthMiddleware(i.file)) {
      suppressed++;
      return false;
    }
    return true;
  });
  return { issues: kept, suppressed };
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const REPORT_FILE = "./.auth-doctor-report.json";
const VERSION     = "1.0.0";

const HELP_TEXT = `
${chalk.bold("auth-doctor")}  v${VERSION}
Security static analysis CLI for Next.js TypeScript codebases.
Built by NoctisNova — noctisnova.com

${chalk.bold("Usage")}
  auth-doctor [options] [path]

${chalk.bold("Arguments")}
  path          Root directory to scan (default: current working directory)

${chalk.bold("Options")}
  --json        Output raw JSON report to stdout (CI mode)
  --no-ai       Skip the agent hand-off menu
  --version, -v Print version and exit
  --help, -h    Show this help message

${chalk.bold("What it detects")}
  ${chalk.red("Access control")}  unprotected routes & Server Actions · IDOR / missing ownership
  ${chalk.red("Secrets")}         hardcoded API keys & JWT secrets · NEXT_PUBLIC_ leaks
  ${chalk.red("JWT")}             tokens decoded without signature verification
  ${chalk.yellow("Sessions")}        tokens stored in localStorage (should be httpOnly cookies)
  ${chalk.yellow("Abuse")}           login/reset/OTP endpoints with no rate limiting
  ${chalk.yellow("Redirects")}       open redirects to user-controlled URLs
  ${chalk.yellow("Exposure")}        password/secret/token fields returned in responses · CSRF

${chalk.dim("Middleware-aware: routes gated by an auth middleware matcher are not false-flagged.")}

${chalk.bold("Examples")}
  auth-doctor
  auth-doctor ./my-nextjs-app
  auth-doctor --json > .auth-doctor-report.json
`.trim();

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function easeOut(t) { return 1 - Math.pow(1 - t, 3); }

function parseCLIArgs() {
  let parsed;
  try {
    parsed = parseArgs({
      allowPositionals: true,
      options: {
        json:    { type: "boolean", default: false },
        "no-ai": { type: "boolean", default: false },
        version: { type: "boolean", short: "v", default: false },
        help:    { type: "boolean", short: "h", default: false },
      },
    });
  } catch (err) {
    console.error(chalk.red(`Error: ${err.message}`));
    process.exit(1);
  }
  return {
    projectPath: parsed.positionals[0] ?? process.cwd(),
    jsonMode:    parsed.values.json,
    noAi:        parsed.values["no-ai"],
    showVersion: parsed.values.version,
    showHelp:    parsed.values.help,
  };
}

// ---------------------------------------------------------------------------
// Score reveal animation
// ---------------------------------------------------------------------------

async function animateScoreReveal(score) {
  const frames = 40;
  process.stdout.write("\x1B[?25l");
  for (let i = 0; i <= frames; i++) {
    const current = Math.round(easeOut(i / frames) * score);
    process.stdout.write(`\r  ${renderProgressBar(current)}  ${renderScoreBadge(current)}   `);
    await sleep(16);
  }
  process.stdout.write("\x1B[?25h\n\n");
}

// ---------------------------------------------------------------------------
// AI hand-off handlers
// ---------------------------------------------------------------------------

function handOffToClaude(prompt) {
  const reportPath = path.resolve(REPORT_FILE);
  if (!fs.existsSync(reportPath)) {
    p.log.warn("Report file not found — run auth-doctor first.");
    return;
  }
  const safePrompt = prompt.replace(/"/g, '\\"');
  p.log.step(chalk.dim("Launching Claude Code…"));
  try {
    execSync(`claude -p "${safePrompt}"`, { stdio: "inherit", shell: true, cwd: process.cwd() });
  } catch (err) {
    if (err.status === 127 || /not found|is not recognized/i.test(err.message ?? "")) {
      p.log.error(
        chalk.red("The `claude` CLI was not found in your PATH.\n") +
        chalk.dim("  Install it: https://docs.anthropic.com/en/docs/claude-code/getting-started")
      );
    } else {
      p.log.warn(chalk.yellow(`Claude exited with code ${err.status ?? "unknown"}.`));
    }
  }
}

async function copyToClipboard(prompt) {
  try {
    await clipboardy.write(prompt);
    p.log.success(chalk.green("Prompt copied to clipboard!"));
    p.log.info(chalk.dim("Paste it into Cursor, ChatGPT, or any AI assistant."));
  } catch (err) {
    p.log.error(chalk.red(`Clipboard write failed: ${err.message}`));
  }
}

function printPrompt(prompt) {
  console.log();
  console.log(
    boxen(chalk.white(prompt), {
      title: chalk.bold.red(" Security Prompt "),
      titleAlignment: "center",
      padding: { top: 1, bottom: 1, left: 2, right: 2 },
      margin: { top: 0, bottom: 1 },
      borderStyle: "round",
      borderColor: "red",
    })
  );
}

// ---------------------------------------------------------------------------
// Multi-phase scan
// ---------------------------------------------------------------------------

async function runPhasedScans({ projectPath }) {
  const spinner = p.spinner();

  spinner.start(chalk.dim("Discovering source files…"));
  await sleep(300);

  const allFiles  = collectSourceFiles(projectPath);
  const liveFiles = allFiles.filter((f) => !isDeadCode(f));
  const deadFiles = allFiles.filter(isDeadCode);

  spinner.message(chalk.dim(`Found ${chalk.white(allFiles.length)} TypeScript files — scanning for vulnerabilities…`));
  await sleep(400);

  // Phase 2 — API routes
  spinner.message(chalk.dim("Scanning API routes for missing auth…"));
  await sleep(300);
  const routeIssues = await scanUnprotectedRoutes(projectPath);

  // Phase 3 — Server Actions
  spinner.message(chalk.dim("Checking Server Actions for auth guards…"));
  await sleep(300);
  const actionIssues = await scanUnprotectedServerActions(projectPath);

  // Phase 4 — localStorage
  spinner.message(chalk.dim("Scanning for insecure token storage…"));
  await sleep(300);
  const localStorageIssues = await scanLocalStorageSessionStorage(projectPath);

  // Phase 5 — JWT
  spinner.message(chalk.dim("Checking JWT handling patterns…"));
  await sleep(300);
  const jwtIssues = await scanJwtWithoutVerification(projectPath);

  // Phase 6 — CSRF
  spinner.message(chalk.dim("Analysing CSRF protection on mutations…"));
  await sleep(300);
  const csrfIssues = await scanMissingCsrf(projectPath);

  // Phase 7 — Advanced security engine
  spinner.message(chalk.dim("Hunting hardcoded secrets & leaked NEXT_PUBLIC_ vars…"));
  await sleep(300);
  spinner.message(chalk.dim("Checking object-level auth (IDOR), redirects & rate limits…"));
  await sleep(300);
  const advancedIssues = await runAdvancedScans(projectPath);

  // Phase 8 — Security context (auth provider + middleware awareness)
  spinner.message(chalk.dim("Reading auth provider & middleware matcher…"));
  await sleep(250);
  const context = detectSecurityContext(projectPath);

  // Phase 9 — Filter dead code + middleware suppression + score
  spinner.message(
    chalk.dim("Filtering dead code") +
    (deadFiles.length > 0 ? chalk.dim(` — ignoring ${deadFiles.length} test/mock file${deadFiles.length !== 1 ? "s" : ""}…`) : chalk.dim("…"))
  );
  await sleep(350);

  const allRaw = [...routeIssues, ...actionIssues, ...localStorageIssues, ...jwtIssues, ...csrfIssues, ...advancedIssues];
  const liveIssues = allRaw.filter((issue) => !isDeadCode(issue.file));
  const { issues, suppressed } = applyMiddlewareSuppression(liveIssues, context);
  const filteredOut = allRaw.length - issues.length;

  spinner.message(chalk.dim("Computing security score…"));
  await sleep(300);

  const totalPenalty = issues.reduce((s, i) => s + i.penalty, 0);
  const score = Math.max(0, 100 - totalPenalty);

  try {
    fs.writeFileSync(
      REPORT_FILE,
      JSON.stringify({
        generatedAt: new Date().toISOString(),
        projectPath: path.resolve(projectPath),
        context,
        score,
        totalPenalty,
        issueCount: issues.length,
        filteredOut,
        suppressedByMiddleware: suppressed,
        liveFilesScanned: liveFiles.length,
        deadFilesIgnored: deadFiles.length,
        issues,
      }, null, 2),
      "utf-8"
    );
  } catch { /* non-fatal */ }

  const doneMsg = issues.length === 0
    ? chalk.green("Done — no vulnerabilities found.")
    : chalk.red(`Done — ${issues.length} security issue${issues.length !== 1 ? "s" : ""} found.`);

  spinner.stop(doneMsg);

  if (deadFiles.length > 0) {
    p.log.info(chalk.dim(`Ignored ${chalk.white(deadFiles.length)} dead-code file${deadFiles.length !== 1 ? "s" : ""} (tests / mocks)`));
  }
  if (suppressed > 0) {
    p.log.info(chalk.dim(`Suppressed ${chalk.white(suppressed)} route finding${suppressed !== 1 ? "s" : ""} covered by auth middleware`));
  }

  return { issues, totalPenalty, score, context };
}

// ---------------------------------------------------------------------------
// Arrow-key hand-off menu
// ---------------------------------------------------------------------------

async function showHandOffMenu(issues) {
  if (issues.length === 0) {
    p.log.success(chalk.green("Nothing to hand off — no vulnerabilities found!"));
    return;
  }

  const reportPath  = path.resolve(REPORT_FILE);
  const agentPrompt = buildAgentPrompt(issues, reportPath);

  console.log();

  const choice = await p.select({
    message: chalk.bold("What do you want to do with these security issues?"),
    options: [
      {
        value: "claude",
        label: chalk.cyan.bold("Send to Claude Code"),
        hint: "runs `claude -p \"...\"` — Claude reads the report and fixes the vulnerabilities",
      },
      {
        value: "clipboard",
        label: chalk.magenta.bold("Copy prompt to clipboard"),
        hint: "paste into Cursor, ChatGPT, Claude.ai, or any AI assistant",
      },
      {
        value: "print",
        label: chalk.yellow.bold("Print prompt in terminal"),
        hint: "display the full security briefing in your shell",
      },
      {
        value: "skip",
        label: chalk.dim("Skip"),
        hint: "exit — report saved to " + chalk.white(".auth-doctor-report.json"),
      },
    ],
  });

  if (p.isCancel(choice)) { p.cancel("Cancelled."); process.exit(0); }

  console.log();

  switch (choice) {
    case "claude":
      handOffToClaude(agentPrompt);
      break;
    case "clipboard":
      await copyToClipboard(agentPrompt);
      break;
    case "print":
      await printPrompt(agentPrompt);
      p.log.info(chalk.dim("Report saved to: ") + chalk.cyan(reportPath));
      break;
    case "skip":
      p.log.info(chalk.dim("Report saved to: ") + chalk.cyan(reportPath));
      break;
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const args = parseCLIArgs();

  if (args.showVersion) { console.log(`auth-doctor v${VERSION}`); process.exit(0); }
  if (args.showHelp)    { console.log(HELP_TEXT);                 process.exit(0); }

  const resolvedProject = path.resolve(args.projectPath);
  if (!fs.existsSync(resolvedProject)) {
    console.error(chalk.red(`Error: path does not exist — ${resolvedProject}`));
    process.exit(1);
  }

  // ── CI / JSON mode ────────────────────────────────────────────────────────
  if (args.jsonMode) {
    const [routeIssues, actionIssues, lsIssues, jwtIssues, csrfIssues, advancedIssues] = await Promise.all([
      scanUnprotectedRoutes(args.projectPath),
      scanUnprotectedServerActions(args.projectPath),
      scanLocalStorageSessionStorage(args.projectPath),
      scanJwtWithoutVerification(args.projectPath),
      scanMissingCsrf(args.projectPath),
      runAdvancedScans(args.projectPath),
    ]);
    const context = detectSecurityContext(args.projectPath);
    const live = [...routeIssues, ...actionIssues, ...lsIssues, ...jwtIssues, ...csrfIssues, ...advancedIssues]
      .filter((i) => !isDeadCode(i.file));
    const { issues } = applyMiddlewareSuppression(live, context);
    const totalPenalty = issues.reduce((s, i) => s + i.penalty, 0);
    const score = Math.max(0, 100 - totalPenalty);
    console.log(JSON.stringify({
      generatedAt: new Date().toISOString(),
      projectPath: resolvedProject,
      context, score, totalPenalty, issueCount: issues.length, issues,
    }, null, 2));
    process.exit(issues.some((i) => i.severity === "critical") ? 1 : 0);
  }

  // ── Interactive mode ──────────────────────────────────────────────────────
  console.log();
  p.intro(
    chalk.bgRed.white.bold("  auth-doctor  ") +
    chalk.dim(`  v${VERSION}  ·  Security static analyser  ·  by `) +
    chalk.magenta("NoctisNova") +
    chalk.dim("  noctisnova.com")
  );

  console.log();

  let scanResult;
  try {
    scanResult = await runPhasedScans({ projectPath: args.projectPath });
  } catch (err) {
    p.log.error(chalk.red(err.message));
    p.outro(chalk.red("auth-doctor encountered an error."));
    process.exit(1);
  }

  const { issues, score, totalPenalty, context } = scanResult;

  // Score reveal animation
  console.log();
  await animateScoreReveal(score);

  // Detected auth context line
  const ctxLine = renderContextLine(context);
  if (ctxLine) console.log(ctxLine);

  // Full dashboard
  console.log(
    renderDashboard({ score, totalPenalty, issues, projectPath: args.projectPath })
  );

  // Agent hand-off menu
  if (!args.noAi) {
    await showHandOffMenu(issues);
  } else {
    p.log.info(chalk.dim("Report saved to: ") + chalk.cyan(path.resolve(REPORT_FILE)));
  }

  const hasCritical = issues.some((i) => i.severity === "critical");
  console.log();
  p.outro(
    hasCritical
      ? chalk.red("Fix the critical vulnerabilities before shipping to production.")
      : issues.length > 0
        ? chalk.yellow("Address the warnings and re-run auth-doctor to verify.")
        : chalk.green("Your auth looks solid. Keep it that way.")
  );

  process.exit(hasCritical ? 1 : 0);
}

main().catch((err) => {
  console.error(chalk.red("\nUnexpected error:"), err.message ?? err);
  if (process.env.DEBUG) console.error(err);
  process.exit(1);
});
