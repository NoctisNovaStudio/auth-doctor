/**
 * ui.js — auth-doctor
 * Terminal UI: score box, numbered security issue list, agent prompt builder.
 */

import boxen from "boxen";
import chalk from "chalk";
import path from "node:path";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const REPORT_FILE  = "./.auth-doctor-report.json";
const BAR_WIDTH    = 30;
const MAX_FILES    = 3;

// ---------------------------------------------------------------------------
// Rule metadata — drives all display text
// ---------------------------------------------------------------------------

const RULE_META = {
  "unprotected-route": {
    badge: "CRIT",
    badgeFn: (s) => chalk.bgRed.white.bold(` ${s} `),
    category: "Access Control",
    label: "Unprotected API Route",
    penalty: 20,
    explanation:
      "A mutation endpoint (POST/PUT/PATCH/DELETE) in your Next.js App Router has no detectable " +
      "auth check. Any unauthenticated HTTP client can call it — bots, scrapers, and attackers included.",
    realWorld:
      "An unprotected POST /api/users/delete endpoint means anyone with the URL can delete any " +
      "user account without logging in. No credentials needed — just a curl command.",
    severity: "critical",
    docs: "https://noctisnova.com/docs/auth/unprotected-routes",
  },

  "unprotected-action": {
    badge: "CRIT",
    badgeFn: (s) => chalk.bgRed.white.bold(` ${s} `),
    category: "Access Control",
    label: "Unprotected Server Action",
    penalty: 20,
    explanation:
      "A Server Action ('use server') is exported without an auth check at the top of the function. " +
      "Server Actions are directly callable by the browser via POST requests — they are not " +
      "protected by being 'server-side'. Any client can invoke them.",
    realWorld:
      "A createInvoice() Server Action with no auth check lets any visitor submit arbitrary invoice " +
      "data directly to your database — even if no UI form is visible to them.",
    severity: "critical",
    docs: "https://noctisnova.com/docs/auth/server-actions",
  },

  "localstorage-session": {
    badge: "CRIT",
    badgeFn: (s) => chalk.bgRed.white.bold(` ${s} `),
    category: "Token Storage",
    label: "Auth Token Stored in localStorage",
    penalty: 15,
    explanation:
      "A session token, JWT, or auth credential is being written to localStorage. Any JavaScript " +
      "running on the page — including injected scripts from third-party dependencies — can read " +
      "localStorage. One XSS vulnerability anywhere on the site steals every user's token.",
    realWorld:
      "A malicious script injected via a compromised npm package reads localStorage, extracts " +
      "all auth tokens, and silently sends them to an attacker's server. Every active session " +
      "is compromised instantly with no way to detect or revoke them.",
    severity: "critical",
    docs: "https://noctisnova.com/docs/auth/token-storage",
  },

  "jwt-no-verify": {
    badge: "CRIT",
    badgeFn: (s) => chalk.bgRed.white.bold(` ${s} `),
    category: "JWT Security",
    label: "JWT Decoded Without Signature Verification",
    penalty: 20,
    explanation:
      "A JWT is being decoded (reading the payload) without verifying the cryptographic signature. " +
      "This means the server trusts whatever the client sends in the token body — an attacker can " +
      "craft a token with any userId, role, or permission they want.",
    realWorld:
      "An attacker sets their role to 'admin' in a JWT payload, uses any random signature, and " +
      "calls jwt.decode(). The server reads { role: 'admin' } and grants admin access. No " +
      "password or account needed.",
    severity: "critical",
    docs: "https://noctisnova.com/docs/auth/jwt-security",
  },

  "csrf-missing": {
    badge: "WARN",
    badgeFn: (s) => chalk.bgYellow.black.bold(` ${s} `),
    category: "CSRF",
    label: "Missing CSRF Protection on Mutation",
    penalty: 10,
    explanation:
      "A mutation endpoint has no CSRF token check and no session-based auth. A malicious website " +
      "can embed a hidden form or script that fires a request to your API using the victim's " +
      "browser cookies — without the victim knowing.",
    realWorld:
      "A user visits evil.com while logged into your app. A hidden <form> on evil.com auto-submits " +
      "a POST to your /api/transfer endpoint using the user's session cookie. Money moves. " +
      "The user never clicked anything.",
    severity: "warning",
    docs: "https://noctisnova.com/docs/auth/csrf-protection",
  },

  // ── Advanced security engine ──────────────────────────────────────────────

  "hardcoded-secret": {
    badge: "CRIT",
    badgeFn: (s) => chalk.bgRed.white.bold(` ${s} `),
    category: "Secrets",
    label: "Hardcoded Secret / API Key",
    penalty: 20,
    explanation:
      "An API key, JWT signing secret, or private key is written directly in source code instead of " +
      "an environment variable. Anyone with repository access — or anyone who finds it in Git history " +
      "after it's 'removed' — has your production credentials.",
    realWorld:
      "A Stripe `sk_live_` key committed once stays in Git history forever. Bots scrape public and even " +
      "private repos for these patterns within minutes and drain accounts before you notice.",
    severity: "critical",
    docs: "https://noctisnova.com/docs/auth/secret-management",
  },

  "public-env-secret": {
    badge: "CRIT",
    badgeFn: (s) => chalk.bgRed.white.bold(` ${s} `),
    category: "Secrets",
    label: "Secret Leaked to Browser (NEXT_PUBLIC_)",
    penalty: 18,
    explanation:
      "A secret-looking value is read from a NEXT_PUBLIC_ environment variable. Next.js inlines every " +
      "NEXT_PUBLIC_ value into the client JavaScript bundle, so it ships to every browser — anyone can " +
      "read it in DevTools.",
    realWorld:
      "`NEXT_PUBLIC_STRIPE_SECRET_KEY` or a service-role key in a NEXT_PUBLIC_ var is visible to every " +
      "visitor in the page source. It must be server-only and rotated immediately.",
    severity: "critical",
    docs: "https://noctisnova.com/docs/auth/secret-management",
  },

  "idor-missing-ownership": {
    badge: "CRIT",
    badgeFn: (s) => chalk.bgRed.white.bold(` ${s} `),
    category: "Access Control",
    label: "IDOR — Missing Ownership Check",
    penalty: 18,
    explanation:
      "A handler updates or deletes a record using an id taken straight from the request, without checking " +
      "the record belongs to the current user. This is Broken Object-Level Authorization (OWASP API #1): " +
      "being logged in is not the same as being allowed to touch THAT object.",
    realWorld:
      "`DELETE /api/posts/[id]` that just calls `prisma.post.delete({ where: { id } })` lets any user delete " +
      "any other user's posts by changing the id in the URL. Auth passes; authorization doesn't.",
    severity: "critical",
    docs: "https://noctisnova.com/docs/auth/object-level-authorization",
  },

  "open-redirect": {
    badge: "WARN",
    badgeFn: (s) => chalk.bgYellow.black.bold(` ${s} `),
    category: "Redirects",
    label: "Open Redirect",
    penalty: 10,
    explanation:
      "A redirect target is taken from user-controlled input (a query param or the request URL) with no " +
      "allow-list. Attackers use your trusted domain to bounce victims to phishing pages.",
    realWorld:
      "`/login?next=https://evil.com` — after login your app redirects to evil.com. The victim trusts the " +
      "link because it started on your domain. Common in OAuth/login callback flows.",
    severity: "warning",
    docs: "https://noctisnova.com/docs/auth/open-redirect",
  },

  "missing-rate-limit": {
    badge: "WARN",
    badgeFn: (s) => chalk.bgYellow.black.bold(` ${s} `),
    category: "Abuse Prevention",
    label: "Auth Endpoint Without Rate Limiting",
    penalty: 8,
    explanation:
      "A login / register / reset / OTP endpoint has no rate limiting. Attackers can brute-force passwords " +
      "and one-time codes, and enumerate which accounts exist, at thousands of attempts per second.",
    realWorld:
      "A 6-digit OTP with no rate limit is crackable in seconds (a million guesses is trivial). A login with " +
      "no limit lets credential-stuffing bots try millions of leaked passwords against your users.",
    severity: "warning",
    docs: "https://noctisnova.com/docs/auth/rate-limiting",
  },

  "sensitive-field-exposure": {
    badge: "WARN",
    badgeFn: (s) => chalk.bgYellow.black.bold(` ${s} `),
    category: "Data Exposure",
    label: "Sensitive Field in API Response",
    penalty: 10,
    explanation:
      "A response body includes a sensitive field such as a password hash, secret, or token. These must never " +
      "leave the server — even a hashed password aids offline cracking and confirms an account exists.",
    realWorld:
      "An endpoint returns the full Prisma user object, including `passwordHash`. Attackers harvest the hashes " +
      "and crack weak passwords offline at leisure. Return only the fields the client needs.",
    severity: "warning",
    docs: "https://noctisnova.com/docs/auth/sensitive-data-exposure",
  },
};

/**
 * Canonical display + agent ordering — criticals first.
 */
const RULE_ORDER = [
  "hardcoded-secret",
  "public-env-secret",
  "unprotected-route",
  "unprotected-action",
  "idor-missing-ownership",
  "jwt-no-verify",
  "localstorage-session",
  "sensitive-field-exposure",
  "open-redirect",
  "missing-rate-limit",
  "csrf-missing",
];

// ---------------------------------------------------------------------------
// Detected-context line (report header)
// ---------------------------------------------------------------------------

/**
 * Renders the detected auth-stack + middleware line under the score.
 * @param {{labels:string[], authMiddleware:boolean, matchers:string[]}} ctx
 */
export function renderContextLine(ctx) {
  if (!ctx || !ctx.labels?.length) return "";
  const parts = [
    chalk.dim("  Detected: ") + ctx.labels.map((l) => chalk.magenta(l)).join(chalk.dim(" · ")),
  ];
  if (ctx.authMiddleware) {
    parts.push(
      chalk.dim("  Middleware: ") +
      chalk.green("auth gate active") +
      (ctx.matchers?.length ? chalk.dim(`  ·  matcher: ${ctx.matchers.slice(0, 2).join(", ")}`) : "")
    );
  }
  return parts.join("\n");
}

// ---------------------------------------------------------------------------
// Progress bar
// ---------------------------------------------------------------------------

export function renderProgressBar(score) {
  const clamped = Math.min(100, Math.max(0, score));
  const filled  = Math.round((clamped / 100) * BAR_WIDTH);
  const empty   = BAR_WIDTH - filled;
  const bar     = "█".repeat(filled) + "░".repeat(empty);

  if (clamped >= 80) return chalk.green(bar);
  if (clamped >= 50) return chalk.yellow(bar);
  return chalk.red(bar);
}

// ---------------------------------------------------------------------------
// Score badge
// ---------------------------------------------------------------------------

export function renderScoreBadge(score) {
  const clamped = Math.min(100, Math.max(0, score));

  let grade, colourFn;
  if (clamped >= 90) { grade = "A · Secure";         colourFn = chalk.green.bold; }
  else if (clamped >= 80) { grade = "B · Good";       colourFn = chalk.green; }
  else if (clamped >= 65) { grade = "C · Fair";       colourFn = chalk.yellow.bold; }
  else if (clamped >= 50) { grade = "D · At Risk";    colourFn = chalk.yellow; }
  else                    { grade = "F · Vulnerable"; colourFn = chalk.red.bold; }

  return colourFn(`${clamped}/100  ${grade}`);
}

// ---------------------------------------------------------------------------
// Score header box
// ---------------------------------------------------------------------------

export function renderScoreBox({ score, totalPenalty, issueCount, projectPath }) {
  const bar   = renderProgressBar(score);
  const badge = renderScoreBadge(score);

  const content = [
    chalk.bold.white("auth-doctor") + chalk.dim("  v1.0.0"),
    chalk.dim(path.resolve(projectPath)),
    "",
    `${bar}  ${badge}`,
    chalk.dim(`${issueCount} issue${issueCount !== 1 ? "s" : ""}  ·  penalty -${totalPenalty}pts`),
  ].join("\n");

  return boxen(content, {
    padding: { top: 0, bottom: 0, left: 2, right: 2 },
    margin: { top: 1, bottom: 0 },
    borderStyle: "round",
    borderColor: score >= 80 ? "green" : score >= 50 ? "yellow" : "red",
  });
}

// ---------------------------------------------------------------------------
// Numbered issue list (react-doctor style)
// ---------------------------------------------------------------------------

export function renderIssueList(issues, { colour = true } = {}) {
  if (issues.length === 0) {
    return colour
      ? chalk.green("\n  ✓  No security issues detected — looking solid!\n")
      : "\n  No security issues detected.\n";
  }

  const grouped = groupByRule(issues);
  const orderedGroups = [
    ...RULE_ORDER.filter((r) => grouped[r]),
    ...Object.keys(grouped).filter((r) => !RULE_ORDER.includes(r)),
  ];

  const lines = [""];
  let idx = 1;

  for (const rule of orderedGroups) {
    const ruleIssues = grouped[rule];
    const meta = RULE_META[rule] ?? {
      badge: "INFO",
      badgeFn: (s) => `[${s}]`,
      category: "Security",
      label: rule,
      explanation: "",
      realWorld: "",
      severity: "info",
      docs: "https://noctisnova.com/docs/auth",
    };

    const count      = ruleIssues.length;
    const badgeStr   = colour ? meta.badgeFn(meta.badge) : `[${meta.badge}]`;
    const heading    = colour ? chalk.bold(`${meta.category}: ${meta.label}`) : `${meta.category}: ${meta.label}`;
    const countStr   = colour ? chalk.dim(`(×${count})`) : `(×${count})`;

    lines.push(`${idx}. ${badgeStr} ${heading} ${countStr}`);

    if (meta.explanation) {
      lines.push(`   ${colour ? chalk.white(meta.explanation) : meta.explanation}`);
    }
    if (meta.realWorld) {
      lines.push(`   ${colour ? chalk.dim(meta.realWorld) : meta.realWorld}`);
    }

    const fixLabel = colour
      ? chalk.dim("   Read the canonical fix before touching the code:")
      : "   Read the canonical fix before touching the code:";
    const fixLink = colour ? chalk.cyan(` ${meta.docs}`) : ` ${meta.docs}`;
    lines.push(`${fixLabel}${fixLink}`);

    const shown    = ruleIssues.slice(0, MAX_FILES);
    const overflow = ruleIssues.length - shown.length;

    for (const issue of shown) {
      const loc = `${issue.file}:${issue.line}`;
      lines.push(colour ? `   ${chalk.dim("-")} ${chalk.cyan(loc)}` : `   - ${loc}`);
    }
    if (overflow > 0) {
      const more = `   +${overflow} more file${overflow !== 1 ? "s" : ""}`;
      lines.push(colour ? chalk.dim(more) : more);
    }

    lines.push("");
    idx++;
  }

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Full dashboard
// ---------------------------------------------------------------------------

export function renderDashboard({ score, totalPenalty, issues, projectPath }) {
  const reportPath = path.resolve(REPORT_FILE);
  const parts = [];

  parts.push(renderScoreBox({ score, totalPenalty, issueCount: issues.length, projectPath }));

  if (issues.length === 0) {
    parts.push(chalk.green("\n  ✓  No security issues detected — your auth looks solid!\n"));
    return parts.join("\n");
  }

  parts.push(renderIssueList(issues, { colour: true }));

  parts.push(chalk.dim("Full results for all " + issues.length + ` issue${issues.length !== 1 ? "s" : ""} (.auth-doctor-report.json):`));
  parts.push(chalk.cyan(reportPath));
  parts.push("");
  parts.push(chalk.dim("Fix the root cause — don't suppress or work around the rule."));
  parts.push("");
  parts.push(
    chalk.dim("Verify: re-run ") +
    chalk.white("`npx auth-doctor`") +
    chalk.dim(" and confirm the issue count drops before moving on.")
  );
  parts.push("");
  parts.push(chalk.dim("─".repeat(64)));
  parts.push(
    chalk.dim("  Built by ") + chalk.magenta.bold("NoctisNova") +
    chalk.dim("  ·  noctisnova.com  ·  hello@noctisnova.com")
  );
  parts.push("");

  return parts.join("\n");
}

// ---------------------------------------------------------------------------
// Summary line
// ---------------------------------------------------------------------------

export function renderSummaryLine(score, issueCount) {
  const bar   = renderProgressBar(score);
  const label = issueCount === 0
    ? chalk.green("No issues found.")
    : chalk.yellow(`${issueCount} issue${issueCount !== 1 ? "s" : ""} found.`);
  return `  ${bar}  ${label}`;
}

// ---------------------------------------------------------------------------
// Agent prompt builder
// ---------------------------------------------------------------------------

export function buildAgentPrompt(issues, reportPath) {
  const grouped = groupByRule(issues);
  const orderedGroups = [
    ...RULE_ORDER.filter((r) => grouped[r]),
    ...Object.keys(grouped).filter((r) => !RULE_ORDER.includes(r)),
  ];

  const companyContext = [
    "CODEBASE CONTEXT — READ BEFORE TOUCHING ANY FILE",
    "──────────────────────────────────────────────────",
    "This is a NoctisNova codebase (https://noctisnova.com).",
    "NoctisNova is a future-focused AI + engineering studio building Next.js/TypeScript/Prisma",
    "applications and live AI products (Nova, Pulse, Lens, Signal).",
    "",
    "Auth stack in use (verify before assuming):",
    "  - NextAuth v5 / Auth.js (auth() from 'next-auth') — most common",
    "  - Clerk (auth(), currentUser(), clerkMiddleware())",
    "  - Supabase Auth (createServerClient, supabase.auth.getUser())",
    "  - Check package.json and lib/auth.ts to confirm which is used",
    "",
    "Security conventions:",
    "  - All auth checks must be the FIRST operation in any route or Server Action",
    "  - Never trust client-supplied IDs without verifying ownership",
    "  - Tokens must be in httpOnly, Secure, SameSite=Lax cookies — never localStorage",
    "  - Always use jwt.verify() never jwt.decode() for security decisions",
    "  - Server Actions are not protected by being 'server-side' — treat them as API endpoints",
    "──────────────────────────────────────────────────",
    "",
  ].join("\n");

  const header = `Fix all ${issues.length} security issue${issues.length !== 1 ? "s" : ""} detected by auth-doctor in this NoctisNova codebase — leave unrelated code untouched.`;

  const issueBlock = renderIssueList(issues, { colour: false });

  const footer = [
    `Full results (.auth-doctor-report.json): ${reportPath}`,
    "",
    "Fix each issue at the root cause — no suppression, no comments saying 'TODO: add auth'.",
    "",
    "Verify: re-run `npx auth-doctor` and confirm every fixed issue disappears from the report.",
    "",
    "Teach me as you go: for each issue explain in plain language what the vulnerability is, " +
    "how an attacker would exploit it, and what the concrete real-world impact would be on " +
    "NoctisNova's users (e.g. 'any visitor can delete any account' vs 'minor logging gap').",
    "",
    "Prioritise CRIT issues first — they represent exploitable vulnerabilities, not just bad practice.",
    "",
    "─────────────────────────────────────────────────────────────────",
    "auth-doctor  ·  Built by NoctisNova  ·  https://noctisnova.com",
  ].join("\n");

  return [companyContext, header, issueBlock, footer].join("\n");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function groupByRule(issues) {
  const grouped = {};
  for (const issue of issues) {
    (grouped[issue.rule] ??= []).push(issue);
  }
  return grouped;
}
