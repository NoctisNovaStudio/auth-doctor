/**
 * advanced.js — auth-doctor
 *
 * The advanced security engine — the vulnerabilities that actually get companies
 * breached, beyond "is there an auth() call":
 *
 *   • hardcoded-secret         — API keys / JWT secrets / private keys in source
 *   • public-env-secret        — secrets leaked to the browser via NEXT_PUBLIC_*
 *   • idor-missing-ownership    — update/delete by request id with no ownership check (BOLA, OWASP API #1)
 *   • open-redirect            — redirect() to a user-controlled URL
 *   • missing-rate-limit        — login/reset/OTP endpoints with no rate limiting
 *   • sensitive-field-exposure  — password/hash/secret fields returned in a response
 *
 * Tightly gated to keep false positives low. Test/mock files are skipped.
 */

import { Project, SyntaxKind } from "ts-morph";
import fs from "node:fs";
import path from "node:path";
import { collectSourceFiles, isDeadCode } from "./scanner.js";

// ---------------------------------------------------------------------------
// Penalties
// ---------------------------------------------------------------------------

const PENALTY_HARDCODED_SECRET = 20;
const PENALTY_PUBLIC_ENV_SECRET = 18;
const PENALTY_IDOR             = 18;
const PENALTY_OPEN_REDIRECT    = 10;
const PENALTY_MISSING_RATE_LIMIT = 8;
const PENALTY_SENSITIVE_EXPOSURE = 10;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

function makeProject() {
  return new Project({
    skipAddingFilesFromTsConfig: true,
    skipFileDependencyResolution: true,
    compilerOptions: { allowJs: true, noEmit: true },
  });
}

function liveFiles(projectPath) {
  return collectSourceFiles(path.resolve(projectPath)).filter((f) => !isDeadCode(f));
}

function trimSnippet(text, max = 110) {
  const first = text.split("\n").map((l) => l.trim()).find((l) => l.length > 0) ?? text.trim();
  return first.length > max ? first.slice(0, max - 3) + "..." : first;
}

/** Removes comments so presence checks don't match words in documentation. */
function stripComments(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, " ").replace(/(^|[^:])\/\/[^\n]*/g, "$1 ");
}

function isApiRoute(filePath) {
  const n = filePath.replace(/\\/g, "/");
  return /\/app\/api\/.*route\.[tj]sx?$/.test(n) || /\/app\/api\/route\.[tj]sx?$/.test(n);
}

/** Function-like nodes with a body, for scoped per-function analysis. */
function functionsWith(sf) {
  return [
    ...sf.getFunctions(),
    ...sf.getDescendantsOfKind(SyntaxKind.ArrowFunction),
    ...sf.getDescendantsOfKind(SyntaxKind.FunctionExpression),
    ...sf.getDescendantsOfKind(SyntaxKind.MethodDeclaration),
  ];
}

// ---------------------------------------------------------------------------
// Rule: hardcoded secrets
// ---------------------------------------------------------------------------

// Known high-confidence secret token shapes.
const SECRET_SIGNATURES = [
  { re: /\bsk_live_[A-Za-z0-9]{10,}/, what: "Stripe live secret key" },
  { re: /\bsk_test_[A-Za-z0-9]{10,}/, what: "Stripe test secret key" },
  { re: /\brk_live_[A-Za-z0-9]{10,}/, what: "Stripe restricted key" },
  { re: /\bAKIA[0-9A-Z]{16}\b/, what: "AWS access key id" },
  { re: /\bASIA[0-9A-Z]{16}\b/, what: "AWS temporary access key" },
  { re: /\bgh[pousr]_[A-Za-z0-9]{20,}/, what: "GitHub token" },
  { re: /\bgithub_pat_[A-Za-z0-9_]{20,}/, what: "GitHub fine-grained PAT" },
  { re: /\bAIza[0-9A-Za-z\-_]{30,}/, what: "Google API key" },
  { re: /\bxox[baprs]-[0-9A-Za-z-]{10,}/, what: "Slack token" },
  { re: /\bsk-[A-Za-z0-9]{20,}/, what: "OpenAI-style API key" },
  { re: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/, what: "private key" },
  { re: /\bSG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}/, what: "SendGrid API key" },
];

// jwt secret passed as a string literal
const JWT_LITERAL_SECRET_RE = /\bjwt\s*\.\s*(?:sign|verify)\s*\(\s*[^,]+,\s*(["'`])([^"'`]{4,})\1/;

// generic "secretName = 'value'" with a meaningful-looking value
const GENERIC_SECRET_RE =
  /\b(jwt[_-]?secret|client[_-]?secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|private[_-]?key|encryption[_-]?key|session[_-]?secret|cookie[_-]?secret)\b\s*[:=]\s*(["'`])([A-Za-z0-9_\-+/=]{12,})\2/i;

const PLACEHOLDER_RE = /^(your|xxx|change|example|placeholder|todo|dummy|fake|sample|test[_-]?secret|secret123|password123|\$\{|process\.env)/i;

export async function scanHardcodedSecrets(projectPath) {
  const issues = [];
  const resolved = path.resolve(projectPath);
  for (const filePath of liveFiles(resolved)) {
    let src; try { src = fs.readFileSync(filePath, "utf-8"); } catch { continue; }
    const rel = path.relative(resolved, filePath).replace(/\\/g, "/");
    const lines = src.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/^\s*(\/\/|\*)/.test(line)) continue; // comment

      let hit = null;

      for (const sig of SECRET_SIGNATURES) {
        if (sig.re.test(line)) { hit = sig.what; break; }
      }

      if (!hit) {
        const jm = line.match(JWT_LITERAL_SECRET_RE);
        if (jm && !PLACEHOLDER_RE.test(jm[2])) hit = "JWT signing secret";
      }

      if (!hit) {
        const gm = line.match(GENERIC_SECRET_RE);
        if (gm && !PLACEHOLDER_RE.test(gm[3])) hit = `hardcoded ${gm[1].toLowerCase()}`;
      }

      if (!hit) continue;

      issues.push({
        type: "Hardcoded Secret",
        rule: "hardcoded-secret",
        severity: "critical",
        file: rel,
        line: i + 1,
        snippet: trimSnippet(line.replace(/(["'`])([A-Za-z0-9_\-+/=]{6})[A-Za-z0-9_\-+/=]+(["'`])/, "$1$2…redacted$3")),
        message:
          `A ${hit} appears to be hardcoded in source. Anyone with repo access (or a leaked Git history) ` +
          "gets your production credentials. Move it to an environment variable (`process.env.X`), rotate the " +
          "exposed key immediately, and add it to a secret manager — committed secrets are compromised forever.",
        docs: "https://noctisnova.com/docs/auth/secret-management",
        penalty: PENALTY_HARDCODED_SECRET,
      });
    }
  }
  return issues;
}

// ---------------------------------------------------------------------------
// Rule: secrets leaked to the client via NEXT_PUBLIC_*
// ---------------------------------------------------------------------------

const PUBLIC_ENV_RE = /process\.env\.(NEXT_PUBLIC_[A-Z0-9_]+)/g;
const PUBLIC_SECRETY_RE = /(SECRET|PASSWORD|PRIVATE|CREDENTIAL|SERVICE_ROLE|CLIENT_SECRET|API_KEY|ACCESS_KEY|AUTH_TOKEN|_SK_|WEBHOOK_SECRET)/;
const PUBLIC_SAFE_RE = /(PUBLISHABLE|ANON|PUBLIC_KEY)/;

export async function scanPublicEnvSecrets(projectPath) {
  const issues = [];
  const resolved = path.resolve(projectPath);
  for (const filePath of liveFiles(resolved)) {
    let src; try { src = fs.readFileSync(filePath, "utf-8"); } catch { continue; }
    const rel = path.relative(resolved, filePath).replace(/\\/g, "/");
    const lines = src.split("\n");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      for (const m of line.matchAll(PUBLIC_ENV_RE)) {
        const name = m[1];
        if (PUBLIC_SAFE_RE.test(name)) continue;
        if (!PUBLIC_SECRETY_RE.test(name)) continue;

        issues.push({
          type: "Public Env Secret",
          rule: "public-env-secret",
          severity: "critical",
          file: rel,
          line: i + 1,
          snippet: trimSnippet(line),
          message:
            `\`${name}\` is a NEXT_PUBLIC_ variable — Next.js inlines its value into the JavaScript bundle ` +
            "shipped to every browser. A name like this holds a secret, so it's now public to the world. " +
            "Rename it without the NEXT_PUBLIC_ prefix, read it only on the server, and rotate the value.",
          docs: "https://noctisnova.com/docs/auth/secret-management",
          penalty: PENALTY_PUBLIC_ENV_SECRET,
        });
      }
    }
  }
  return issues;
}

// ---------------------------------------------------------------------------
// Rule: IDOR / missing ownership check (BOLA)
// ---------------------------------------------------------------------------

const BY_ID_WRITE_RE = /\b(?:prisma|db|tx|trx)\s*\.\s*\w+\s*\.\s*(update|delete)\s*\(\s*\{[\s\S]{0,200}?\bwhere\b[\s\S]{0,120}?\bid\b/;
const READS_EXTERNAL_ID_RE = /params\s*[.)]|searchParams\s*\.\s*get|req\s*\.\s*query|\.query\s*\.|await\s+req\.json|await\s+request\.json|context\s*\.\s*params|\bbody\s*\.\s*\w*[Ii]d\b|formData\s*\.\s*get|formData\b/;
const OWNERSHIP_SCOPE_RE = /userId|ownerId|authorId|accountId|tenantId|organi[sz]ationId|createdById|session\s*\.\s*user|\buser\s*\.\s*id\b|currentUser|getServerSession|\bauth\s*\(\s*\)/;

export async function scanIdorOwnership(projectPath) {
  const issues = [];
  const resolved = path.resolve(projectPath);
  const project = makeProject();

  for (const filePath of liveFiles(resolved)) {
    let src; try { src = fs.readFileSync(filePath, "utf-8"); } catch { continue; }
    // Only meaningful in request-handling code
    const isServerAction = /^\s*['"`]use server['"`]/m.test(src);
    if (!isApiRoute(filePath) && !isServerAction) continue;

    let sf; try { sf = project.addSourceFileAtPath(filePath); } catch { continue; }
    const rel = path.relative(resolved, filePath).replace(/\\/g, "/");
    const seen = new Set();

    for (const fn of functionsWith(sf)) {
      const body = stripComments(fn.getBody?.()?.getText?.() ?? fn.getText());
      if (!BY_ID_WRITE_RE.test(body)) continue;       // mutates a row by id
      if (!READS_EXTERNAL_ID_RE.test(body)) continue; // id comes from the request
      if (OWNERSHIP_SCOPE_RE.test(body)) continue;    // already scoped to the caller

      const line = sf.getLineAndColumnAtPos(fn.getStart()).line;
      if (seen.has(line)) continue; seen.add(line);

      const m = body.match(/\.\s*(update|delete)\s*\(/);
      issues.push({
        type: "Broken Object-Level Authorization (IDOR)",
        rule: "idor-missing-ownership",
        severity: "critical",
        file: rel,
        line,
        snippet: trimSnippet(`prisma.*.${m ? m[1] : "update"}({ where: { id } }) — id from request, no ownership check`),
        message:
          "This handler updates/deletes a record using an id taken straight from the request, with no check " +
          "that the record belongs to the current user. That's an IDOR (OWASP API #1): any logged-in user can " +
          "tamper with anyone's data by changing the id. Scope the query — `where: { id, userId: session.user.id }` " +
          "— or fetch first and verify ownership before mutating.",
        docs: "https://noctisnova.com/docs/auth/object-level-authorization",
        penalty: PENALTY_IDOR,
      });
    }
    project.removeSourceFile(sf);
  }
  return issues;
}

// ---------------------------------------------------------------------------
// Rule: open redirect
// ---------------------------------------------------------------------------

const REDIRECT_CALL_RE = /(?:NextResponse\s*\.\s*redirect|(?<![.\w])redirect|res\s*\.\s*redirect)\s*\(\s*([^,)\n]+)/g;
const REQUEST_DERIVED_RE = /searchParams|req\s*\.\s*query|\.query\b|req\s*\.\s*url|request\s*\.\s*url|callbackUrl|returnTo|returnUrl|redirectTo|\bnextUrl\b|\bnext\b/;

export async function scanOpenRedirect(projectPath) {
  const issues = [];
  const resolved = path.resolve(projectPath);
  const project = makeProject();

  for (const filePath of liveFiles(resolved)) {
    let src; try { src = fs.readFileSync(filePath, "utf-8"); } catch { continue; }
    if (!/redirect\s*\(/.test(src)) continue;

    let sf; try { sf = project.addSourceFileAtPath(filePath); } catch { continue; }
    const rel = path.relative(resolved, filePath).replace(/\\/g, "/");
    const seen = new Set();

    for (const fn of functionsWith(sf)) {
      const body = stripComments(fn.getBody?.()?.getText?.() ?? fn.getText());
      if (!/redirect\s*\(/.test(body)) continue;

      for (const m of body.matchAll(REDIRECT_CALL_RE)) {
        const arg = m[1].trim();
        if (/^["'`]/.test(arg)) continue;            // string literal target — safe
        if (/^new\s+URL|^\//.test(arg)) continue;    // constructed/normalised — lower risk

        // Direct request-derived target, or a variable assigned from one.
        const directlyDerived = REQUEST_DERIVED_RE.test(arg);
        const varName = /^[A-Za-z_$][\w$]*$/.test(arg) ? arg : null;
        const varDerived = varName && new RegExp(
          `\\b(?:const|let|var)\\s+${varName}\\s*=\\s*[^;\\n]*(?:searchParams|req\\s*\\.\\s*query|\\.query|callbackUrl|returnTo|returnUrl|redirectTo|req\\.url|request\\.url)`
        ).test(body);

        if (!directlyDerived && !varDerived) continue;
        // Skip if there's an explicit allow-list / same-origin validation nearby
        if (/startsWith\(\s*["'`]\//.test(body) && /new\s+URL/.test(body)) continue;

        const line = sf.getLineAndColumnAtPos(fn.getStart()).line;
        const key = `${line}:${arg}`;
        if (seen.has(key)) continue; seen.add(key);

        issues.push({
          type: "Open Redirect",
          rule: "open-redirect",
          severity: "warning",
          file: rel,
          line,
          snippet: trimSnippet(`redirect(${arg})`),
          message:
            "A redirect target comes from user-controlled input (query string / request URL) with no allow-list. " +
            "Attackers craft links like `/login?next=https://evil.com` to bounce victims to phishing pages that look " +
            "like they came from your domain. Validate the target is a relative path you own (e.g. it starts with '/' " +
            "and isn't '//'), or match it against an allow-list before redirecting.",
          docs: "https://noctisnova.com/docs/auth/open-redirect",
          penalty: PENALTY_OPEN_REDIRECT,
        });
        break; // one per function
      }
    }
    project.removeSourceFile(sf);
  }
  return issues;
}

// ---------------------------------------------------------------------------
// Rule: missing rate limiting on auth-sensitive endpoints
// ---------------------------------------------------------------------------

const AUTH_SENSITIVE_PATH_RE = /(login|sign-?in|sign-?up|register|reset|forgot|otp|verify|password|magic-?link|2fa|mfa|token|authenticate|credentials)/i;
const RATE_LIMIT_PRESENT_RE = /ratelimit|rate-?limit|Ratelimit|limiter|throttl|@upstash\/ratelimit|leakyBucket|tokenBucket|slowDown/i;
const MUTATION_HANDLER_RE = /export\s+(?:async\s+)?function\s+(POST|PUT|PATCH)\b|export\s+const\s+(POST|PUT|PATCH)\s*=/;

export async function scanMissingRateLimit(projectPath) {
  const issues = [];
  const resolved = path.resolve(projectPath);

  for (const filePath of liveFiles(resolved)) {
    if (!isApiRoute(filePath)) continue;
    const n = filePath.replace(/\\/g, "/");
    if (!AUTH_SENSITIVE_PATH_RE.test(n)) continue;

    let src; try { src = fs.readFileSync(filePath, "utf-8"); } catch { continue; }
    const code = stripComments(src);
    if (!MUTATION_HANDLER_RE.test(code)) continue;     // only POST/PUT/PATCH endpoints
    if (RATE_LIMIT_PRESENT_RE.test(code)) continue;    // already rate-limited

    const rel = path.relative(resolved, filePath).replace(/\\/g, "/");
    const lines = src.split("\n");
    const line = Math.max(1, lines.findIndex((l) => MUTATION_HANDLER_RE.test(l)) + 1);

    issues.push({
      type: "Missing Rate Limit",
      rule: "missing-rate-limit",
      severity: "warning",
      file: rel,
      line,
      snippet: trimSnippet(`auth endpoint at ${rel} — no rate limiting`),
      message:
        "This looks like an authentication endpoint (login / register / reset / OTP) with no rate limiting. " +
        "Without it, attackers can brute-force passwords and OTPs and enumerate accounts at thousands of requests " +
        "per second. Add a limiter (e.g. @upstash/ratelimit) keyed by IP + identifier, with exponential backoff on failures.",
      docs: "https://noctisnova.com/docs/auth/rate-limiting",
      penalty: PENALTY_MISSING_RATE_LIMIT,
    });
  }
  return issues;
}

// ---------------------------------------------------------------------------
// Rule: sensitive field exposure in responses
// ---------------------------------------------------------------------------

const RESPONSE_CALL_RE = /(?:NextResponse|Response|res|response)\s*\.\s*(?:json|send)\s*\(/g;
const SENSITIVE_KEY_RE = /\b(password|passwordHash|hashedPassword|passwd|pwd|salt|secret|privateKey|api[_-]?key|sessionToken|refreshToken|mfaSecret|totpSecret|ssn)\s*:/i;

export async function scanSensitiveExposure(projectPath) {
  const issues = [];
  const resolved = path.resolve(projectPath);

  for (const filePath of liveFiles(resolved)) {
    let src; try { src = fs.readFileSync(filePath, "utf-8"); } catch { continue; }
    if (!/\.(?:json|send)\s*\(/.test(src)) continue;
    const rel = path.relative(resolved, filePath).replace(/\\/g, "/");

    for (const m of src.matchAll(RESPONSE_CALL_RE)) {
      // Inspect a window from the call to the next ~250 chars (the response body).
      const start = m.index ?? 0;
      const window = src.slice(start, start + 250);
      const km = window.match(SENSITIVE_KEY_RE);
      if (!km) continue;
      // Skip if it's being explicitly stripped (omit / select:false)
      if (/\bomit\s*:/.test(window) || new RegExp(`${km[1]}\\s*:\\s*(?:false|undefined)`, "i").test(window)) continue;

      const line = src.slice(0, start).split("\n").length;
      issues.push({
        type: "Sensitive Field Exposure",
        rule: "sensitive-field-exposure",
        severity: "warning",
        file: rel,
        line,
        snippet: trimSnippet(km[0]),
        message:
          `A response body includes a sensitive field (\`${km[1]}\`). Password hashes, secrets, and tokens must never ` +
          "leave the server — even hashed passwords help offline cracking and confirm account existence. Use Prisma " +
          "`select`/`omit` to return only safe fields, or map to a DTO before serialising.",
        docs: "https://noctisnova.com/docs/auth/sensitive-data-exposure",
        penalty: PENALTY_SENSITIVE_EXPOSURE,
      });
      break; // one per file to avoid noise
    }
  }
  return issues;
}

// ---------------------------------------------------------------------------
// Aggregate runner
// ---------------------------------------------------------------------------

export async function runAdvancedScans(projectPath) {
  const [secrets, publicEnv, idor, redirect, rateLimit, exposure] = await Promise.all([
    scanHardcodedSecrets(projectPath),
    scanPublicEnvSecrets(projectPath),
    scanIdorOwnership(projectPath),
    scanOpenRedirect(projectPath),
    scanMissingRateLimit(projectPath),
    scanSensitiveExposure(projectPath),
  ]);
  return [...secrets, ...publicEnv, ...idor, ...redirect, ...rateLimit, ...exposure];
}
