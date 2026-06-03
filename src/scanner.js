/**
 * scanner.js — auth-doctor
 * AST-based static analyser for authentication and security vulnerabilities.
 * Targets Next.js App Router + TypeScript codebases.
 */

import { Project, SyntaxKind } from "ts-morph";
import fs from "node:fs";
import path from "node:path";

// ---------------------------------------------------------------------------
// Penalty constants
// ---------------------------------------------------------------------------

const PENALTY_UNPROTECTED_ROUTE    = 20;
const PENALTY_UNPROTECTED_ACTION   = 20;
const PENALTY_LOCALSTORAGE_SESSION = 15;
const PENALTY_JWT_NO_VERIFY        = 20;
const PENALTY_CSRF_MISSING         = 10;

const REPORT_FILE = "./.auth-doctor-report.json";

// ---------------------------------------------------------------------------
// Auth check pattern catalogue
// ---------------------------------------------------------------------------

/**
 * Any of these appearing in a function body means auth IS checked.
 * Covers: NextAuth v4/v5, Clerk, Auth.js, Supabase, custom patterns.
 */
const AUTH_PRESENT_PATTERNS = [
  /\bauth\s*\(\s*\)/,                         // auth() — NextAuth v5 / Clerk
  /\bgetServerSession\s*\(/,                   // NextAuth v4
  /\bcurrentUser\s*\(\s*\)/,                   // Clerk
  /\bgetToken\s*\(/,                           // NextAuth getToken
  /\bverifyToken\s*\(/,                        // custom / Firebase
  /\brequireAuth\s*\(/,                        // custom guard
  /\bauthenticate\s*\(/,                       // custom guard
  /\bvalidateSession\s*\(/,                    // custom guard
  /\bcheckAuth\s*\(/,                          // custom guard
  /\bprotectRoute\s*\(/,                       // custom guard
  /\bgetSession\s*\(/,                         // generic session getter
  /\buseAuth\s*\(/,                            // custom hook (server-side)
  /\.get\s*\(\s*['"`]authorization['"`]\s*\)/, // headers().get('authorization')
  /cookies\s*\(\s*\)\s*\.\s*(get|has)\s*\(/,  // cookies().get('session')
  /\bjwt\.verify\s*\(/,                        // manual JWT verify
  /\bcreateServerClient\s*\(/,                 // Supabase server client
  /\bsupabase\s*\.\s*auth\s*\.\s*getUser/,    // Supabase auth
  /if\s*\(\s*![\w.]+(?:session|user|token|auth)/i, // if (!session) guard
  /NextResponse\.redirect.*(?:login|signin|auth)/,  // redirect to login
  /unauthorize|forbidden|401|403/i,            // explicit rejection
];

/**
 * HTTP mutation methods that need auth checks in Route Handlers.
 * GET is intentionally excluded — public GETs are often fine.
 */
const MUTATION_EXPORTS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

/**
 * Patterns indicating session or auth data being written to localStorage.
 */
const LOCALSTORAGE_SENSITIVE_KEYS = [
  /localStorage\s*\.\s*setItem\s*\(\s*['"`](?:token|auth|session|user|jwt|access_token|refresh_token|id_token|bearer|credential|secret|key|api.?key)['"`]/i,
  /localStorage\s*\.\s*setItem\s*\(\s*\w+\s*,\s*(?:token|session|jwt|auth)/i,
  // Storing a value that looks like a JWT (three base64 segments)
  /localStorage\s*\.\s*setItem\s*\([^)]*[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/,
];

/**
 * JWT decode-without-verify patterns.
 */
const JWT_UNSAFE_PATTERNS = [
  /\bjwt\.decode\s*\(/,                                          // jsonwebtoken decode()
  /jwtDecode\s*\(/,                                              // jwt-decode library
  /JSON\.parse\s*\(\s*(?:atob|Buffer\.from)\s*\([^)]*split/,   // manual b64 decode
  /atob\s*\(\s*\w*token\w*\.split\s*\(\s*['"`.]['"`]\s*\)\s*\[/i, // atob(token.split('.')[1])
  /\bBase64\.decode\s*\([^)]*\btoken\b/i,                       // Base64.decode with token
];

/**
 * Patterns that indicate CSRF protection IS present.
 */
const CSRF_PRESENT_PATTERNS = [
  /csrf/i,
  /csurf/i,
  /csrfToken/i,
  /x-csrf-token/i,
  /x-requested-with/i,
  /same.?site/i,
  /verifyCSRF/i,
  /checkCsrf/i,
  /origin.*header/i,
  /referer.*header/i,
];

// ---------------------------------------------------------------------------
// Dead code patterns (same as orm-doctor — skip test/mock files)
// ---------------------------------------------------------------------------

const DEAD_CODE_PATTERNS = [
  /\.test\.[tj]sx?$/,
  /\.spec\.[tj]sx?$/,
  /\.mock\.[tj]sx?$/,
  /\.stub\.[tj]sx?$/,
  /\/__tests__\//,
  /\/__mocks__\//,
  /\/test\//,
  /\/tests\//,
  /\/e2e\//,
  /\/cypress\//,
  /\/playwright\//,
];

export function isDeadCode(filePath) {
  const norm = filePath.replace(/\\/g, "/");
  return DEAD_CODE_PATTERNS.some((re) => re.test(norm));
}

// ---------------------------------------------------------------------------
// File collection utilities
// ---------------------------------------------------------------------------

/**
 * Walks a directory tree collecting TypeScript/TSX source files,
 * skipping node_modules, dist, .next, and .git.
 */
export function collectSourceFiles(rootPath) {
  const results = [];
  function walk(dir) {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (["node_modules", "dist", ".next", ".nuxt", "out", ".git", ".turbo"].includes(entry.name)) continue;
        walk(full);
      } else if (entry.isFile() && /\.[tj]sx?$/.test(entry.name) && !entry.name.endsWith(".d.ts")) {
        results.push(full);
      }
    }
  }
  walk(path.resolve(rootPath));
  return results;
}

/**
 * Returns true if the file path matches the Next.js App Router API route pattern.
 */
function isApiRoute(filePath) {
  const norm = filePath.replace(/\\/g, "/");
  return /\/app\/api\/[^/].*\/route\.[tj]sx?$/.test(norm) ||
         /\/app\/api\/route\.[tj]sx?$/.test(norm);
}

/**
 * Returns true if the file contains a 'use server' directive (Server Action file).
 */
function isServerActionFile(source) {
  return /^['"`]use server['"`]/m.test(source) ||
         /^\s*['"`]use server['"`]\s*;/m.test(source);
}

/**
 * Trims a code snippet to its first non-empty line, capped at 120 chars.
 */
function trimSnippet(text) {
  const first = text.split("\n").map((l) => l.trim()).find((l) => l.length > 0) ?? text.trim();
  return first.length > 120 ? first.slice(0, 117) + "..." : first;
}

/**
 * Returns true if bodyText contains any auth check pattern.
 */
function hasAuthCheck(bodyText) {
  return AUTH_PRESENT_PATTERNS.some((re) => re.test(bodyText));
}

// ---------------------------------------------------------------------------
// Rule 1 — Unprotected API Route Handlers
// ---------------------------------------------------------------------------

/**
 * Scans Next.js App Router route files for exported mutation handlers
 * (POST, PUT, PATCH, DELETE) that contain no recognisable auth check.
 *
 * @param {string} projectPath
 * @returns {Promise<object[]>}
 */
export async function scanUnprotectedRoutes(projectPath) {
  const issues = [];
  const resolvedPath = path.resolve(projectPath);
  const allFiles = collectSourceFiles(resolvedPath);
  const routeFiles = allFiles.filter(isApiRoute);

  if (routeFiles.length === 0) return issues;

  const project = new Project({
    skipAddingFilesFromTsConfig: true,
    skipFileDependencyResolution: true,
    compilerOptions: { allowJs: true, noEmit: true },
  });

  for (const filePath of routeFiles) {
    let sourceFile;
    try { sourceFile = project.addSourceFileAtPath(filePath); } catch { continue; }

    const relPath = path.relative(resolvedPath, filePath).replace(/\\/g, "/");
    const fullSource = sourceFile.getFullText();

    // Collect all exported function declarations and arrow functions
    const exportedFunctions = [
      ...sourceFile.getFunctions().filter((f) => f.isExported()),
      ...sourceFile.getVariableDeclarations().filter((v) => {
        const init = v.getInitializer();
        return (
          v.getVariableStatement()?.isExported() &&
          init &&
          (init.getKind() === SyntaxKind.ArrowFunction ||
            init.getKind() === SyntaxKind.FunctionExpression)
        );
      }),
    ];

    for (const fn of exportedFunctions) {
      const name = "getName" in fn ? fn.getName() : fn.getName?.();
      if (!name || !MUTATION_EXPORTS.has(name.toUpperCase())) continue;

      const bodyText = fn.getText();

      // Skip if any auth pattern is found in the function OR at module level
      // (some handlers call a shared auth() at the top of the file)
      if (hasAuthCheck(bodyText) || hasAuthCheck(fullSource.slice(0, 800))) continue;

      const line = sourceFile.getLineAndColumnAtPos(fn.getStart?.() ?? 0).line;

      issues.push({
        type: "Unprotected Route",
        rule: "unprotected-route",
        severity: "critical",
        file: relPath,
        line,
        snippet: trimSnippet(`export async function ${name}(req)`),
        message: `Exported \`${name}\` handler in API route has no detectable auth check — any unauthenticated request can call this endpoint.`,
        docs: "https://noctisnova.com/tools/auth-doctor/auth-security-best-practices",
        penalty: PENALTY_UNPROTECTED_ROUTE,
      });
    }

    project.removeSourceFile(sourceFile);
  }

  return issues;
}

// ---------------------------------------------------------------------------
// Rule 2 — Unprotected Server Actions
// ---------------------------------------------------------------------------

/**
 * Finds files with a 'use server' directive and checks each exported async
 * function for an auth check at or near the top of the function body.
 *
 * @param {string} projectPath
 * @returns {Promise<object[]>}
 */
export async function scanUnprotectedServerActions(projectPath) {
  const issues = [];
  const resolvedPath = path.resolve(projectPath);
  const allFiles = collectSourceFiles(resolvedPath);

  const project = new Project({
    skipAddingFilesFromTsConfig: true,
    skipFileDependencyResolution: true,
    compilerOptions: { allowJs: true, noEmit: true },
  });

  for (const filePath of allFiles) {
    if (isDeadCode(filePath)) continue;

    let source;
    try { source = fs.readFileSync(filePath, "utf-8"); } catch { continue; }

    // Only process files that are Server Action files
    if (!isServerActionFile(source)) continue;

    let sourceFile;
    try { sourceFile = project.addSourceFileAtPath(filePath); } catch { continue; }

    const relPath = path.relative(resolvedPath, filePath).replace(/\\/g, "/");

    const exportedFns = [
      ...sourceFile.getFunctions().filter((f) => f.isExported() && f.isAsync()),
      ...sourceFile.getVariableDeclarations().filter((v) => {
        const stmt = v.getVariableStatement();
        const init = v.getInitializer();
        return (
          stmt?.isExported() &&
          init?.getKind() === SyntaxKind.ArrowFunction
        );
      }),
    ];

    for (const fn of exportedFns) {
      const bodyText = fn.getText();

      // Only check the first ~30 lines of the body — auth should be at the top
      const bodyLines = bodyText.split("\n").slice(0, 30).join("\n");

      if (hasAuthCheck(bodyLines) || hasAuthCheck(bodyText)) continue;

      const name = fn.getName?.() ?? "anonymous";
      const line = sourceFile.getLineAndColumnAtPos(fn.getStart?.() ?? 0).line;

      issues.push({
        type: "Unprotected Server Action",
        rule: "unprotected-action",
        severity: "critical",
        file: relPath,
        line,
        snippet: trimSnippet(`export async function ${name}()`),
        message: `Server Action \`${name}\` has no auth check — Server Actions are directly callable by clients and must verify the caller's identity before mutating data.`,
        docs: "https://noctisnova.com/tools/auth-doctor/auth-security-best-practices",
        penalty: PENALTY_UNPROTECTED_ACTION,
      });
    }

    project.removeSourceFile(sourceFile);
  }

  return issues;
}

// ---------------------------------------------------------------------------
// Rule 3 — Session / token data stored in localStorage
// ---------------------------------------------------------------------------

/**
 * Scans client-side source files for localStorage.setItem calls that store
 * session tokens, JWTs, or auth credentials.
 *
 * @param {string} projectPath
 * @returns {Promise<object[]>}
 */
export async function scanLocalStorageSessionStorage(projectPath) {
  const issues = [];
  const resolvedPath = path.resolve(projectPath);
  const allFiles = collectSourceFiles(resolvedPath);

  for (const filePath of allFiles) {
    if (isDeadCode(filePath)) continue;

    let source;
    try { source = fs.readFileSync(filePath, "utf-8"); } catch { continue; }

    // Only flag in files likely rendered on the client
    // (server components shouldn't have localStorage at all — but flag if found)
    const lines = source.split("\n");
    const relPath = path.relative(resolvedPath, filePath).replace(/\\/g, "/");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line.includes("localStorage")) continue;

      if (LOCALSTORAGE_SENSITIVE_KEYS.some((re) => re.test(line))) {
        issues.push({
          type: "Insecure Token Storage",
          rule: "localstorage-session",
          severity: "critical",
          file: relPath,
          line: i + 1,
          snippet: trimSnippet(line),
          message:
            "Auth token or session data written to localStorage — XSS attacks can steal it. " +
            "Use httpOnly cookies (set server-side) which are inaccessible to JavaScript.",
          docs: "https://noctisnova.com/tools/auth-doctor/auth-security-best-practices",
          penalty: PENALTY_LOCALSTORAGE_SESSION,
        });
      }
    }
  }

  return issues;
}

// ---------------------------------------------------------------------------
// Rule 4 — JWT decoded without signature verification
// ---------------------------------------------------------------------------

/**
 * Finds calls to jwt.decode() or manual base64 JWT decoding — patterns that
 * read JWT payload without verifying the signature, meaning the data can be
 * tampered with by the client.
 *
 * @param {string} projectPath
 * @returns {Promise<object[]>}
 */
export async function scanJwtWithoutVerification(projectPath) {
  const issues = [];
  const resolvedPath = path.resolve(projectPath);
  const allFiles = collectSourceFiles(resolvedPath);

  for (const filePath of allFiles) {
    if (isDeadCode(filePath)) continue;

    let source;
    try { source = fs.readFileSync(filePath, "utf-8"); } catch { continue; }

    const lines = source.split("\n");
    const relPath = path.relative(resolvedPath, filePath).replace(/\\/g, "/");

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];

      if (!JWT_UNSAFE_PATTERNS.some((re) => re.test(line))) continue;

      // Skip if jwt.verify() also appears in the same file — may be intentional decode for header inspection
      const fileHasVerify = /jwt\.verify\s*\(/.test(source);
      if (fileHasVerify) continue;

      // Skip comments
      if (/^\s*\/\//.test(line) || /^\s*\*/.test(line)) continue;

      issues.push({
        type: "JWT Without Verification",
        rule: "jwt-no-verify",
        severity: "critical",
        file: relPath,
        line: i + 1,
        snippet: trimSnippet(line),
        message:
          "JWT is decoded without signature verification — a client can forge any payload by crafting a token with a matching header/payload and an invalid signature. " +
          "Always use jwt.verify(token, secret) to validate both the signature and expiry.",
        docs: "https://noctisnova.com/tools/auth-doctor/jwt-security",
        penalty: PENALTY_JWT_NO_VERIFY,
      });
    }
  }

  return issues;
}

// ---------------------------------------------------------------------------
// Rule 5 — Missing CSRF protection on mutation endpoints
// ---------------------------------------------------------------------------

/**
 * Scans Next.js App Router route files for POST/PUT/PATCH/DELETE handlers
 * that show no signs of CSRF protection (no token check, no origin check,
 * no CSRF library usage).
 *
 * Note: Routes that already have auth() checks get a pass — authenticated
 * sessions with SameSite=Lax cookies provide implicit CSRF protection in
 * most Next.js setups.
 *
 * @param {string} projectPath
 * @returns {Promise<object[]>}
 */
export async function scanMissingCsrf(projectPath) {
  const issues = [];
  const resolvedPath = path.resolve(projectPath);
  const allFiles = collectSourceFiles(resolvedPath);
  const routeFiles = allFiles.filter(isApiRoute);

  if (routeFiles.length === 0) return issues;

  const project = new Project({
    skipAddingFilesFromTsConfig: true,
    skipFileDependencyResolution: true,
    compilerOptions: { allowJs: true, noEmit: true },
  });

  for (const filePath of routeFiles) {
    let sourceFile;
    try { sourceFile = project.addSourceFileAtPath(filePath); } catch { continue; }

    const relPath = path.relative(resolvedPath, filePath).replace(/\\/g, "/");
    const fullSource = sourceFile.getFullText();

    // If the whole file has CSRF protection at module level, skip
    if (CSRF_PRESENT_PATTERNS.some((re) => re.test(fullSource))) {
      project.removeSourceFile(sourceFile);
      continue;
    }

    // If the route is already auth-protected AND uses session cookies (SameSite),
    // CSRF risk is low — skip to avoid noise
    if (hasAuthCheck(fullSource)) {
      project.removeSourceFile(sourceFile);
      continue;
    }

    const exportedFunctions = [
      ...sourceFile.getFunctions().filter((f) => f.isExported()),
      ...sourceFile.getVariableDeclarations().filter((v) => {
        const init = v.getInitializer();
        return (
          v.getVariableStatement()?.isExported() &&
          init &&
          (init.getKind() === SyntaxKind.ArrowFunction ||
            init.getKind() === SyntaxKind.FunctionExpression)
        );
      }),
    ];

    for (const fn of exportedFunctions) {
      const name = "getName" in fn ? fn.getName() : fn.getName?.();
      if (!name || !MUTATION_EXPORTS.has(name.toUpperCase())) continue;

      const bodyText = fn.getText();
      if (CSRF_PRESENT_PATTERNS.some((re) => re.test(bodyText))) continue;

      const line = sourceFile.getLineAndColumnAtPos(fn.getStart?.() ?? 0).line;

      issues.push({
        type: "Missing CSRF Protection",
        rule: "csrf-missing",
        severity: "warning",
        file: relPath,
        line,
        snippet: trimSnippet(`export async function ${name}(req)`),
        message:
          `\`${name}\` handler has no CSRF protection and no session-based auth — a malicious site can trick a logged-in user's browser into making this request without their knowledge.`,
        docs: "https://noctisnova.com/tools/auth-doctor/advanced-auth-security",
        penalty: PENALTY_CSRF_MISSING,
      });
    }

    project.removeSourceFile(sourceFile);
  }

  return issues;
}

// ---------------------------------------------------------------------------
// Main orchestrator
// ---------------------------------------------------------------------------

/**
 * Runs all security scanners in parallel and writes the report file.
 *
 * @param {object} opts
 * @param {string} opts.projectPath
 * @returns {Promise<{ issues, totalPenalty, score }>}
 */
export async function runAllScans({ projectPath }) {
  const [
    routeIssues,
    actionIssues,
    localStorageIssues,
    jwtIssues,
    csrfIssues,
  ] = await Promise.all([
    scanUnprotectedRoutes(projectPath),
    scanUnprotectedServerActions(projectPath),
    scanLocalStorageSessionStorage(projectPath),
    scanJwtWithoutVerification(projectPath),
    scanMissingCsrf(projectPath),
  ]);

  const issues = [
    ...routeIssues,
    ...actionIssues,
    ...localStorageIssues,
    ...jwtIssues,
    ...csrfIssues,
  ];

  const totalPenalty = issues.reduce((sum, i) => sum + i.penalty, 0);
  const score = Math.max(0, 100 - totalPenalty);

  const report = {
    generatedAt: new Date().toISOString(),
    projectPath: path.resolve(projectPath),
    score,
    totalPenalty,
    issueCount: issues.length,
    issues,
  };

  try {
    fs.writeFileSync(REPORT_FILE, JSON.stringify(report, null, 2), "utf-8");
  } catch { /* non-fatal */ }

  return { issues, totalPenalty, score };
}
