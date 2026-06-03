/**
 * context.js — auth-doctor
 *
 * Builds a security context for the project so the scanner is ACCURATE, not just
 * noisy. The big win here is middleware-awareness: Next.js routes can be gated by
 * `middleware.ts` via a `matcher`. Without knowing that, every protected route
 * looks "unprotected". This module parses the middleware matcher + auth provider
 * so index.js can suppress false positives and tailor the report header.
 */

import fs from "node:fs";
import path from "node:path";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function readIfExists(file) {
  try { return fs.readFileSync(file, "utf-8"); } catch { return null; }
}

function ver(range) { const m = String(range ?? "").match(/(\d+)/); return m ? ` ${m[1]}` : ""; }

/**
 * Derives a Next.js route path from a route-handler file path.
 * e.g. src/app/api/users/[id]/route.ts → /api/users/[id]
 */
export function routePathFromFile(relFile) {
  const norm = relFile.replace(/\\/g, "/");
  const m = norm.match(/(?:^|\/)((?:src\/)?app\/.*?)\/route\.[tj]sx?$/);
  if (!m) return null;
  let p = m[1].replace(/^(src\/)?app/, "").replace(/\/\([^)]*\)/g, ""); // strip route groups
  return p === "" ? "/" : p;
}

// ---------------------------------------------------------------------------
// Auth-present detection for middleware
// ---------------------------------------------------------------------------

const MIDDLEWARE_AUTH_RE = /\bauth\b|getToken|clerkMiddleware|authMiddleware|withAuth|updateSession|getServerSession|createMiddlewareClient|withClerkMiddleware|NextResponse\.redirect/;

/**
 * Parses a Next.js middleware `config.matcher` into matcher strings.
 */
function parseMatchers(source) {
  const out = [];
  const m = source.match(/matcher\s*:\s*(\[[\s\S]*?\]|["'`][^"'`]+["'`])/);
  if (!m) return out;
  const block = m[1];
  for (const lit of block.matchAll(/["'`]([^"'`]+)["'`]/g)) out.push(lit[1]);
  return out;
}

/**
 * Turns a matcher string into a coverage test. Next matchers may use
 * negative-lookahead catch-alls ('/((?!_next).*)') → treated as "covers all".
 */
function matcherCovers(matcher, routePath) {
  if (/\(\?!/.test(matcher)) return true; // catch-all negative lookahead
  // static prefix = up to the first dynamic token
  const prefix = matcher.split(/[:(*]/)[0].replace(/\/$/, "") || "/";
  if (prefix === "/") return true;
  return routePath === prefix || routePath.startsWith(prefix + "/");
}

// ---------------------------------------------------------------------------
// Public: detect the security context
// ---------------------------------------------------------------------------

export function detectSecurityContext(projectPath) {
  const root = path.resolve(projectPath);

  let pkg = {};
  try { pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf-8")); } catch { /* */ }
  const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };

  const labels = [];
  let provider = null;
  if (deps["next-auth"] || deps["@auth/core"]) { labels.push(`NextAuth${ver(deps["next-auth"])}`); provider ??= "NextAuth"; }
  if (deps["@clerk/nextjs"])                   { labels.push("Clerk");      provider ??= "Clerk"; }
  if (deps["@supabase/supabase-js"] || deps["@supabase/ssr"]) { labels.push("Supabase"); provider ??= "Supabase"; }
  if (deps["lucia"])                           { labels.push("Lucia");      provider ??= "Lucia"; }
  if (deps["jsonwebtoken"] || deps["jose"])    labels.push("JWT");
  if (deps["iron-session"])                    labels.push("iron-session");
  if (deps.next)                               labels.push(`Next.js${ver(deps.next)}`);

  // Rate-limit library present anywhere?
  const rateLimitLib = Object.keys(deps).some((d) =>
    /ratelimit|rate-limit|rate-limiter|@upstash\/ratelimit|throttl/i.test(d)
  );
  if (rateLimitLib) labels.push("rate-limiting");

  // Middleware
  const mwCandidates = ["middleware.ts", "middleware.js", "src/middleware.ts", "src/middleware.js"];
  let middlewareSource = null, middlewareFile = null;
  for (const c of mwCandidates) {
    const src = readIfExists(path.join(root, c));
    if (src != null) { middlewareSource = src; middlewareFile = c; break; }
  }

  const hasMiddleware = middlewareSource != null;
  const authMiddleware = hasMiddleware && MIDDLEWARE_AUTH_RE.test(middlewareSource);
  const matchers = hasMiddleware ? parseMatchers(middlewareSource) : [];
  if (authMiddleware) labels.push("auth-middleware");

  /**
   * True when the given route-handler file is gated by an auth middleware
   * matcher (so "unprotected route" findings for it are false positives).
   */
  function isRouteCoveredByAuthMiddleware(relFile) {
    if (!authMiddleware) return false;
    if (matchers.length === 0) return false; // matcher absent = runs on everything in older setups, but be conservative
    const routePath = routePathFromFile(relFile);
    if (!routePath) return false;
    return matchers.some((mt) => matcherCovers(mt, routePath));
  }

  return {
    labels,
    provider,
    rateLimitLib,
    hasMiddleware,
    authMiddleware,
    middlewareFile,
    matchers,
    isRouteCoveredByAuthMiddleware,
  };
}
