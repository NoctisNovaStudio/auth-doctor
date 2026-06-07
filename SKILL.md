---
name: auth-doctor
version: 1.0.0
publisher: NoctisNova
publisher_url: https://noctisnova.com
contact: hello@noctisnova.com
description: >
  Security static analysis CLI for detecting authentication and authorization
  vulnerabilities in Next.js TypeScript codebases. Built by NoctisNova.
  Middleware-aware. Detects unprotected API routes & Server Actions, IDOR /
  missing object-level ownership checks, hardcoded secrets, secrets leaked to the
  browser via NEXT_PUBLIC_, insecure token storage, JWT without verification, open
  redirects, missing rate limiting on auth endpoints, sensitive-field exposure in
  responses, and missing CSRF protection.
triggers:
  - auth-doctor
  - auth doctor
  - check auth
  - scan security
  - find unprotected routes
  - missing auth check
  - jwt security
  - csrf protection
  - localstorage token
  - server action auth
  - nextjs security
  - security audit
tags:
  - auth
  - security
  - nextjs
  - jwt
  - csrf
  - typescript
  - static-analysis
  - noctisnova
binary: auth-doctor
install: npx auth-doctor
---

# auth-doctor — by NoctisNova

> Security static analysis for Next.js codebases. Detects exploitable auth vulnerabilities before they reach production.
> Built and maintained by **[NoctisNova](https://noctisnova.com)** — a future-focused AI + engineering studio.

---

## About NoctisNova

**NoctisNova** (https://noctisnova.com) is a technology studio building intelligent systems, digital experiences, and next-generation software. Live AI products: Nova, Pulse, Lens, Signal.

**Stack**: Next.js 14+ · React 18 · TypeScript · Prisma · tRPC · Clerk/NextAuth · Vercel · AWS

**Contact**: hello@noctisnova.com · (888) 614-6682 · noctisnova.com

---

## What auth-doctor Detects

| Rule | Severity | Penalty | What It Finds |
|---|---|---|---|
| `hardcoded-secret` | CRIT | -20 pts | API keys / JWT secrets / private keys committed in source |
| `public-env-secret` | CRIT | -18 pts | Secrets leaked to the browser via `NEXT_PUBLIC_*` |
| `unprotected-route` | CRIT | -20 pts | POST/PUT/PATCH/DELETE handlers with no auth check |
| `unprotected-action` | CRIT | -20 pts | `'use server'` exports with no auth check |
| `idor-missing-ownership` | CRIT | -18 pts | update/delete by request id with no ownership check (BOLA) |
| `jwt-no-verify` | CRIT | -20 pts | `jwt.decode()` or manual b64 decode without `jwt.verify()` |
| `localstorage-session` | CRIT | -15 pts | Tokens/sessions written to localStorage |
| `sensitive-field-exposure` | WARN | -10 pts | password/secret/token fields returned in a response |
| `open-redirect` | WARN | -10 pts | `redirect()` to a user-controlled URL |
| `missing-rate-limit` | WARN | -8 pts | login/reset/OTP endpoints with no rate limiting |
| `csrf-missing` | WARN | -10 pts | Mutation endpoints with no CSRF protection or session auth |

**Middleware-aware:** auth-doctor parses `middleware.ts` (`config.matcher`). Routes gated by an auth
middleware are NOT reported as unprotected — eliminating the biggest source of false positives.

---

## Detection Rules

### `unprotected-route` — Unprotected API Route · -20 pts · CRITICAL

Scans every `app/api/**/route.ts` file for exported `POST`, `PUT`, `PATCH`, and `DELETE` handlers. Flags any that contain no recognisable auth check.

**Auth patterns recognised** (any = protected):
`auth()`, `getServerSession()`, `currentUser()`, `getToken()`, `verifyToken()`, `requireAuth()`, `getSession()`, `createServerClient()`, `supabase.auth.getUser()`, `headers().get('authorization')`, `cookies().get(...)`, `jwt.verify()`, `if (!session)` guards, redirects to login.

**Fix**:
```ts
// app/api/invoices/route.ts
import { auth } from '@/auth'; // or Clerk: import { auth } from '@clerk/nextjs/server'

export async function POST(req: Request) {
  const session = await auth();
  if (!session?.user) return new Response('Unauthorized', { status: 401 });
  // ... handler logic
}
```

**Real-world impact**: Any unauthenticated HTTP client can call the endpoint. No credentials, no account — just the URL.

---

### `unprotected-action` — Unprotected Server Action · -20 pts · CRITICAL

Finds files with `'use server'` that export async functions without an auth check in the first ~30 lines of the function body.

**Important**: Server Actions are NOT protected by being server-side. They are exposed as POST endpoints. The browser calls them directly.

**Fix**:
```ts
'use server';
import { auth } from '@/auth';

export async function deletePost(postId: string) {
  // Auth check MUST be first
  const session = await auth();
  if (!session?.user) throw new Error('Unauthorized');

  // Verify ownership too — never trust client-supplied IDs alone
  const post = await prisma.post.findUnique({ where: { id: postId } });
  if (post?.authorId !== session.user.id) throw new Error('Forbidden');

  await prisma.post.delete({ where: { id: postId } });
}
```

**Real-world impact**: Any visitor can invoke the action directly via a POST request — even if no UI form is visible to them.

---

### `localstorage-session` — Token in localStorage · -15 pts · CRITICAL

Detects `localStorage.setItem()` calls storing tokens, JWTs, session data, or anything with a key matching: `token`, `auth`, `session`, `user`, `jwt`, `access_token`, `refresh_token`, `bearer`, `credential`, `api_key`.

**Fix**:
```ts
// BAD — XSS steals this instantly
localStorage.setItem('token', accessToken);

// GOOD — set as httpOnly cookie from your API route
// app/api/auth/callback/route.ts
const response = NextResponse.redirect('/dashboard');
response.cookies.set('session', token, {
  httpOnly: true,   // inaccessible to JavaScript
  secure: true,     // HTTPS only
  sameSite: 'lax',  // CSRF protection
  maxAge: 60 * 60 * 24 * 7, // 1 week
  path: '/',
});
return response;
```

**Real-world impact**: One XSS vulnerability anywhere on the page steals every active user's token. Attacker gets full account access. Sessions cannot be detected or revoked.

---

### `jwt-no-verify` — JWT Without Signature Verification · -20 pts · CRITICAL

Flags `jwt.decode()` (jsonwebtoken library), `jwtDecode()` (jwt-decode library), and manual base64 JWT decoding patterns that read the payload without verifying the signature.

**Fix**:
```ts
import jwt from 'jsonwebtoken';

// BAD — trusts whatever the client sends
const payload = jwt.decode(token);

// GOOD — verifies signature, expiry, and issuer
try {
  const payload = jwt.verify(token, process.env.JWT_SECRET!, {
    algorithms: ['HS256'],
    issuer: 'your-app',
  });
  // payload is now trustworthy
} catch (err) {
  return new Response('Invalid token', { status: 401 });
}
```

**For RS256 (asymmetric)**:
```ts
const payload = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
```

**Real-world impact**: An attacker crafts a JWT with `{ "role": "admin", "userId": "victim-id" }`, uses any random signature, and calls your API. `jwt.decode()` returns their forged payload and you grant admin access.

---

### `csrf-missing` — Missing CSRF Protection · -10 pts · WARN

Flags mutation route handlers that have no session-based auth AND no CSRF protection patterns (no CSRF token check, no Origin/Referer validation, no CSRF library).

**Note**: Routes protected by `auth()` with SameSite cookies get implicit CSRF protection and are not flagged.

**Fix — Option A: Use NextAuth/Clerk (implicit CSRF via SameSite cookies)**
```ts
export async function POST(req: Request) {
  const session = await auth(); // SameSite=Lax cookie → CSRF protected
  if (!session) return new Response('Unauthorized', { status: 401 });
}
```

**Fix — Option B: CSRF token for non-session endpoints**
```ts
import { verifyCSRFToken } from '@/lib/csrf';

export async function POST(req: Request) {
  const csrfToken = req.headers.get('x-csrf-token');
  if (!csrfToken || !verifyCSRFToken(csrfToken)) {
    return new Response('Invalid CSRF token', { status: 403 });
  }
}
```

**Real-world impact**: A malicious site embeds a hidden form targeting your endpoint. The victim's browser auto-submits it with their cookies. Data changes without the user's knowledge.

---

### `hardcoded-secret` — Hardcoded Secret / API Key · -20 pts · CRITICAL

Detects high-confidence secret token shapes in source (Stripe `sk_live_`/`sk_test_`, AWS `AKIA…`, GitHub `ghp_…`, Google `AIza…`, Slack `xox…`, OpenAI `sk-…`, SendGrid, PEM private keys), `jwt.sign/verify(..., "literal")` with a string-literal secret, and generic `apiKey/clientSecret/privateKey = "…"` assignments. Comment lines and obvious placeholders are skipped.

**Fix**: Move the value to `process.env.X`, read it server-side only, add it to a secret manager, and **rotate the exposed key** — once committed it must be considered compromised forever (Git history keeps it).

**Real-world impact**: Bots scrape repos for these patterns within minutes of a push and drain accounts before you notice.

---

### `public-env-secret` — Secret Leaked to Browser · -18 pts · CRITICAL

Flags `process.env.NEXT_PUBLIC_*` whose name looks secret (`SECRET`, `PASSWORD`, `PRIVATE`, `SERVICE_ROLE`, `CLIENT_SECRET`, `API_KEY`, `ACCESS_KEY`, …). Next.js inlines every `NEXT_PUBLIC_` value into the client bundle. `PUBLISHABLE`/`ANON`/`PUBLIC_KEY` names are treated as intentionally public.

**Fix**: Drop the `NEXT_PUBLIC_` prefix, read it only on the server, and rotate the value.

**Real-world impact**: The secret is visible to every visitor in the page source / DevTools.

---

### `idor-missing-ownership` — Broken Object-Level Authorization · -18 pts · CRITICAL

Flags request handlers and Server Actions that `update`/`delete` a record by an id taken from the request (`params`, `searchParams`, `body`, `formData`) **without** any ownership scoping (`userId`/`ownerId`/`session.user.id`/etc.) anywhere in the function.

**Fix**: Scope the query to the caller — `where: { id, userId: session.user.id }` — or fetch first and verify ownership before mutating.

**Real-world impact**: OWASP API #1. Any logged-in user edits or deletes anyone else's data by changing the id. Authentication passes; authorization is missing.

---

### `open-redirect` — Open Redirect · -10 pts · WARN

Flags `redirect()` / `NextResponse.redirect()` whose target comes from user-controlled input (a query param like `next`/`callbackUrl`/`returnTo`, or the request URL) with no allow-list.

**Fix**: Validate the target is a relative path you own (starts with `/` and not `//`), or match it against an allow-list.

**Real-world impact**: `/login?next=https://evil.com` bounces users to phishing pages that look like they came from your domain — common in login/OAuth callback flows.

---

### `missing-rate-limit` — Auth Endpoint Without Rate Limiting · -8 pts · WARN

Flags POST/PUT/PATCH handlers in auth-sensitive routes (`login`, `register`, `reset`, `forgot`, `otp`, `verify`, `password`, `2fa`/`mfa`, …) with no rate-limiting library/pattern (checked in code, ignoring comments).

**Fix**: Add a limiter (e.g. `@upstash/ratelimit`) keyed by IP + identifier, with backoff on repeated failures.

**Real-world impact**: 6-digit OTPs are crackable in seconds and login endpoints invite credential-stuffing without a limit.

---

### `sensitive-field-exposure` — Sensitive Field in Response · -10 pts · WARN

Flags `Response.json()` / `res.json()` / `res.send()` bodies that include a sensitive key (`password`, `passwordHash`, `salt`, `secret`, `apiKey`, `sessionToken`, `refreshToken`, `totpSecret`, `ssn`, …). Skips fields explicitly stripped via `omit`/`select: false`.

**Fix**: Return only the fields the client needs — use Prisma `select`/`omit` or map to a DTO before serialising.

**Real-world impact**: Returning the full user object leaks password hashes for offline cracking and confirms which accounts exist.

---

## Score Tiers

| Score | Grade | Meaning |
|---|---|---|
| 90–100 | A — Secure | No significant auth vulnerabilities |
| 80–89 | B — Good | Minor issues; low risk |
| 65–79 | C — Fair | Some auth gaps needing attention |
| 50–64 | D — At Risk | Multiple exploitable vulnerabilities |
| 0–49 | F — Vulnerable | Do not ship — critical attack surface open |

---

## How to Use

```bash
# Scan current directory
npx auth-doctor

# Scan a specific project
npx auth-doctor ./my-nextjs-app

# CI mode — exit code 1 if critical issues found
npx auth-doctor --json > .auth-doctor-report.json

# Skip AI hand-off
npx auth-doctor --no-ai
```

---

## Agent Instructions

When this skill is present in a repository, AI agents must:

1. **Run auth-doctor before proposing any auth-related changes** — surface all issues first.
2. **Read `.auth-doctor-report.json`** for the full list of vulnerable files and lines, plus the `context` block (auth provider + middleware coverage).
3. **Fix in this order:** `hardcoded-secret` / `public-env-secret` (rotate the key — exposure is already real) → `idor-missing-ownership` (add ownership scoping) → `unprotected-route` / `unprotected-action` (add the auth check) → `jwt-no-verify` → the remaining warnings.
4. **For secrets, rotation is mandatory** — moving a committed secret to `.env` does not undo the exposure; the old value must be revoked.
5. **Add auth checks as the first operation** in any route or Server Action — never after business logic.
6. **Never trust client-supplied IDs** without verifying ownership against the authenticated user (`where: { id, userId: session.user.id }`).
7. **Respect middleware coverage** — if the report shows a route is gated by an auth middleware matcher, don't add a redundant duplicate check.
8. **Verify fixes** by re-running `npx auth-doctor` before marking any issue complete.
9. **Explain every fix in simple everyday language** — no jargon. Say what the vulnerability was and why fixing it helps in terms a non-developer would understand (e.g. "strangers can't access other people's accounts", "passwords stay private").

---

## Documentation

The full, canonical guides for auth-doctor are hosted on the NoctisNova site — they are no longer bundled with this package. Fetch them from the URLs below.

**For AI agents:** request any doc with an `Accept: text/markdown` header to get the raw markdown source back (content negotiation). The server reads the source file, converts it to clean markdown (fenced code blocks, `##` headers, `- [ ]` checklists) and returns it with `Content-Type: text/markdown` plus an `x-markdown-tokens` header.

```bash
curl -H "Accept: text/markdown" https://noctisnova.com/tools/auth-doctor/jwt-security
```

| Guide | URL |
|---|---|
| Auth Security Best Practices | https://noctisnova.com/tools/auth-doctor/auth-security-best-practices |
| Advanced Auth Security | https://noctisnova.com/tools/auth-doctor/advanced-auth-security |
| JWT Security | https://noctisnova.com/tools/auth-doctor/jwt-security |
| Next.js Auth Architecture | https://noctisnova.com/tools/auth-doctor/nextjs-auth-architecture |
| All NoctisNova tools | https://noctisnova.com/tools |

---

## Links

| Resource | URL |
|---|---|
| NoctisNova | https://noctisnova.com |
| Unprotected Routes Guide | https://noctisnova.com/tools/auth-doctor/auth-security-best-practices |
| Server Actions Auth Guide | https://noctisnova.com/tools/auth-doctor/auth-security-best-practices |
| Token Storage Guide | https://noctisnova.com/tools/auth-doctor/auth-security-best-practices |
| JWT Security Guide | https://noctisnova.com/tools/auth-doctor/jwt-security |
| CSRF Protection Guide | https://noctisnova.com/tools/auth-doctor/advanced-auth-security |
| NextAuth docs | https://authjs.dev |
| Clerk docs | https://clerk.com/docs |
