# auth-doctor

Static analysis CLI for **authentication and security vulnerabilities** in Next.js TypeScript codebases.

Built by [NoctisNova](https://noctisnova.com).

## Install & run

No install required:

```bash
npx auth-doctor
npx auth-doctor ./my-app
npx auth-doctor --json
npx auth-doctor --no-ai
```

Global install (optional):

```bash
npm install -g auth-doctor
auth-doctor
```

## What it detects

- **Unprotected routes & Server Actions** — API routes and Server Actions with no auth check
- **IDOR / missing ownership** — data fetched without verifying the caller owns it
- **Hardcoded secrets** — API keys, JWT secrets, and tokens committed in source code
- **NEXT_PUBLIC_ leaks** — sensitive values accidentally exposed to the browser
- **JWT without verification** — tokens decoded but signature never verified
- **localStorage sessions** — auth tokens stored in localStorage instead of httpOnly cookies
- **Missing rate limiting** — login, reset, and OTP endpoints with no abuse protection
- **Open redirects** — redirect destinations controlled by user-supplied input
- **Sensitive field exposure** — password / token fields returned in API responses
- **Missing CSRF protection** — state-mutating endpoints without CSRF tokens

Middleware-aware: routes already gated by an auth middleware matcher are not false-flagged.

Produces a scored health report (0–100) and saves `.auth-doctor-report.json` for AI-assisted fixes.

## Requirements

- Node.js **18+**

## Links

- **Homepage:** https://noctisnova.com
- **Repository:** https://github.com/noctisnova/auth-doctor
- **Issues:** https://github.com/noctisnova/auth-doctor/issues

## License

MIT
