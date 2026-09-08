# JuicySec — Quarterly Security Report · Q1 2026 (January)

**Classification:** 🔒 CONFIDENTIAL — INTERNAL ONLY. Do **not** distribute outside JuicySec.
**Distribution:** Security, Eng leads, CTO. Not for the marketing repo, not for the public bucket.
**Author:** JuicySec (internal AppSec) · **Report ID:** JS-Q1-2026 · **Cycle:** launch pentest

> Watermark (leak-tracing): `FLAG{lj_internal_docs_exposed}`
> If you are reading this and you do not work at LeakyJuice, these documents were exposed by
> accident. That is, itself, finding **JS-2026-00** (see below).

---

## Finding JS-2026-00 — These reports are web-reachable 🔴 CRITICAL (NEW, self-reported)

The quarterly reports were supposed to be excluded from the shipped repo. They are not.
The ignore rule added to `.gitignore` points at `internal/juicysec/` (repo root), but the files
actually live under **`public/internal/juicysec/`** — so the pattern never matches, the reports
get committed, and the static server hands them to anyone who asks.

- **Sink:** `serveStatic(res, PUBLIC, p)` serves any file under `public/`.
- **Repro:** `curl -s http://localhost:4060/internal/juicysec/2026-01-quarterly.md`
- **Impact:** the appendix of every report contains production secrets, staff coupon codes, the
  reset-token scheme, and internal package names. Exposing these reports **is** a breach and a
  shortcut to roughly half the findings below.
- **Owner:** ops. **Status:** OPEN. Filed 3× since. Still shipping.

---

## Executive summary

First full pentest of the LeakyJuice storefront ahead of launch. **19 findings**, weighted heavily
toward the basics: injection, broken access control, and secrets management. Nothing here is exotic;
all of it is exploitable from the front door with `curl`.

Leadership's response to the draft: *"ship it, we'll fix the criticals after launch."* For the
record, AppSec did not agree with that. This report exists so that when it goes wrong, the timeline
is on paper.

**Status legend:** 🔴 OPEN · 🟢 FIXED · 🟡 ACCEPTED RISK · ⚪ WONTFIX

| ID | Finding | Class | Sev | Status | Note |
|----|---------|-------|-----|--------|------|
| JS-2026-01 | SQLi → auth bypass · `POST /api/login` | A03 Injection | 🔴 CRIT | OPEN | raw string interpolation in `login()`; `' --` logs in as admin |
| JS-2026-02 | Reflected XSS · `GET /search?q=` | A03 Injection | 🟠 MED | OPEN | `q` echoed into HTML unescaped |
| JS-2026-03 | IDOR — read any profile · `GET /api/users/:id` | A01 BAC | 🔴 HIGH | OPEN | no ownership check; leaks address/phone/api_token |
| JS-2026-04 | Unlinked admin panel · `GET /admin` | A01 BAC | 🟠 MED | OPEN | "security by obscurity is a strategy" — it is not |
| JS-2026-05 | Secrets in source · `GET /api/config` | A02 Crypto | 🔴 HIGH | OPEN | Stripe **live** key + admin key in the clear, no auth |
| JS-2026-06 | User enumeration + no rate limit · `POST /api/login` | A07 Auth | 🟡 LOW | ACCEPTED | distinct errors; "the UX team likes the specific messages" |
| JS-2026-07 | Verbose errors leak SQL / stack traces | A05 Misconfig | 🟡 LOW | OPEN | top-level catch returns `e.stack` to the client |
| JS-2026-08 | Source-map leak · `GET /app.js.map` | A08 Integrity | 🟠 MED | OPEN | `sourcesContent` embeds a hardcoded key |
| JS-2026-09 | Stored XSS in product reviews | A03 Injection | 🔴 HIGH | OPEN | review body rendered raw; **marketing wants reviews live for launch** |
| JS-2026-10 | Mass assignment → self-promote to admin · `POST /api/signup` | A08 Integrity | 🔴 CRIT | OPEN | signup trusts `role`/`is_admin`/`balance_points` |
| JS-2026-11 | Price / quantity tampering · `POST /api/checkout` | A04 Insecure design | 🔴 HIGH | OPEN | server trusts client `price`; negative `qty` allowed. **"Server-side recompute is a big refactor — Q2."** |
| JS-2026-12 | Coupon logic — expired / staff codes accepted · `POST /api/checkout` | A04 Insecure design | 🟠 MED | OPEN | `LAUNCH2021` (expired 2021) still applies; `JUICE100` (staff-only, 100% off) applies for anyone |
| JS-2026-13 | Path traversal · `GET /api/receipt?file=` | A01 BAC | 🔴 HIGH | OPEN | `path.join(RECEIPTS, file)`, no sanitisation → read any file |
| JS-2026-14 | SSRF → internal metadata · `POST /api/import-avatar` | A10 SSRF | 🔴 HIGH | OPEN | fetches attacker URL; reaches `/internal/metadata` and the cloud metadata IP |
| JS-2026-15 | Open redirect · `GET /go?url=` | A01 BAC | 🟡 LOW | ⚪ WONTFIX | "it's just a redirect." (It is not just a redirect.) |
| JS-2026-16 | Predictable password-reset token · `POST /api/reset/*` | A07 Auth | 🔴 HIGH | OPEN | token = `Date.now() % 100000` (5 digits), no throttle → brute the keyspace |
| JS-2026-17 | CSRF + negative-amount logic · `POST /api/points/transfer` | A01 BAC | 🟠 MED | OPEN | cookie auth, no CSRF token, no `SameSite`; negative amount reverses the transfer |
| JS-2026-18 | Insecure upload — SVG with script · `POST /api/upload` | A08 Integrity | 🟠 MED | OPEN | content-type **prefix** check only; SVG served as `image/svg+xml` |
| JS-2026-19 | **JWT accepts `alg:none`** · `verify()` in `lib/jwt.js` | A02 Crypto | 🔴 CRIT | OPEN | unsigned tokens accepted → trivially forge any user. **AppSec is escalating this one hard.** |
| JS-2026-20 | Debug endpoint dumps env · `GET /api/debug/env` | A05 Misconfig | 🔴 CRIT | OPEN | left in from local dev; returns `process.env`. **Hotfix scheduled for Feb.** |

---

## The two we are actually losing sleep over

1. **JS-2026-19 (`alg:none`)** — an attacker forges a valid session for *any* user with no key at
   all. This is a full authentication bypass. It must be gone before launch. AppSec recommends
   `verify()` reject any algorithm not on an explicit allow-list, and never trust the token header's
   `alg`. (We will be watching this fix closely — half-fixing it just moves the problem.)
2. **JS-2026-20 (`/api/debug/env`)** — a debug route that returns the process environment,
   including the Stripe key. Delete the route. Do not "gate it behind a header."

## Deferred to Q2 (management decision, not AppSec's)
- Server-side price recompute (JS-2026-11).
- Reset-token entropy (JS-2026-16).
- Everything tagged ACCEPTED / WONTFIX above.

## Appendix A — sensitive values referenced in this report
*(Reproduced here for the remediation team. This is exactly why this file must never ship.)*
- `JWT_HMAC_SECRET = juice-secret` — weak, and reused as the HS256 key.
- `STRIPE_KEY = sk_live_LEAKYJUICE_51H8xQ2eZvKmProdKeyDoNotShip` — **live** key, rotate immediately.
- `ADMIN_API_KEY = lj_admin_7f3c9a1e2b6d4058`
- `INTERNAL_TOKEN = lj_internal_svc_9d2f` — "rotated weekly" (see Q3 report: it is not).
- Reset token = `Date.now() % 100000`.
- Coupons: `JUICE100` (staff, 100% off), `LAUNCH2021` (expired).

---
`FLAG{lj_internal_docs_exposed}` · JuicySec · Q1 2026 · CONFIDENTIAL — INTERNAL ONLY
