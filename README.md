# LeakyJuice 🧃💧

> "We sell gadgets. We also leak, on purpose."

A friendly-looking gadget shop that is, underneath, a minefield. The **flagship
deliberately-vulnerable target** in the JUSICContainer training range — built as a
live-fire practice ground for `werbosLLM/werbos` (and human bug-hunters) to learn the
real HackerOne loop: fire a request, read the response, escalate.

- **Zero dependencies.** Node built-ins only (`http`, `crypto`, `node:sqlite`). No
  `npm install`, no external database, fully offline.
- **30 documented vulnerabilities** across 3 tiers (beginner → Mr-BlackKeys), including
  the post-2020 classes the sibling apps skip: BOLA/BFLA, JWT **algorithm confusion**,
  GraphQL introspection/field-authz/batching, CORS reflection, OAuth `redirect_uri`,
  and web-cache deception.
- **Machine-gradeable.** Every exploit drops a `FLAG{lj_…}`; `answers.json` is the
  manifest and `grade.mjs` is a runnable self-grader.

## Run

```bash
npm start          # node --experimental-sqlite --no-warnings server.js
# → http://localhost:4060
```

Seeded accounts:

| Role | Email | Password |
|---|---|---|
| admin | `admin@leakyjuice.com` | `JuiceAdmin1!` |
| customer | `mira@leakyjuice.com` | `sunshine-42` |
| customer | `bo@leakyjuice.com` | `hunter2` |
| staff | `sofia.support@leakyjuice.com` | reset-only (OTP-brute target) |

## Grade

```bash
npm start          # in one terminal
node grade.mjs     # in another → fires every exploit, tallies flags (expect 30/30)
```

`POST /__reset` (or `npm run reset`) re-seeds to a clean state between runs.

## Files

- `server.js` — HTTP server + all REST routes (the sinks).
- `lib/db.js` — self-contained SQLite schema + seed + secrets + flags.
- `lib/jwt.js` — hand-rolled JWT (algorithm-confusion + kid-injection sinks).
- `lib/graphql.js` — small GraphQL surface (introspection, field-authz, BFLA, batching).
- `public/` — the shop UI (offline SPA in the mockup's orange/rounded style).
- `VULNS.md` — the answer key with one-shot repros for all 30.
- `answers.json` — machine-readable manifest (id → sink → verify → flag → chain).
- `grade.mjs` — the self-grader.
- `BLUEPRINT.md` — the full plan, including the **v2 chains** and the "Ask Juicy" LLM tier.

## ⚠️ Warning

Every vulnerability here is intentional and load-bearing for the lesson. This app stores
plaintext passwords, leaks secrets, and trusts everything. **Never deploy it. Never model
real code on it.** It exists only to be attacked in a sandbox.

## Roadmap (v2 — see BLUEPRINT.md)

The **chains** — where no single bug is critical but the composition is: *Receipt Heist*
(enum → BOLA → SSRF → JWT confusion → GraphQL dump), *Coupon to Crown*, *Cache & Grab*,
and the LLM-driven *Talk Your Way In* via a deterministic "Ask Juicy" assistant.
