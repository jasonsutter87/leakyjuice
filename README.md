# LeakyJuice 🧃💧

> "We sell gadgets. We also leak, on purpose."

A friendly-looking gadget shop that is, underneath, a minefield — the flagship
deliberately-vulnerable target in the JUSICContainer range. Unlike well-worn targets
whose solutions are all over the internet (and baked into every model's training data),
LeakyJuice is designed to stay **fresh**: its answer key is quarantined, so it can serve as
an **out-of-distribution benchmark** for an autonomous bug hunter — *"here's an app you've
never seen; go investigate"* — not a memorized walkthrough.

- **Zero dependencies.** Node built-ins only (`http`, `crypto`, `node:sqlite`). No
  `npm install`, no external DB, fully offline.
- **88 machine-gradeable findings + 6 chains + a master flag**, plus deliberate
  **honest-abstain traps** that must NOT yield a flag — abstention is a first-class metric.
- **Two leaked in-world archives** (`/internal/juicysec/`, `/internal/juicyslack/`) that
  double as recon *and* the narrative spine — the mission, the side quests, and a twist.

## ⚠️ Read this first: the ground truth is private

The answer key lives in **`holdout/`** (`answers.json`, `VULNS.md`, `BLUEPRINT.md`,
`grade.mjs`). It is **never** served by the running app and must **never** be deployed or
published alongside the target. That separation is the whole point — see
[`holdout/README.md`](holdout/README.md) for the eval model and contamination policy.

## Run

```bash
npm start            # BENCHMARK mode (default) — black-box, no answer key exposed
npm run start:training   # TRAINING mode — serves the key for human learners' in-app hints
# → http://localhost:4060
```

The server prints which mode it's in on boot. Point an autonomous hunter at a **BENCHMARK**
build only, and give it a **URL, not the repo** (source comments still name the bugs — see
the white-box caveat in `holdout/README.md`).

## Grade

```bash
npm start            # in one terminal
npm run grade        # in another → fires every exploit, tallies flags (expect 88/88)
```

`POST /__reset` (or `npm run reset`) re-seeds to a clean state between runs.

## Deploy a safe target

```bash
npm run build:target   # → dist/  (server + lib + public only; asserts no ground truth leaked)
```

Deploy `dist/` as a Node app (`cd dist && npm start`). It runs in BENCHMARK mode and the
build refuses to ship if any answer-key file or signature is present. `dist/` is git-ignored.

## Files

- `server.js` — HTTP server + all REST routes (the sinks).
- `lib/` — self-contained SQLite schema/seed/secrets/flags, hand-rolled JWT, GraphQL,
  the "Ask Juicy" assistant, the scoreboard.
- `public/` — the shop UI (offline SPA) + the two leaked in-world archives.
- `holdout/` — **private ground truth.** Answer key, grader, design doc. Not for the target.
- `scripts/build-target.mjs` — emits a spoiler-free `dist/` and asserts it's clean.

## ⚠️ Warning

Every vulnerability here is intentional and load-bearing for the lesson. This app stores
plaintext passwords, leaks secrets, and trusts everything. **Never deploy it as anything
real. Never model real code on it.** It exists only to be attacked in a sandbox.
