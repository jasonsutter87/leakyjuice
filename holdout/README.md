# holdout/ — ground truth. Do not ship. Do not publish.

This directory is the **answer key** for LeakyJuice. It is deliberately quarantined
from the deployable target so the two never travel together. That separation is the
entire reason LeakyJuice can work as an **out-of-distribution (OOD) benchmark** for an
autonomous bug hunter instead of a memorized walkthrough.

## Why the split exists

Juice Shop is a solved landscape: its endpoints, payloads, and solutions have been
written up for 15 years and are baked into every model's training data. A model can look
brilliant on it while doing pure retrieval — *"Ah, Juice Shop, I know this one."* That
measures memory, not security reasoning.

LeakyJuice is a fresh world **only as long as its answers are not known**. The moment the
answer key ships with the target — or the repo is published and scraped into a training
set — it becomes Juice Shop 2: contaminated, memorized, retrieval again.

So the rule is absolute:

> **The target and the ground truth never live in the same place a hunter (or a crawler) can reach.**

## What's in here

| File | What it is | Why it's ground truth |
|---|---|---|
| `answers.json` | machine-readable manifest: id → endpoint → sink → verify → flag → chain, plus the `honest_abstain_traps_*` decoy sets | the decoder ring for every finding |
| `VULNS.md` | prose answer key with one-shot repros | full walkthrough |
| `BLUEPRINT.md` | design doc: the chains, the LLM tier, the roadmap | reveals structure + intent |
| `grade.mjs` | the self-grader; fires every documented exploit over HTTP and tallies flags | encodes the exact repros |

## Two modes (one server, one env flag)

The app is **black-box by default**. Ground truth is never served over HTTP by the target.

- **BENCHMARK mode** (`npm start`): `/answers.json` 404s, the hacker terminal's
  `hint`/`sink` commands report the key is unavailable. A hunter sees only behavior.
  This is what you point an autonomous agent at.
- **TRAINING mode** (`npm run start:training`, i.e. `LJ_TRAINING=1`): the server reads
  `holdout/answers.json` and serves it at `/answers.json` so **human learners** get hints.
  Never expose a training build publicly.

Grade a running server (either mode) from the repo root: `npm run grade` (expects 88/88).

## Deploying the target safely

`npm run build:target` emits `dist/` — server + `lib/` + `public/` + a spoiler-free
README, and **asserts** no ground-truth file or signature is present, failing the build if
one is. Deploy `dist/` as a Node app; it runs in BENCHMARK mode. `dist/` is git-ignored.

## Known caveat: white-box source

The **running target** exposes no answer key over HTTP. But the *source* (`lib/db.js`,
`server.js`) still carries flag names and explanatory `// VULN:` comments — a spoiler to
anyone handed the source. BENCHMARK evals must therefore be **black-box** (give the hunter
a URL, not the repo). A future `build:target` step could strip comments/rename flags for a
white-box-safe distribution; not done yet — treat source as ground-truth-adjacent.

## The bigger play: rotate the corpus

A static public target is contaminated the day it's scraped. The durable defense is a
**generator**: hold the invariant (the vuln *class* and the reasoning path — "this input
reaches SQL unsafely"), rotate the surface (endpoint/table/column names, which bugs are
live vs. patched, the fictional company, which planted-doc lies are present). Because the
generator *plants* the bugs, it can emit each instance's ground truth automatically — no
hand-written key per version. That's the path from "one fresh app" to "an OOD benchmark
that stays fresh." See `BLUEPRINT.md`.

## Metrics this enables (that Juice Shop can't)

With private ground truth + planted decoys, each is scorable:
discovery · hypothesis · experiment · **evidence (the `FLAG{}` drop = the reproduction
gate)** · impact · chaining · **abstention (false-claim rate on the `honest_abstain_traps_*`
decoys)**. The last one is the whole game, and it only works when the decoys are secret.
