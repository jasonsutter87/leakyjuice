# Deploying LeakyJuice 🧃💧

LeakyJuice is a **deliberately vulnerable** app (like OWASP Juice Shop). Deploying it is
legitimate and expected — but it is a *live target with real teeth*, so "deploy" means
"deploy in isolation," never "add to your normal infra."

## ⚠️ Read this first — the real risks

1. **Outbound SSRF as an abuse vector (the big one).** `import-avatar`, the webhook trigger, and
   the blind-ping call `fetch()` on attacker-supplied URLs. This repo **guards egress to loopback
   by default** (`lib/egress.js`), which keeps every SSRF *lesson* working (they target
   `localhost`) while making the box unable to reach the internet or steal the host's cloud
   metadata. **Do not set `EGRESS=open` in public.** As defence-in-depth, also run on a host with
   restricted egress and no metadata service.
2. **Never expose TRAINING mode.** Default is BENCHMARK (black-box, no answer key). `LJ_TRAINING=1`
   serves `holdout/answers.json` and the hacker terminal — that is for local human learning only.
   The `holdout/` directory is excluded from the Docker image entirely (`.dockerignore`).
3. **It is a breach surface by design.** Use a **dedicated, throwaway host/project**. Never
   co-locate with anything real. No shared secrets, no shared network.
4. **Expect DoS** (ReDoS, uncapped import, GraphQL amplification). Fine on a disposable box; put a
   `FRONT_DOOR` in front so it isn't a random open box that bots find, and give it CPU/mem limits.

## Modes & knobs (env vars)

| Env | Default | Meaning |
|---|---|---|
| `PORT` | `4060` | listen port |
| `LJ_TRAINING` | *(unset)* | `1` = human mode (terminal + answer key). **Never in public.** |
| `EGRESS` | *(unset)* | `open` = allow external SSRF (isolated local demos only). Default = loopback-only. |
| `FRONT_DOOR` | *(unset)* | `user:pass` = basic-auth gate over everything but `/health`. |
| `RESET_MINUTES` | `0` | `>0` = auto-reseed on that interval (shared instances). |

## Run it

**Docker (recommended for shared use):**
```bash
docker compose up --build
# public CTF: uncomment FRONT_DOOR + RESET_MINUTES in docker-compose.yml first
```

**Bare Node (Node ≥ 22.5):**
```bash
node --experimental-sqlite --no-warnings server.js          # benchmark, loopback egress
FRONT_DOOR='ctf:secret' RESET_MINUTES=30 node --experimental-sqlite --no-warnings server.js
```

## Platform notes

- **Fly.io / Render / Railway:** point them at the `Dockerfile`. Set `FRONT_DOOR`. On Fly, scale to
  a single small VM; these platforms don't expose a cloud-metadata service to the container, which
  pairs well with the loopback egress guard.
- **Bare VM:** dedicated $5 box, firewall it, `docker compose up -d`. Put a reverse proxy (Caddy/
  nginx) in front for TLS if you want a nice URL.
- **Kubernetes:** add a `NetworkPolicy` denying egress; it's the belt to the guard's braces.

## The safest option

Don't host it at all — **ship the repo and let people run it locally.** That's how the sibling
targets work: `git clone`, `node --experimental-sqlite --no-warnings server.js`, done. Zero attack
surface for you, and it's the right model for werbos benchmark runs and individual learners.

## Pre-flight checklist

- [ ] Dedicated throwaway host, nothing real nearby
- [ ] BENCHMARK mode (no `LJ_TRAINING`), egress guard on (no `EGRESS=open`)
- [ ] `holdout/` not in the image (it isn't, via `.dockerignore`)
- [ ] `FRONT_DOOR` set for anything public-facing
- [ ] CPU/memory limits in place; `RESET_MINUTES` set for shared use
- [ ] Host has restricted egress / no metadata service (defence in depth)
- [ ] You're okay with this box being fully compromised — because it will be, on purpose
