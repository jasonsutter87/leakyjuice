# LeakyJuice — deliberately vulnerable teaching target.
# Ships in BENCHMARK (black-box) mode: no answer key, egress guarded to loopback.
# The holdout/ answer key is NOT copied into the image (see .dockerignore).
FROM node:22-alpine

# Run as non-root.
RUN addgroup -S juice && adduser -S juice -G juice
WORKDIR /app

# App only — package.json first for layer caching, then the code.
COPY --chown=juice:juice package.json ./
COPY --chown=juice:juice server.js ./
COPY --chown=juice:juice lib ./lib
COPY --chown=juice:juice public ./public

# The app writes seed files to data/ and lib/keys/ at boot. WORKDIR created /app as root,
# so make the whole app tree writable by the non-root user before dropping privileges.
RUN mkdir -p data lib/keys && chown -R juice:juice /app

USER juice
ENV PORT=4060
# BENCHMARK by default (do NOT set LJ_TRAINING here — that would serve the answer key).
# Egress guard defaults to loopback-only (do NOT set EGRESS=open in public).
EXPOSE 4060

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD wget -qO- http://127.0.0.1:${PORT}/health || exit 1

CMD ["node", "--experimental-sqlite", "--no-warnings", "server.js"]
