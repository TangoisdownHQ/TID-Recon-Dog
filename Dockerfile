# ---- builder: install all deps and compile TypeScript ----
FROM node:18-alpine AS builder
WORKDIR /app

COPY package*.json ./
# npm ci on alpine intermittently hits the "Exit handler never called!" bug:
# it exits 0 but leaves node_modules incomplete (e.g. typescript missing), which
# then breaks the tsc step below. --no-audit/--no-fund reduce the trigger but
# don't eliminate it, so we retry until the artifact we need is actually present.
RUN for i in 1 2 3 4 5; do \
      npm ci --include=dev --no-audit --no-fund && [ -f node_modules/typescript/bin/tsc ] && break; \
      echo "npm ci incomplete (attempt $i) — retrying"; rm -rf node_modules; \
    done; \
    [ -f node_modules/typescript/bin/tsc ]

COPY . .
# Invoke tsc by module path so the build never depends on the .bin shim.
RUN node node_modules/typescript/bin/tsc && npm run copy:assets

# ---- runtime: production deps + compiled output only ----
FROM node:18-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

COPY package*.json ./
# Same retry guard as the builder stage (see note above): verify a couple of
# real production deps landed before trusting npm ci's exit code.
RUN for i in 1 2 3 4 5; do \
      npm ci --omit=dev --no-audit --no-fund && [ -d node_modules/express ] && [ -d node_modules/socks-proxy-agent ] && break; \
      echo "npm ci incomplete (attempt $i) — retrying"; rm -rf node_modules; \
    done; \
    [ -d node_modules/express ] && [ -d node_modules/socks-proxy-agent ] && npm cache clean --force

COPY --from=builder /app/dist ./dist
RUN mkdir -p runtime logs uploads && chown -R node:node /app

USER node

EXPOSE 3000 2222 2121 5432 8554 3389 2323 1502 16100/udp 2525 9090
VOLUME ["/app/runtime", "/app/logs", "/app/uploads"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD wget -qO- http://127.0.0.1:9090/healthz >/dev/null || exit 1

CMD ["node", "dist/index.js", "start", "all"]
