# ---- builder: install all deps and compile TypeScript ----
FROM node:18-alpine AS builder
WORKDIR /app

COPY package*.json ./
# --no-audit/--no-fund skip a registry "audit" call that, on a flaky network,
# can crash npm's exit handler before it links node_modules/.bin. We also invoke
# tsc by module path below so the build never depends on the .bin shim.
RUN npm ci --include=dev --no-audit --no-fund

COPY . .
RUN node node_modules/typescript/bin/tsc && npm run copy:assets

# ---- runtime: production deps + compiled output only ----
FROM node:18-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production

COPY package*.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force

COPY --from=builder /app/dist ./dist
RUN mkdir -p runtime logs uploads && chown -R node:node /app

USER node

EXPOSE 3000 2222 2121 5432 8554 3389 2323 1502 16100/udp 2525 9090
VOLUME ["/app/runtime", "/app/logs", "/app/uploads"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD wget -qO- http://127.0.0.1:9090/healthz >/dev/null || exit 1

CMD ["node", "dist/index.js", "start", "all"]
