# Multi-stage production image — non-root, production deps only
FROM node:20-bookworm-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force

FROM node:20-bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends wget ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 10001 ztiam \
 && useradd --uid 10001 --gid ztiam --shell /usr/sbin/nologin --create-home ztiam

WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json package-lock.json ./
COPY *.js ./
COPY scripts ./scripts

ENV NODE_ENV=production \
    PORT=4000 \
    NODE_OPTIONS=--enable-source-maps

USER 10001:10001
EXPOSE 4000

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:4000/health || exit 1

CMD ["node", "server.js"]
