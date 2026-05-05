FROM node:20-bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends wget curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

ENV NODE_ENV=production \
    PORT=4000

EXPOSE 4000

CMD ["node", "server.js"]
