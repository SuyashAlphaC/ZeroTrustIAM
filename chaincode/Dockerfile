FROM node:20-alpine AS deps
WORKDIR /usr/src/app
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

FROM node:20-alpine AS runtime
RUN addgroup -g 10001 -S chaincode \
 && adduser -u 10001 -S -G chaincode chaincode

WORKDIR /usr/src/app
COPY --from=deps /usr/src/app/node_modules ./node_modules
COPY package*.json ./
COPY index.js ./
COPY lib ./lib

USER 10001:10001
EXPOSE 9999

CMD ["sh", "-c", "npx fabric-chaincode-node server --chaincode-address 0.0.0.0:9999 --chaincode-id ${CHAINCODE_ID}"]
