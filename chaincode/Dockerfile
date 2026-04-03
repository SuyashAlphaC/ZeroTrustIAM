FROM node:18-alpine

WORKDIR /usr/src/app

COPY package*.json ./
RUN npm install --production

COPY . .

EXPOSE 9999

CMD ["sh", "-c", "npx fabric-chaincode-node server --chaincode-address 0.0.0.0:9999 --chaincode-id ${CHAINCODE_ID}"]
