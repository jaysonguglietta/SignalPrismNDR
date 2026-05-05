FROM node:22-alpine

ENV NODE_ENV=production
WORKDIR /app

COPY package.json ./
COPY server.mjs ./
COPY index.html styles.css app.js ./
COPY src ./src

RUN addgroup -S ndr && adduser -S ndr -G ndr && mkdir -p /data && chown -R ndr:ndr /data /app

USER ndr
ENV NDR_DATA_DIR=/data
EXPOSE 4173

CMD ["node", "server.mjs"]
