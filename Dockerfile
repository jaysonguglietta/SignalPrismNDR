FROM node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2

ENV NODE_ENV=production
WORKDIR /app

COPY package.json ./
COPY server.mjs ./
RUN mkdir -p /app/public/src
COPY index.html styles.css app.js favicon.svg ./public/
COPY src ./src
COPY src/idb-store.js src/backend-client.js src/topology.js src/platform-ui.mjs src/operations-ui.mjs ./public/src/

RUN addgroup -S -g 10001 ndr && adduser -S -D -H -u 10001 -G ndr ndr && mkdir -p /data && chown -R ndr:ndr /data /app

USER ndr
ENV NDR_DATA_DIR=/data
ENV NDR_PUBLIC_DIR=/app/public
EXPOSE 4173

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:4173/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.mjs"]
