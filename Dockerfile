FROM node:24-bookworm-slim AS builder

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

COPY . .
ENV YUEMI_RUNTIME=vps
RUN npm run build

FROM node:24-bookworm-slim AS runtime

ENV NODE_ENV=production \
    YUEMI_RUNTIME=vps \
    YUEMI_DATA_DIR=/data \
    HOSTNAME=0.0.0.0 \
    PORT=3000

WORKDIR /app
COPY --from=builder --chown=node:node /app /app
RUN mkdir -p /data && chown node:node /data

USER node
EXPOSE 3000

CMD ["npm", "run", "start:vps"]
