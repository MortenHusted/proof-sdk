FROM node:24-bookworm-slim@sha256:ba849c60be29959425b8734d57b8b4b7d56f98edd9504c9af091d5281095a71e
WORKDIR /app
COPY . .
RUN npm ci --no-audit --no-fund && npm run build
ENV NODE_ENV=production HOST=0.0.0.0 VITE_ENABLE_TELEMETRY=false
USER node
EXPOSE 4000
CMD ["node", "--import", "tsx", "server/index.ts"]
