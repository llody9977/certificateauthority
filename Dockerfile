# Stage 1: Build Frontend Assets
FROM node:20-alpine AS frontend-builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Stage 2: Production Server Image
FROM node:20-alpine AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3001

COPY package*.json ./
RUN npm ci --only=production

# Copy built frontend static files and server source code
COPY --from=frontend-builder /app/dist ./dist
COPY server ./server

# Expose CA API and Web UI port
EXPOSE 3001

# Mountable directory for encrypted keys, certificates, DB, and OPA policies
VOLUME [ "/app/data" ]

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3001/api/setup/status || exit 1

CMD ["node", "server/index.js"]
