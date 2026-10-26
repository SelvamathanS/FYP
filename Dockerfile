# Production Multi-Stage Dockerfile for Self-Healing GraphRAG CTI Platform
FROM node:22-alpine AS builder

WORKDIR /app

# Copy dependency manifests
COPY package.json package-lock.json ./

# Install dependencies (clean install)
RUN npm ci

# Copy application sources
COPY . .

# Build Vite frontend & Bundle Express TypeScript backend into dist/server.cjs
RUN npm run build

# Run automated system verification test suite to ensure release integrity
RUN npm test

# Production Runtime Image
FROM node:22-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000

# Copy built artifacts and runtime manifests
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY --from=builder /app/dist ./dist
COPY --from=builder /app/data ./data
COPY --from=builder /app/public ./public

# Expose HTTP service port
EXPOSE 3000

# Start production server
CMD ["node", "dist/server.cjs"]
