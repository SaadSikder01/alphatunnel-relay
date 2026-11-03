# AlphaTunnel Relay — Production Dockerfile
FROM node:20-alpine

WORKDIR /app

# Install deps first (better layer caching)
COPY package*.json ./
RUN npm ci --omit=dev

# Copy app code
COPY server.js ./

# Non-root user for security
RUN addgroup -S app && adduser -S app -G app
USER app

# Render sets $PORT automatically
ENV PORT=8080
EXPOSE 8080

CMD ["node", "server.js"]
