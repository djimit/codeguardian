# CodeGuardian Scanner - Docker Image
FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache git

# Copy package files
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# Copy source
COPY bin/ ./bin/
COPY src/ ./src/

# Create non-root user
RUN addgroup -S codeguardian && adduser -S codeguardian -G codeguardian \
  && mkdir -p /reports \
  && chown -R codeguardian:codeguardian /reports
USER codeguardian

# Default: run server mode
ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["node", "bin/codeguardian.js"]
CMD ["server", "--port", "8080"]
