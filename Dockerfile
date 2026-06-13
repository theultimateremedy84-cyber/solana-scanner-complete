FROM node:22-alpine

WORKDIR /app

# Install Caddy
RUN apk add --no-cache caddy

# Install dependencies
COPY package.json bun.lock* ./
RUN npm install

# Copy source and build
COPY . .
RUN npm run build

# Copy Caddyfile
COPY Caddyfile /etc/caddy/Caddyfile

EXPOSE 8080

CMD ["caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"]
