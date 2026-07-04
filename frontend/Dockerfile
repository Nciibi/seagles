FROM node:26-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.26-alpine
RUN addgroup -S ironmesh && adduser -S -G ironmesh ironmesh

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

RUN chown -R ironmesh:ironmesh /usr/share/nginx/html && \
    chmod -R 444 /usr/share/nginx/html && \
    touch /var/run/nginx.pid && \
    chown ironmesh:ironmesh /var/run/nginx.pid

USER ironmesh

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:80/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
