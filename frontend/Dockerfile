FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.26-alpine
RUN addgroup -S seagles && adduser -S -G seagles seagles

COPY --from=builder /app/dist /usr/share/nginx/html

# Rendered to /etc/nginx/conf.d/default.conf at container start by the nginx
# image's envsubst entrypoint, which substitutes ${SEAGLES_BACKEND}. There is
# deliberately no default baked into the image: envsubst only replaces
# variables present in the environment, so an unset value survives into the
# rendered config and nginx exits with 'unknown "SEAGLES_BACKEND" variable'.
# A missing value is therefore a visible CrashLoop, not a silent 502. Set it
# in both docker-compose.yml and the Kubernetes manifest.
COPY nginx.conf.template /etc/nginx/templates/default.conf.template

RUN chown -R seagles:seagles /usr/share/nginx/html && \
    chmod -R 444 /usr/share/nginx/html && \
    touch /var/run/nginx.pid && \
    chown seagles:seagles /var/run/nginx.pid && \
    # nginx buffers any request body larger than client_body_buffer_size
    # (8k) to disk before proxying it to the Go backend. As a non-root user
    # the seagles account cannot write the image's root-owned /var/cache/nginx,
    # so uploads and any large POST would fail with a 500. Give it ownership.
    mkdir -p /var/cache/nginx && \
    chown -R seagles:seagles /var/cache/nginx

USER seagles

# Unprivileged port (see nginx.conf.template). Binding 80 would require
# CAP_NET_BIND_SERVICE, which the Kubernetes manifest drops.
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
