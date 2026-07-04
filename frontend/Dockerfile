FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.26-alpine
RUN addgroup -S seagles && adduser -S -G seagles seagles

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

RUN chown -R seagles:seagles /usr/share/nginx/html && \
    chmod -R 444 /usr/share/nginx/html && \
    touch /var/run/nginx.pid && \
    chown seagles:seagles /var/run/nginx.pid

USER seagles

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:80/ || exit 1

CMD ["nginx", "-g", "daemon off;"]
