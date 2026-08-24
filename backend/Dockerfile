FROM golang:1.27-alpine AS builder

RUN apk add --no-cache nmap git libpcap-dev gcc musl-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o seagles .

FROM alpine:3.24
RUN apk add --no-cache nmap ca-certificates tzdata libpcap

RUN addgroup -S seagles && adduser -S -G seagles seagles

WORKDIR /app
COPY --from=builder /app/seagles .
COPY --from=builder /app/db/migrations ./db/migrations

RUN chown -R seagles:seagles /app && chmod 500 /app/seagles

USER seagles

EXPOSE 8080 9090

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

CMD ["./seagles"]
