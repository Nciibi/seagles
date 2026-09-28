FROM golang:1.25-alpine AS builder

# Build-time toolchain only. nmap is NOT needed here — it is a runtime
# dependency and is installed in the runtime stage, which keeps this layer
# (and the builder image) small.
RUN apk add --no-cache git libpcap-dev gcc musl-dev

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO must stay ENABLED: scanner/passive.go imports github.com/google/gopacket/pcap,
# whose types are only defined behind cgo build tags. With CGO_ENABLED=0 the
# package fails to compile ("undefined: pcapErrorNotActivated", etc.) and the
# image cannot be built at all. The resulting binary links libpcap dynamically,
# which the runtime stage provides.
RUN CGO_ENABLED=1 GOOS=linux go build -trimpath -o seagles .

FROM alpine:3.24
RUN apk add --no-cache nmap ca-certificates tzdata libpcap

RUN addgroup -S seagles && adduser -S -G seagles seagles

WORKDIR /app
COPY --from=builder /app/seagles .
COPY --from=builder /app/db/migrations ./db/migrations

RUN chown -R seagles:seagles /app && chmod 500 /app/seagles

USER seagles

EXPOSE 8080

# /api/v1/health is the diagnostic endpoint. It returns 200 unless the
# database is unreachable, so a degraded optional dependency does not mark the
# container unhealthy. Liveness for orchestrators is /api/v1/livez and
# readiness is /api/v1/readyz — do not point this at /health, which does not
# exist and would leave the container permanently unhealthy.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/api/v1/health || exit 1

CMD ["./seagles"]
