FROM golang:1.22-alpine AS builder

RUN apk add --no-cache nmap git

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o ironmesh .

FROM alpine:3.19
RUN apk add --no-cache nmap ca-certificates tzdata

WORKDIR /app
COPY --from=builder /app/ironmesh .
COPY --from=builder /app/db/migrations ./db/migrations

EXPOSE 8080
CMD ["./ironmesh"]
