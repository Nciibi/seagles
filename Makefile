.PHONY: up down logs scan stats reset build-backend build-frontend test

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs -f

scan:
	curl -s -X POST http://localhost:8080/api/v1/scan/network | jq .

stats:
	curl -s http://localhost:8080/api/v1/stats | jq .

reset:
	docker compose down -v
	docker compose up -d --build

build-backend:
	cd backend && go build -o bin/ironmesh .

build-frontend:
	cd frontend && npm run build

build-all: build-backend build-frontend

test:
	cd backend && go test -v ./...

test-race:
	cd backend && go test -race ./...

vet:
	cd backend && go vet ./...

watch-logs:
	docker compose logs -f backend

health:
	curl -s http://localhost:8080/api/v1/health | jq .

dev:
	docker compose up -d postgres redis minio pgbouncer
	cd backend && go run .

login:
	curl -s -X POST http://localhost:8080/api/v1/auth/login \
		-H "Content-Type: application/json" \
		-d '{"username":"admin","password":"changeme"}' | jq .
