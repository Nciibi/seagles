.PHONY: up down logs scan stats reset

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
