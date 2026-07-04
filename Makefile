.PHONY: all build build-backend build-frontend test test-backend test-frontend test-backend-race lint lint-backend lint-frontend fmt vet clean docker-build docker-up docker-down docker-logs security-scan help

GO_DIR := backend
FRONTEND_DIR := frontend
FIRMWARE_DIR := firmware-analyzer

all: lint test build

# === Build ===

build:
	cd $(GO_DIR) && go build -o seagles .
	cd $(FRONTEND_DIR) && npm run build

build-backend:
	cd $(GO_DIR) && go build -o seagles .

build-frontend:
	cd $(FRONTEND_DIR) && npm run build

# === Test ===

test: test-backend test-frontend

test-backend:
	cd $(GO_DIR) && go test -v -count=1 ./...

test-frontend:
	cd $(FRONTEND_DIR) && npm test

test-backend-race:
	cd $(GO_DIR) && go test -race -count=1 ./...

# === Lint ===

lint: lint-backend lint-frontend

lint-backend:
	cd $(GO_DIR) && golangci-lint run --timeout=5m

lint-frontend:
	cd $(FRONTEND_DIR) && npx tsc --noEmit

fmt:
	cd $(GO_DIR) && go fmt ./...

vet:
	cd $(GO_DIR) && go vet ./...

# === Docker ===

docker-build:
	docker build -t seagles-backend:latest $(GO_DIR)
	docker build -t seagles-frontend:latest $(FRONTEND_DIR)
	docker build -t seagles-firmware-analyzer:latest $(FIRMWARE_DIR)

docker-up:
	docker compose up -d

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f

# === Security ===

security-scan:
	trivy fs --severity CRITICAL,HIGH .

# === Clean ===

clean:
	rm -f $(GO_DIR)/seagles
	rm -rf $(FRONTEND_DIR)/dist
	rm -rf $(FRONTEND_DIR)/node_modules/.vite

# === Help ===

help:
	@echo "Targets:"
	@echo "  build              Build backend + frontend"
	@echo "  test               Run all tests"
	@echo "  test-backend       Run Go tests"
	@echo "  test-frontend      Run Vitest"
	@echo "  lint               Run all linters"
	@echo "  fmt                Format Go code"
	@echo "  vet                Run go vet"
	@echo "  docker-build       Build all Docker images"
	@echo "  docker-up          Start Docker Compose services"
	@echo "  security-scan      Run Trivy vulnerability scan"
	@echo "  clean              Remove build artifacts"
