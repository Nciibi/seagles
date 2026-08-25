#!/bin/bash
set -euo pipefail

# Seagles IoT Security Platform — Production Deployment Script
# Usage: ./deploy.sh [--env production|staging] [--skip-build] [--skip-migrate]

APP_NAME="seagles"
ENV="${ENV:-production}"
SKIP_BUILD=false
SKIP_MIGRATE=false

while [[ $# -gt 0 ]]; do
	case "$1" in
		--env) ENV="$2"; shift 2 ;;
		--skip-build) SKIP_BUILD=true; shift ;;
		--skip-migrate) SKIP_MIGRATE=true; shift ;;
		*) echo "Unknown flag: $1"; exit 1 ;;
	esac
done

if [ ! -f ".env" ]; then
	if [ -f ".env.example" ]; then
		echo "Creating .env from .env.example"
		cp .env.example .env
		echo "WARNING: Review .env before deploying"
	else
		echo "ERROR: .env file not found"
		exit 1
	fi
fi

if [ "$SKIP_BUILD" = false ]; then
	echo "=== Building backend ==="
	cd backend
	go build -ldflags="-s -w" -o "../bin/$APP_NAME" .
	cd ..

	echo "=== Building frontend ==="
	cd frontend
	npm ci --omit=dev
	npm run build
	cd ..

	echo "=== Copying frontend assets ==="
	mkdir -p "bin/public"
	cp -r frontend/dist/* bin/public/
fi

if [ "$SKIP_MIGRATE" = false ]; then
	echo "=== Running database migrations ==="
	for f in backend/db/migrations/*.sql; do
		echo "  Applying: $(basename "$f")"
		PGPASSWORD="${DB_PASSWORD}" psql -h "${DB_HOST:-localhost}" \
			-U "${DB_USER:-seagles}" \
			-d "${DB_NAME:-seagles}" \
			-f "$f"
	done
fi

echo "=== Deployment complete ==="
echo "Run: ./bin/$APP_NAME --env $ENV"
