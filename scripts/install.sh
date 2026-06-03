#!/usr/bin/env sh
# First-time Scrinium setup (Podman/Docker Compose).
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

compose() {
  if command -v podman-compose >/dev/null 2>&1; then
    podman-compose "$@"
  elif command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    docker compose "$@"
  else
    echo "Error: need podman-compose or docker compose." >&2
    exit 1
  fi
}

mkdir -p data
if [ ! -f .env ] && [ -f .env.example ]; then
  cp .env.example .env
  echo "Created .env from .env.example — review before production use."
fi

echo "Building and starting Scrinium..."
compose up -d --build

PORT="${SCRINIUM_HTTP_PORT:-8080}"
if [ -f .env ]; then
  # shellcheck disable=SC1091
  . ./.env 2>/dev/null || true
  PORT="${SCRINIUM_HTTP_PORT:-$PORT}"
fi

echo "Waiting for health check..."
n=0
while [ "$n" -lt 60 ]; do
  if curl -sf "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then
    echo "Scrinium is up: http://127.0.0.1:${PORT}/"
    echo "First visit: complete /setup to create the admin account."
    echo "Optional packages (e.g. Security) are disabled until enabled in Admin."
    exit 0
  fi
  n=$((n + 1))
  sleep 2
done

echo "Health check timed out. Run: compose logs scrinium" >&2
exit 1
