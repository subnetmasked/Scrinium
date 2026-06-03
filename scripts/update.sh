#!/usr/bin/env sh
# Update an existing Scrinium install from git and rebuild containers.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

NO_CACHE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-cache) NO_CACHE=1; shift ;;
    *) echo "Usage: $0 [--no-cache]" >&2; exit 1 ;;
  esac
done

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

echo "Pulling latest changes..."
git pull

if [ -n "$NO_CACHE" ]; then
  echo "Rebuilding without cache..."
  compose build --no-cache scrinium
  compose up -d --force-recreate
else
  compose up -d --build
fi

PORT="${SCRINIUM_HTTP_PORT:-8080}"
if [ -f .env ]; then
  # shellcheck disable=SC1091
  . ./.env 2>/dev/null || true
  PORT="${SCRINIUM_HTTP_PORT:-$PORT}"
fi

sleep 3
if curl -sf "http://127.0.0.1:${PORT}/health"; then
  echo ""
  echo "Update complete. Optional platform packages stay off until enabled in Admin."
else
  echo "Warning: health check failed — inspect logs." >&2
  exit 1
fi
