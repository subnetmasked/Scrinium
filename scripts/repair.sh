#!/usr/bin/env sh
# Diagnostics and safe recovery for Scrinium.
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

REBUILD=0
while [ $# -gt 0 ]; do
  case "$1" in
    --rebuild) REBUILD=1; shift ;;
    *) echo "Usage: $0 [--rebuild]" >&2; exit 1 ;;
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

echo "=== Scrinium repair / diagnostics ==="
echo "Data dir: $ROOT/data"

if [ -d data/.scrinium ]; then
  echo "Config dir permissions: $(ls -ld data/.scrinium 2>/dev/null || true)"
  for db in data/.scrinium/auth.db data/.scrinium/security.db data/.scrinium/itsm.db; do
    if [ -f "$db" ]; then
      echo "DB: $db ($(wc -c <"$db" | tr -d ' ') bytes)"
      if command -v sqlite3 >/dev/null 2>&1; then
        chk="$(sqlite3 "$db" 'PRAGMA integrity_check;' 2>/dev/null | head -1)"
        echo "  integrity: $chk"
      fi
    fi
  done
else
  echo "No data/.scrinium yet (fresh install?)."
fi

for slug in security itsm; do
  if [ -d "data/$slug" ]; then
    echo "WARNING: data/$slug exists — may conflict with package URL /$slug/. Consider renaming."
  fi
done

if [ "$REBUILD" = 1 ]; then
  echo "Rebuilding containers (--rebuild requested)..."
  compose down
  compose build --no-cache scrinium
  compose up -d --force-recreate
  echo "Done. Check health: curl -s http://127.0.0.1:\${SCRINIUM_HTTP_PORT:-8080}/health"
else
  echo "No destructive action taken. Use --rebuild to force image rebuild."
  echo "Forgot password? podman exec -it scrinium python3 /app/scripts/reset_password.py <user>"
fi
