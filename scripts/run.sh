#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)

export PYTHONUNBUFFERED=1
export PYTHONPATH="$ROOT_DIR/backend"

# Backend
PY=python
if ! command -v $PY >/dev/null 2>&1; then
  if command -v python3 >/dev/null 2>&1; then
    PY=python3
  fi
fi

# Ensure dependencies are installed if missing
if ! $PY -c 'import uvicorn, pydantic_settings' >/dev/null 2>&1; then
  echo "Installing backend requirements..."
  $PY -m pip install -r "$ROOT_DIR/backend/requirements.txt"
fi

echo "Starting backend at http://127.0.0.1:8000 ..."
$PY -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000 &
BACK_PID=$!

cleanup() {
  kill $BACK_PID 2>/dev/null || true
}
trap cleanup EXIT

sleep 2

# Static frontend via python simple server proxied by uvicorn? We'll serve directly from uvicorn root via reverse proxy suggestion
# Open a lightweight static server for frontend on 5173
# Free port 5173 if occupied
if command -v lsof >/dev/null 2>&1; then
  lsof -ti:5173 | xargs -r kill -9 || true
elif command -v fuser >/dev/null 2>&1; then
  fuser -k 5173/tcp || true
fi

cd "$ROOT_DIR/frontend"
$PY -m http.server 5173 &
FRONT_PID=$!
trap 'cleanup; kill $FRONT_PID 2>/dev/null || true' EXIT

cat <<EOF

Demo running.
- API:   http://127.0.0.1:8000
- UI:    http://127.0.0.1:5173

In the UI, click "Load Sample Emails" then "Analyze".
If you set OPENAI_API_KEY in environment, LLM analysis will be included.

Press Ctrl+C to stop.
EOF

wait
