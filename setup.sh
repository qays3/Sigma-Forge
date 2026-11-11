#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$ROOT/.venv"
HOST="${SIGMA_FORGE_HOST:-127.0.0.1}"
PORT="${SIGMA_FORGE_PORT:-8000}"
RUN=0
DEV=0
UPDATE_ATTACK=0
DOCKER=0
RECREATE=0

PURPLE='\033[38;2;176;108;255m'
GREEN='\033[38;2;91;214;164m'
YELLOW='\033[38;2;224;179;65m'
RED='\033[38;2;255;107;138m'
RESET='\033[0m'

info() { printf "${PURPLE}[sigma-forge]${RESET} %s\n" "$1"; }
ok() { printf "${GREEN}[ok]${RESET} %s\n" "$1"; }
warn() { printf "${YELLOW}[warn]${RESET} %s\n" "$1"; }
fail() { printf "${RED}[error]${RESET} %s\n" "$1" >&2; exit 1; }

usage() {
  cat <<EOF
Sigma Forge setup for Linux and macOS

Usage: ./setup.sh [options]

  --run              Start the server after setup
  --dev              Install test tools and run the test suite
  --update-attack    Download the latest MITRE ATT&CK data
  --docker           Build and start with Docker Compose instead of a venv
  --recreate         Delete and rebuild the virtual environment
  --host HOST        Bind address (default: $HOST)
  --port PORT        Port (default: $PORT)
  -h, --help         Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run) RUN=1 ;;
    --dev) DEV=1 ;;
    --update-attack) UPDATE_ATTACK=1 ;;
    --docker) DOCKER=1 ;;
    --recreate) RECREATE=1 ;;
    --host) HOST="${2:?missing value for --host}"; shift ;;
    --port) PORT="${2:?missing value for --port}"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; fail "Unknown option: $1" ;;
  esac
  shift
done

cd "$ROOT"

if [[ "$DOCKER" -eq 1 ]]; then
  command -v docker >/dev/null 2>&1 || fail "Docker is not installed"
  info "Building and starting the container"
  if docker compose version >/dev/null 2>&1; then
    COMPOSE=(docker compose)
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE=(docker-compose)
  else
    fail "Docker Compose is not installed"
  fi
  if [[ "$UPDATE_ATTACK" -eq 1 ]]; then
    "${COMPOSE[@]}" build --build-arg REFRESH_ATTACK=true
  else
    "${COMPOSE[@]}" build
  fi
  "${COMPOSE[@]}" up -d
  ok "Sigma Forge is running at http://127.0.0.1:8000"
  exit 0
fi

PYTHON=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3 python; do
  if command -v "$candidate" >/dev/null 2>&1; then
    if "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
      PYTHON="$candidate"
      break
    fi
  fi
done
[[ -n "$PYTHON" ]] || fail "Python 3.10 or newer is required"
info "Using $($PYTHON --version) at $(command -v "$PYTHON")"

if [[ "$RECREATE" -eq 1 && -d "$VENV" ]]; then
  info "Removing old virtual environment"
  rm -rf "$VENV"
fi

if [[ ! -x "$VENV/bin/python" ]]; then
  info "Creating virtual environment in .venv"
  "$PYTHON" -m venv "$VENV" || fail "Could not create the venv. On Debian or Ubuntu run: sudo apt install python3-venv"
fi

VPY="$VENV/bin/python"
info "Installing dependencies"
"$VPY" -m pip install --upgrade pip >/dev/null
if [[ "$DEV" -eq 1 ]]; then
  "$VPY" -m pip install -r requirements-dev.txt
else
  "$VPY" -m pip install -r requirements.txt
fi
ok "Dependencies installed"

if [[ "$UPDATE_ATTACK" -eq 1 || ! -f "$ROOT/data/attack/attack.json" ]]; then
  info "Fetching MITRE ATT&CK data"
  "$VPY" tools/fetch_attack.py || warn "ATT&CK download failed. Coverage will not work until you run: $VPY tools/fetch_attack.py"
fi

if [[ "$DEV" -eq 1 ]]; then
  info "Running tests"
  "$VPY" -m pytest -q
fi

ok "Setup finished"
echo
echo "  Start the server:  $VPY -m uvicorn app.main:app --host $HOST --port $PORT"
echo "  Or run:            ./setup.sh --run"
echo "  Open:              http://$HOST:$PORT"
echo

if [[ "$RUN" -eq 1 ]]; then
  info "Starting Sigma Forge on http://$HOST:$PORT (Ctrl+C to stop)"
  exec "$VPY" -m uvicorn app.main:app --host "$HOST" --port "$PORT"
fi
