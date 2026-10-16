#!/usr/bin/env bash
# Android Sentinel launcher (Linux/macOS). Finds the venv the installer made,
# installs any requirements a `git pull` added, then starts the dashboard.
#   ./run.sh            phone on USB debugging
#   ./run.sh --demo     simulated device
#   ./run.sh -s IP:PORT wireless debugging
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY="$DIR/.venv/bin/python"
[ -x "$PY" ] || PY="${XDG_DATA_HOME:-$HOME/.local/share}/android-sentinel/.venv/bin/python"
if [ ! -x "$PY" ]; then
  echo "No virtualenv found. Run the installer first: $DIR/install.sh" >&2
  exit 1
fi
STAMP="$PY.reqs-stamp"
if [ ! -f "$STAMP" ] || [ "$DIR/requirements.txt" -nt "$STAMP" ]; then
  echo "==> installing/updating dependencies"
  "$PY" -m pip install --quiet -r "$DIR/requirements.txt" && touch "$STAMP"
fi
cd "$DIR"
exec "$PY" -m sentinel "$@"
