#!/usr/bin/env bash
# Android Sentinel installer - Linux / macOS.
# Clones (or updates) the repo, builds a venv, installs deps, and prints how to run.
#   ./install.sh                 install to ~/android-sentinel
#   ./install.sh /opt/sentinel   install somewhere else
#   ./install.sh --demo          install, then start in demo mode right away
set -euo pipefail

REPO="https://github.com/sxi9/andro"
BRANCH="claude/youthful-goldberg-01npzu"
DIR="$HOME/android-sentinel"
START_DEMO=0

for arg in "$@"; do
  case "$arg" in
    --demo) START_DEMO=1 ;;
    *) DIR="$arg" ;;
  esac
done

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

command -v git >/dev/null     || fail "git is required (install it and re-run)"
command -v python3 >/dev/null || fail "python3 (3.10+) is required"
python3 - <<'EOF' || fail "python 3.10+ required"
import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)
EOF

# If this script already sits inside a checkout, use that instead of cloning.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "$SCRIPT_DIR/sentinel/__main__.py" ]; then
  DIR="$SCRIPT_DIR"
  say "using existing checkout: $DIR"
elif [ -d "$DIR/.git" ]; then
  say "updating existing install: $DIR"
  git -C "$DIR" fetch origin "$BRANCH" && git -C "$DIR" checkout "$BRANCH" \
    && git -C "$DIR" pull --ff-only origin "$BRANCH"
else
  say "cloning $REPO ($BRANCH) -> $DIR"
  git clone -b "$BRANCH" "$REPO" "$DIR"
fi

# Python refuses to create a venv in a path containing ':' (the PATH
# separator on POSIX). Fall back to a safe location while the code stays put.
VENV_ROOT="$DIR"
case "$DIR" in *:*)
  VENV_ROOT="$HOME/.local/share/android-sentinel"
  mkdir -p "$VENV_ROOT"
  say "checkout path contains ':' - venv goes to $VENV_ROOT instead"
;; esac

say "creating virtualenv"
python3 -m venv "$VENV_ROOT/.venv" 2>/dev/null || {
  fail "python3 -m venv failed - on Debian/Ubuntu: sudo apt install python3-venv, then re-run"
}
PY="$VENV_ROOT/.venv/bin/python"
"$VENV_ROOT/.venv/bin/pip" install --quiet --upgrade pip
say "installing dependencies"
"$VENV_ROOT/.venv/bin/pip" install --quiet -r "$DIR/requirements.txt"

if command -v adb >/dev/null; then
  say "adb found: $(adb version 2>/dev/null | head -1)"
else
  cat <<'EOT'
NOTE: adb (Android platform-tools) is not installed. Sentinel needs it for a
real device (demo mode works without it). Install it:
  Debian/Ubuntu:  sudo apt install adb
  Fedora:         sudo dnf install android-tools
  Arch:           sudo pacman -S android-tools
  macOS:          brew install android-platform-tools
EOT
fi

say "done."
cat <<EOT

Run it (from the checkout folder):
  cd "$DIR"
  "$PY" -m sentinel --demo     # simulated device, try the UI
  "$PY" -m sentinel            # phone on USB debugging
  "$PY" -m sentinel -s IP:PORT # wireless debugging

Dashboard: http://127.0.0.1:8765  (local-only by design)
EOT

if [ "$START_DEMO" = "1" ]; then
  say "starting demo mode"
  cd "$DIR"
  exec "$PY" -m sentinel --demo
fi
