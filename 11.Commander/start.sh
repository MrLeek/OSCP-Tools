#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# OSCP Commander — Start Script
# Usage: ./start.sh [path/to/commands/dir]
# Default commands dir: ./commands (relative to this script)
# ─────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Allow overriding the commands dir (e.g. point at your git repo's commands/ folder)
COMMANDS_DIR="${1:-$SCRIPT_DIR/commands}"

if [ ! -d "$COMMANDS_DIR" ]; then
  echo "[!] Commands directory not found: $COMMANDS_DIR"
  exit 1
fi

echo "[*] Commands dir: $COMMANDS_DIR"
echo "[*] Starting OSCP Commander on http://localhost:50000"
echo "[*] Press Ctrl-C to stop"

export COMMANDS_DIR="$COMMANDS_DIR"
cd "$SCRIPT_DIR"

# Install deps if needed (Kali usually has pip3)
pip3 install -r requirements.txt -q --break-system-packages 2>/dev/null

python3 server.py
