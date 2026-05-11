#!/usr/bin/env bash
# OSCP Commander — Start Script
# Usage: ./start.sh [path/to/OSCP-CheatSheet]
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHEATSHEET="${1:-$HOME/OSCP-CheatSheet}"

if [ ! -d "$CHEATSHEET/.git" ]; then
  echo "[!] Warning: $CHEATSHEET is not a git repo — git sync disabled"
fi

echo "[*] Script dir:  $SCRIPT_DIR"
echo "[*] Cheatsheet:  $CHEATSHEET"
echo "[*] Starting on  http://localhost:50000"

pip3 install flask flask-cors -q --break-system-packages 2>/dev/null

export CHEATSHEET_DIR="$CHEATSHEET"
cd "$SCRIPT_DIR"
python3 server.py
