#!/usr/bin/env bash
# OSCP Commander — Start Script
# Usage: ./start.sh [path/to/OSCP-CheatSheet]
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHEATSHEET="${1:-$HOME/OSCP-CheatSheet}"

if [ ! -d "$CHEATSHEET/.git" ]; then
  echo "[!] Warning: $CHEATSHEET is not a git repo — git sync disabled"
fi

# Check tmux is available
if ! command -v tmux &>/dev/null; then
  echo "[!] tmux not found — install with: sudo apt install tmux"
  exit 1
fi

echo "[*] Script dir:  $SCRIPT_DIR"
echo "[*] Cheatsheet:  $CHEATSHEET"
echo "[*] Starting on  http://localhost:50000"
echo "[*] Session mgr: tmux (use 'tmux new -s box1' to create sessions)"

pip3 install flask flask-cors -q --break-system-packages 2>/dev/null

export CHEATSHEET_DIR="$CHEATSHEET"
cd "$SCRIPT_DIR"
python3 server.py
