# OSCP Commander

A local web UI for semi-automated command execution during OSCP labs and exams.
Runs at `http://localhost:50000`. Sends commands to named `screen` sessions.

---

## Setup

```bash
# 1. Clone into your OSCP-CheatSheet repo (or anywhere on Kali)
git clone ... && cd oscp-commander

# 2. Start the server
chmod +x start.sh
./start.sh

# Optional: point at your cheatsheet repo's commands folder
./start.sh /path/to/OSCP-CheatSheet/commands
```

Then open Firefox → `http://localhost:50000`

---

## Directory structure

```
oscp-commander/
├── server.py           ← Flask backend
├── start.sh            ← Startup script
├── requirements.txt
├── static/
│   └── index.html      ← Full UI (single file)
└── commands/           ← Command files (edit freely, update via git pull)
    ├── linux.txt
    ├── windows.txt
    ├── active_directory.txt
    └── utils.txt
```

---

## Command file format

Files live in `commands/`. One command per line.
- Lines starting with `# ===` become **section headers**
- Lines starting with `#` (without `===`) become **inline comments** above the next command
- Blank lines separate sections
- `{{VARNAME}}` placeholders are substituted from the variables table

```
# === PHASE 1: QUICK WINS ===
# Run as first thing — always
sudo -l
# SUID binaries
find / -perm -4000 -type f 2>/dev/null
```

---

## Workflow

1. **Start screen sessions** — Click `+ New` to create named screen sessions (one per box)
2. **Select session** from the dropdown — variables are per-session
3. **Fill in variables** — `RHOST`, `LHOST`, etc. Placeholders turn green when filled, red when missing
4. **Send commands** — Click `▶` or press `Ctrl+Enter` on a focused row → sent directly to the screen session
5. **Done tracking** — Sent commands are automatically crossed out. Toggle manually with `✓`/`↺`
6. **Copy** — Press `⎘` or `C` on a row to copy the substituted command to clipboard

---

## Variables

Variables are **per screen session** (in memory — reset on server restart).
Set them in the left panel. `{{RHOST}}` etc. in command files are replaced on send/copy.

Default variables:
- `RHOST` — Target IP
- `LHOST` — Kali IP
- `LPORT` — Listener port
- `FILENAME` — File to transfer
- `DOMAIN` — AD domain name
- `DOMAIN_USER` — Domain username
- `DC_IP` — Domain controller IP
- `DOMAIN_SID` — Domain SID
- `KRBTGT_HASH` — krbtgt NTLM hash

---

## Updating commands

Just edit the `.txt` files (or `git pull`) — refresh the tab in the UI to reload.
The backend re-reads files on every request.

---

## Keyboard shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+Enter` | Send focused command to screen session |
| `C` | Copy focused command (with vars) |

---

## OSCP exam layout (suggested screen sessions)

```
screen -S box1    ← Standalone box 1
screen -S box2    ← Standalone box 2
screen -S box3    ← Standalone box 3
screen -S dc01    ← AD domain controller
screen -S web01   ← AD web server / pivot
```
