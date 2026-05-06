#!/usr/bin/env python3
"""
PEAS Output Analyzer
====================
Processes linpeas/winpeas output and extracts actionable findings by severity.
Supports both file input and piped input.

Usage:
    python3 peas_analyzer.py linpeas_output.txt
    cat linpeas_output.txt | python3 peas_analyzer.py
    ./linpeas.sh | python3 peas_analyzer.py
"""

import re
import sys
import os
from datetime import datetime

# ==============================================================================
# ANSI COLOURS
# ==============================================================================
class C:
    RED     = '\033[91m'
    YELLOW  = '\033[93m'
    CYAN    = '\033[96m'
    GREEN   = '\033[92m'
    BOLD    = '\033[1m'
    RESET   = '\033[0m'
    DIM     = '\033[2m'

# ==============================================================================
# PLATFORM DETECTION
# Looks for known linpeas/winpeas markers to label output source
# ==============================================================================
def detect_platform(content):
    windows_markers = [
        r'winpeas', r'Windows Privesc', r'HKLM\\', r'HKCU\\',
        r'SeImpersonatePrivilege', r'AlwaysInstallElevated',
        r'C:\\Windows', r'PowerShell', r'schtasks', r'wmic',
        r'Unquoted Service', r'Services with weak'
    ]
    linux_markers = [
        r'linpeas', r'Linux Privesc', r'/etc/passwd', r'/etc/shadow',
        r'/bin/bash', r'SUID', r'sudo -l', r'crontab', r'/etc/cron',
        r'LD_PRELOAD', r'NFS.*no_root_squash', r'\.ssh/authorized_keys'
    ]

    windows_score = sum(1 for m in windows_markers if re.search(m, content, re.I))
    linux_score   = sum(1 for m in linux_markers   if re.search(m, content, re.I))

    if windows_score > linux_score:
        return 'Windows (WinPEAS output detected)'
    elif linux_score > windows_score:
        return 'Linux (LinPEAS output detected)'
    else:
        return 'Unknown platform (mixed or unrecognised output)'

# ==============================================================================
# PATTERN DEFINITIONS
# Each entry is (pattern, description)
# Description is used in the findings output instead of the raw matched line
# where the raw line would be too noisy.
# ==============================================================================

CRITICAL_PATTERNS = [
    # Windows - Token Privileges
    (r'SeImpersonatePrivilege\s+\S+\s+Enabled',         'Token: SeImpersonatePrivilege ENABLED (Potato exploit path)'),
    (r'SeAssignPrimaryTokenPrivilege\s+\S+\s+Enabled',  'Token: SeAssignPrimaryTokenPrivilege ENABLED (Potato exploit path)'),
    (r'SeDebugPrivilege\s+\S+\s+Enabled',               'Token: SeDebugPrivilege ENABLED'),
    (r'SeBackupPrivilege\s+\S+\s+Enabled',              'Token: SeBackupPrivilege ENABLED (SAM/SYSTEM dump path)'),
    (r'SeRestorePrivilege\s+\S+\s+Enabled',             'Token: SeRestorePrivilege ENABLED'),
    (r'SeTakeOwnershipPrivilege\s+\S+\s+Enabled',       'Token: SeTakeOwnershipPrivilege ENABLED'),
    (r'SeManageVolumePrivilege\s+\S+\s+Enabled',        'Token: SeManageVolumePrivilege ENABLED'),

    # Windows - Service misconfigs
    (r'Unquoted Service.*C:\\Program Files',            'Unquoted service path in Program Files'),
    (r'No quotes and Space detected',                   'Unquoted service path detected'),
    (r'Everyone.*SERVICE_ALL_ACCESS',                   'Service: Everyone has SERVICE_ALL_ACCESS'),
    (r'BUILTIN\\Users.*SERVICE_ALL_ACCESS',             'Service: Users have SERVICE_ALL_ACCESS'),
    (r'binPath.*Everyone',                              'Writable service binary path'),

    # Windows - Registry
    (r'AlwaysInstallElevated.*1',                       'AlwaysInstallElevated enabled (MSI privesc path)'),

    # Windows - DLL Hijacking
    (r'Possible DLL Hijacking',                         'Possible DLL hijacking opportunity'),

    # Linux - SUID
    (r'SUID.*(pkexec|/usr/bin/pkexec)',                 'SUID: pkexec found (CVE-2021-4034 PwnKit)'),
    (r'SUID.*(sudo|/usr/bin/sudo)',                     'SUID: sudo binary is SUID'),
    (r'SUID.*(nmap|/usr/bin/nmap)',                     'SUID: nmap found (GTFOBins)'),
    (r'SUID.*(vim|/usr/bin/vim)',                       'SUID: vim found (GTFOBins)'),
    (r'SUID.*(python|perl|ruby|php)',                   'SUID: interpreter found (GTFOBins)'),
    (r'SUID.*(bash|/bin/bash)',                         'SUID: bash is SUID'),
    (r'SUID.*(cp|/bin/cp)',                             'SUID: cp found - can overwrite files as root'),
    (r'SUID.*(find|/usr/bin/find)',                     'SUID: find found (GTFOBins)'),

    # Linux - Sudo
    (r'\(ALL.*NOPASSWD.*ALL\)',                         'Sudo: (ALL) NOPASSWD: ALL - full root access'),
    (r'NOPASSWD.*\/bin\/bash',                          'Sudo: NOPASSWD bash'),
    (r'NOPASSWD.*\/bin\/sh',                            'Sudo: NOPASSWD sh'),
    (r'NOPASSWD.*(python|perl|ruby|php)',               'Sudo: NOPASSWD interpreter'),
    (r'NOPASSWD.*(vim|nano|less|more|man)',             'Sudo: NOPASSWD editor/pager (GTFOBins)'),
    (r'NOPASSWD.*(find|nmap|awk|sed)',                  'Sudo: NOPASSWD utility (GTFOBins)'),
    (r'NOPASSWD.*(cp|mv|tee|dd)',                       'Sudo: NOPASSWD file write utility'),

    # Linux - Writable critical files
    (r'Writable.*\/etc\/passwd',                        'Writable /etc/passwd (add root user)'),
    (r'Writable.*\/etc\/shadow',                        'Writable /etc/shadow (overwrite root hash)'),
    (r'Writable.*\/etc\/sudoers',                       'Writable /etc/sudoers'),
    (r'Writable.*cron',                                 'Writable cron file'),

    # Linux - NFS
    (r'no_root_squash',                                 'NFS: no_root_squash enabled (remote root file plant)'),
]

HIGH_PATTERNS = [
    # Windows - Credential hunting
    (r'Found.*password.*in.*registry',                  'Credentials: Password found in registry'),
    (r'AutoLogon.*password',                            'Credentials: AutoLogon password found'),
    (r'HKLM.*password',                                 'Credentials: Password in HKLM registry'),
    (r'Unattend.*password',                             'Credentials: Password in Unattend file'),
    (r'SAM.*SYSTEM.*readable',                          'SAM/SYSTEM files may be readable'),
    (r'DPAPI.*master.*key',                             'DPAPI master key found'),
    (r'\.rdp.*password',                                'RDP file with saved password'),
    (r'wifi.*password|WifiPassword',                    'WiFi password in config'),

    # Windows - Scheduled tasks
    (r'Task.*Everyone.*Write',                          'Scheduled task writable by Everyone'),
    (r'Task.*BUILTIN\\Users.*Write',                    'Scheduled task writable by Users'),

    # Windows - Registry autorun
    (r'HKLM.*Run.*Writable',                            'Writable registry autorun key (HKLM)'),
    (r'HKCU.*Run.*Writable',                            'Writable registry autorun key (HKCU)'),

    # Windows - PATH hijacking
    (r'Writable.*PATH.*directory',                      'Writable directory in system PATH'),

    # Linux - Sudo version
    (r'Sudo version 1\.8\.(1[0-9]|2[0-8])',            'Sudo version may be vulnerable to CVE-2021-3156 (Baron Samedit)'),
    (r'Sudo version 1\.[0-7]\.',                        'Old sudo version - check CVEs'),

    # Linux - Capabilities
    (r'cap_setuid',                                     'Capability: cap_setuid set (privesc path)'),
    (r'cap_net_raw',                                    'Capability: cap_net_raw set'),
    (r'cap_dac_override',                               'Capability: cap_dac_override set (bypass file permissions)'),
    (r'cap_dac_read_search',                            'Capability: cap_dac_read_search set (read any file)'),

    # Linux - Writable systemd/init
    (r'Writable.*\.service',                            'Writable systemd service file'),
    (r'Writable.*\/etc\/init\.d',                       'Writable init.d script'),

    # Linux - LD_PRELOAD
    (r'LD_PRELOAD',                                     'LD_PRELOAD in sudo env_keep (library hijack path)'),
    (r'LD_LIBRARY_PATH',                                'LD_LIBRARY_PATH in sudo env_keep'),

    # Linux - Cron
    (r'Writable.*cron\.d',                              'Writable /etc/cron.d directory'),
    (r'cron.*script.*writable',                         'Cron script is writable'),
    (r'PATH.*cron.*writable',                           'Writable directory in cron PATH'),

    # Linux - SUID (less common)
    (r'SUID.*(wget|curl|base64)',                       'SUID: download/encode utility (GTFOBins)'),
    (r'SUID.*(tar|zip|gzip)',                           'SUID: archive utility (GTFOBins)'),
    (r'SUID.*\/(usr\/local|opt)\/',                     'SUID: binary in non-standard location'),

    # Linux - SSH keys
    (r'Readable.*id_rsa',                               'SSH: readable private key found'),
    (r'\.ssh.*authorized_keys.*writable',               'SSH: writable authorized_keys'),

    # Linux - Kernel
    (r'Linux version [2-4]\.',                          'Old kernel version - check local exploits'),
]

MEDIUM_PATTERNS = [
    # Windows - General interesting
    (r'Interesting.*file.*AppData',                     'Interesting files in AppData'),
    (r'Interesting.*file.*Desktop',                     'Interesting files on Desktop'),
    (r'Interesting.*\.kdbx',                            'KeePass database found'),
    (r'Interesting.*\.pfx|\.p12',                       'Certificate file found'),
    (r'Interesting.*\.key',                             'Key file found'),
    (r'McAfee.*SiteList',                               'McAfee SiteList.xml found (may contain creds)'),
    (r'Groups\.xml.*found',                             'Groups.xml found (GPP credentials)'),
    (r'PowerShell.*history',                            'PowerShell history file found'),
    (r'Clipboard.*content',                             'Clipboard content captured'),

    # Windows - Network
    (r'Listening.*127\.0\.0\.1',                        'Service listening on localhost only (port forward candidate)'),
    (r'Active.*connections',                            'Active network connections - review for internal services'),

    # Linux - General interesting
    (r'Readable.*\/etc\/passwd',                        'Can read /etc/passwd (user enumeration)'),
    (r'history.*file.*found',                           'Shell history file found'),
    (r'\.bash_history.*readable',                       'Readable .bash_history'),
    (r'config.*password|password.*config',              'Possible password in config file'),
    (r'Interesting.*file.*\/var\/www',                  'Interesting file in web root'),
    (r'Interesting.*file.*\/opt',                       'Interesting file in /opt'),
    (r'Interesting.*\.conf.*password',                  'Config file may contain password'),
    (r'MySQL.*running as root',                         'MySQL running as root (UDF exploit path)'),
    (r'Docker.*socket.*writable|docker\.sock',          'Writable Docker socket (container escape)'),
    (r'lxd|lxc',                                       'LXD/LXC group membership (container escape)'),
    (r'disk.*group',                                    'Member of disk group (read raw disk)'),
    (r'adm.*group',                                     'Member of adm group (read logs)'),

    # Linux - Network
    (r'127\.0\.0\.1.*LISTEN',                           'Service on localhost only (port forward candidate)'),
    (r'Active Internet connections',                    'Active connections - review for internal services'),
]

INFO_PATTERNS = [
    (r'Running as.*root',                               'Already running as root'),
    (r'whoami.*root',                                   'Already root'),
    (r'Current user.*Administrator',                    'Already Administrator'),
    (r'hostname',                                       'Hostname identified'),
    (r'OS.*Version|Windows.*Version',                  'OS version identified'),
]

# ==============================================================================
# CORE PARSER
# ==============================================================================
def parse_peas(content):
    findings = {
        'CRITICAL': [],
        'HIGH':     [],
        'MEDIUM':   [],
        'INFO':     []
    }

    pattern_map = [
        ('CRITICAL', CRITICAL_PATTERNS),
        ('HIGH',     HIGH_PATTERNS),
        ('MEDIUM',   MEDIUM_PATTERNS),
        ('INFO',     INFO_PATTERNS),
    ]

    for line in content.split('\n'):
        stripped = line.strip()
        if not stripped or stripped.startswith('=') or stripped.startswith('#'):
            continue

        matched = False
        for severity, patterns in pattern_map:
            if matched:
                break
            for pattern, description in patterns:
                if re.search(pattern, stripped, re.I):
                    # Store both the description and the raw line for context
                    findings[severity].append({
                        'description': description,
                        'raw':         stripped[:200]  # cap line length
                    })
                    matched = True
                    break

    return findings

# ==============================================================================
# OUTPUT FORMATTING
# ==============================================================================
SEVERITY_COLOURS = {
    'CRITICAL': C.RED,
    'HIGH':     C.YELLOW,
    'MEDIUM':   C.CYAN,
    'INFO':     C.GREEN,
}

SEVERITY_ICONS = {
    'CRITICAL': '[!!!]',
    'HIGH':     '[!]',
    'MEDIUM':   '[+]',
    'INFO':     '[*]',
}

def print_findings(findings, platform, show_raw=False):
    print(f"\n{C.BOLD}{'=' * 65}{C.RESET}")
    print(f"{C.BOLD}  PEAS ANALYZER - {platform}{C.RESET}")
    print(f"{C.BOLD}{'=' * 65}{C.RESET}")

    total = sum(len(v) for v in findings.values())
    if total == 0:
        print(f"\n{C.GREEN}No actionable findings detected.{C.RESET}")
        print("This could mean the box is clean, or PEAS output wasn't parsed correctly.")
        print("Consider running manual checks from your enumeration doc.\n")
        return

    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'INFO']:
        items = findings[severity]
        if not items:
            continue

        colour = SEVERITY_COLOURS[severity]
        icon   = SEVERITY_ICONS[severity]

        print(f"\n{colour}{C.BOLD}=== {severity} ({len(items)} findings) ==={C.RESET}")
        print(f"{C.DIM}{'-' * 65}{C.RESET}")

        # Cap output per severity to avoid noise
        display_limit = {'CRITICAL': 20, 'HIGH': 15, 'MEDIUM': 10, 'INFO': 5}
        limit = display_limit[severity]

        for i, finding in enumerate(items[:limit]):
            print(f"{colour}{icon}{C.RESET} {finding['description']}")
            if show_raw:
                print(f"    {C.DIM}>> {finding['raw']}{C.RESET}")

        if len(items) > limit:
            print(f"    {C.DIM}... and {len(items) - limit} more (see findings file){C.RESET}")

    print(f"\n{C.BOLD}{'=' * 65}{C.RESET}")
    print(f"{C.BOLD}Total actionable findings: {total}{C.RESET}")
    crit = len(findings['CRITICAL'])
    high = len(findings['HIGH'])
    if crit > 0:
        print(f"{C.RED}{C.BOLD}>> {crit} CRITICAL findings - exploit these first{C.RESET}")
    elif high > 0:
        print(f"{C.YELLOW}>> {high} HIGH findings - likely privesc paths{C.RESET}")
    else:
        print(f"{C.CYAN}>> No critical/high findings - review MEDIUM findings manually{C.RESET}")
    print(f"{C.BOLD}{'=' * 65}{C.RESET}\n")

def save_findings(findings, platform, source_name):
    timestamp   = datetime.now().strftime('%Y%m%d_%H%M%S')
    safe_source = re.sub(r'[^\w]', '_', source_name)
    filename    = f"findings_{safe_source}_{timestamp}.txt"

    with open(filename, 'w') as f:
        f.write(f"PEAS Analyzer Findings\n")
        f.write(f"{'=' * 65}\n")
        f.write(f"Platform : {platform}\n")
        f.write(f"Source   : {source_name}\n")
        f.write(f"Time     : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"{'=' * 65}\n\n")

        total = sum(len(v) for v in findings.values())

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'INFO']:
            items = findings[severity]
            if not items:
                continue
            icon = SEVERITY_ICONS[severity]
            f.write(f"\n=== {severity} ({len(items)} findings) ===\n")
            f.write(f"{'-' * 65}\n")
            for finding in items:
                f.write(f"{icon} {finding['description']}\n")
                f.write(f"   >> {finding['raw']}\n")

        f.write(f"\n{'=' * 65}\n")
        f.write(f"Total actionable findings: {total}\n")

    return filename

# ==============================================================================
# MAIN
# ==============================================================================
def main():
    # Determine input source
    if not sys.stdin.isatty():
        # Data is being piped in
        content     = sys.stdin.read()
        source_name = 'piped_input'
    elif len(sys.argv) >= 2:
        # File argument provided
        filepath = sys.argv[1]
        if not os.path.isfile(filepath):
            print(f"[!] File not found: {filepath}")
            sys.exit(1)
        with open(filepath, 'r', errors='ignore') as f:
            content = f.read()
        source_name = os.path.basename(filepath)
    else:
        print(f"Usage:")
        print(f"  python3 peas_analyzer.py <peas_output_file>")
        print(f"  cat peas_output.txt | python3 peas_analyzer.py")
        print(f"  ./linpeas.sh | python3 peas_analyzer.py")
        sys.exit(1)

    # Strip ANSI colour codes from PEAS output
    content = re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', content)
    content = re.sub(r'\x1b\][^\x07]*\x07', '', content)  # strip OSC sequences too

    # Detect platform
    platform = detect_platform(content)

    # Parse
    findings = parse_peas(content)

    # Show raw matched lines if --raw flag passed
    show_raw = '--raw' in sys.argv

    # Print to terminal
    print_findings(findings, platform, show_raw)

    # Save to file
    findings_file = save_findings(findings, platform, source_name)
    print(f"{C.GREEN}[*] Findings saved to: {findings_file}{C.RESET}\n")

if __name__ == '__main__':
    main()
