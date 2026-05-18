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
    python3 peas_analyzer.py linpeas_output.txt --raw   # show matched source lines
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
# Patterns are matched against ANSI-stripped linpeas/winpeas output lines.
# More specific patterns must come BEFORE more general ones within each list.
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

    # Windows - DLL Hijacking / Writable binary folder
    # More specific first - actual DLL file mentioned
    (r'Possible DLL Hijacking.*\.dll',                 'DLL hijacking - missing or writable DLL file'),
    # Writable folder - could be DLL hijack OR binary replacement, check for associated service
    (r'Possible DLL Hijacking in binary folder.*AllAccess', 'Writable binary folder (Everyone:AllAccess) - check for associated service → binary replacement or DLL hijack'),
    (r'Possible DLL Hijacking in binary folder.*WriteData',  'Writable binary folder (WriteData) - check for associated service → binary replacement or DLL hijack'),
    (r'Possible DLL Hijacking in binary folder',        'Writable binary folder - check for associated service (binary replacement or DLL hijack)'),

    # Linux - SUID
    (r'SUID.*(pkexec|/usr/bin/pkexec)',                 'SUID: pkexec found (CVE-2021-4034 PwnKit)'),
    (r'SUID.*(sudo|/usr/bin/sudo)',                     'SUID: sudo binary is SUID'),
    (r'SUID.*(nmap|/usr/bin/nmap)',                     'SUID: nmap found (GTFOBins)'),
    (r'SUID.*(vim?|/usr/bin/vim)',                      'SUID: vim found (GTFOBins)'),
    (r'SUID.*(python3?|perl|ruby|php)',                 'SUID: interpreter found (GTFOBins)'),
    (r'SUID.*(bash|/bin/bash)',                         'SUID: bash is SUID'),
    (r'SUID.*(cp|/bin/cp)\b',                          'SUID: cp found - can overwrite files as root'),
    (r'SUID.*(find|/usr/bin/find)',                     'SUID: find found (GTFOBins)'),
    (r'SUID.*(wget|curl|base64)',                       'SUID: download/encode utility (GTFOBins)'),
    (r'SUID.*(tar|zip|gzip)',                           'SUID: archive utility (GTFOBins)'),
    (r'SUID.*\/(usr\/local|opt)\/',                     'SUID: binary in non-standard location - check manually'),

    # Linux - Sudo (specific binaries first, catch-all last)
    # Matches linpeas format: "User X may run the following commands"
    (r'may run.*NOPASSWD.*\(ALL\).*ALL',                'Sudo: NOPASSWD ALL - immediate root (sudo -i)'),
    (r'\(ALL.*\).*NOPASSWD.*ALL',                       'Sudo: NOPASSWD ALL - immediate root (sudo -i)'),
    (r'NOPASSWD.*\/bin\/(bash|sh)\b',                   'Sudo: NOPASSWD shell - immediate root'),
    (r'NOPASSWD.*\/usr\/bin\/env\b',                    'Sudo: NOPASSWD env (GTFOBins - instant shell)'),
    (r'NOPASSWD.*\/usr\/bin\/git\b',                    'Sudo: NOPASSWD git (GTFOBins → sudo git -p help → !bash)'),
    (r'NOPASSWD.*\/usr\/bin\/(python3?|perl|ruby|php)', 'Sudo: NOPASSWD interpreter (GTFOBins)'),
    (r'NOPASSWD.*\/usr\/bin\/(vim?|nano|less|more|man)','Sudo: NOPASSWD editor/pager (GTFOBins)'),
    (r'NOPASSWD.*\/usr\/bin\/(find|nmap|awk|sed|tar)',  'Sudo: NOPASSWD utility (GTFOBins)'),
    (r'NOPASSWD.*\/usr\/bin\/(cp|mv|tee|dd|wget|curl)', 'Sudo: NOPASSWD file utility (GTFOBins)'),
    (r'NOPASSWD.*\/usr\/bin\/(zip|ftp|ssh|mysql)',      'Sudo: NOPASSWD network/archive tool (GTFOBins)'),
    (r'NOPASSWD.*\/usr\/sbin\/',                        'Sudo: NOPASSWD sbin binary - check GTFOBins'),
    (r'NOPASSWD',                                       'Sudo: NOPASSWD entry found - check GTFOBins immediately'),

    # Linux - Writable critical files
    (r'Writable.*\/etc\/passwd',                        'Writable /etc/passwd (add root user)'),
    (r'Writable.*\/etc\/shadow',                        'Writable /etc/shadow (overwrite root hash)'),
    (r'Writable.*\/etc\/sudoers',                       'Writable /etc/sudoers'),
    (r'Writable.*cron',                                 'Writable cron file'),

    # Linux - NFS
    (r'no_root_squash',                                 'NFS: no_root_squash enabled (remote root file plant)'),

    # Linux - CVEs explicitly flagged by linpeas (linpeas format: "[+] [CVE-XXXX-YYYY] name")
    (r'\[\+\].*CVE-2021-3156',                         'CVE-2021-3156 Baron Samedit (sudo heap overflow → root)'),
    (r'\[\+\].*CVE-2021-4034',                         'CVE-2021-4034 PwnKit (pkexec → root)'),
    (r'\[\+\].*CVE-2022-0847',                         'CVE-2022-0847 DirtyPipe (kernel write → root)'),
    (r'\[\+\].*CVE-2019-14287',                        'CVE-2019-14287 sudo UID bypass → root'),
    (r'\[\+\].*CVE-2023-22809',                        'CVE-2023-22809 sudoedit path traversal → arbitrary file write'),
    (r'\[\+\].*CVE-2022-2586',                         'CVE-2022-2586 nftables UAF → root'),
    (r'\[\+\].*CVE-2021-22555',                        'CVE-2021-22555 netfilter heap overflow → root'),
    (r'\[\+\]\s+\[CVE-',                               'CVE flagged by linpeas as exploitable - review findings file'),
]

HIGH_PATTERNS = [
    # Windows - Credential hunting
    (r'Found.*password.*in.*registry',                  'Credentials: Password found in registry'),
    (r'AutoLogon.*password',                            'Credentials: AutoLogon password found'),
    (r'HKLM.*password',                                 'Credentials: Password in HKLM registry'),
    (r'Unattend.*password',                             'Credentials: Password in Unattend file'),
    (r'SAM.*SYSTEM.*readable',                          'SAM/SYSTEM files may be readable'),
    (r'DPAPI.*master.*key.*[A-Z]:\\',                'DPAPI master key found - path identified'),
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

    # Linux - Sudo version (linpeas outputs "Sudo version X.Y.Z")
    (r'Sudo version 1\.8\.(2[0-9]|3[0-1])',            'Sudo 1.8.20-1.8.31 - likely vulnerable to CVE-2021-3156'),
    (r'Sudo version 1\.9\.[0-5][^0-9]',                'Sudo 1.9.0-1.9.5 - likely vulnerable to CVE-2021-3156'),
    (r'Sudo version 1\.9\.(6|7|8|9|10|11)[^0-9]',      'Sudo version - check CVE-2023-22809 (sudoedit)'),
    (r'Sudo version 1\.[0-7]\.',                        'Old sudo version - check CVEs'),

    # Linux - Capabilities
    (r'cap_setuid',                                     'Capability: cap_setuid set (privesc path - check GTFOBins)'),
    (r'cap_dac_override',                               'Capability: cap_dac_override set (bypass file permissions)'),
    (r'cap_dac_read_search',                            'Capability: cap_dac_read_search set (read any file)'),
    (r'cap_net_raw',                                    'Capability: cap_net_raw set'),
    (r'cap_sys_admin',                                  'Capability: cap_sys_admin set (near god-mode)'),
    (r'cap_setgid',                                     'Capability: cap_setgid set'),

    # Linux - Writable systemd/init
    (r'Writable.*\.service',                            'Writable systemd service file'),
    (r'Writable.*\/etc\/init\.d',                       'Writable init.d script'),

    # Linux - LD_PRELOAD / LD_LIBRARY_PATH
    (r'env_keep.*LD_PRELOAD',                           'LD_PRELOAD in sudo env_keep (library hijack path)'),
    (r'env_keep.*LD_LIBRARY_PATH',                      'LD_LIBRARY_PATH in sudo env_keep (library hijack path)'),

    # Linux - Cron
    (r'Writable.*cron\.d',                              'Writable /etc/cron.d directory'),
    (r'cron.*script.*writable',                         'Cron script is writable'),
    (r'PATH.*cron.*writable',                           'Writable directory in cron PATH'),

    # Linux - SSH keys
    (r'Readable.*id_rsa',                               'SSH: readable private key found'),
    (r'\.ssh.*authorized_keys.*writable',               'SSH: writable authorized_keys'),

    # Linux - Kernel version
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

    # Linux - Passwords in config files
    (r'(password|passwd)\s*[=:]\s*\S+',                'Possible plaintext password in config/file'),
    (r'define\s*\(\s*[\'"].*pass',                      'Possible password in define statement (wp-config?)'),
    (r'DB_PASSWORD',                                    'Database password found in config'),
    (r'wp-config\.php',                                 'WordPress config file found - check for DB credentials'),

    # Linux - General interesting
    (r'Readable.*\/etc\/passwd',                        'Can read /etc/passwd (user enumeration)'),
    (r'\.bash_history.*readable',                       'Readable .bash_history'),
    (r'Interesting.*file.*\/var\/www',                  'Interesting file in web root'),
    (r'Interesting.*file.*\/opt',                       'Interesting file in /opt'),
    (r'MySQL.*running as root',                         'MySQL running as root (UDF exploit path)'),
    (r'docker\.sock',                                   'Writable Docker socket (container escape)'),
    (r'lxd|lxc',                                       'LXD/LXC group membership (container escape)'),
    (r'\bdisk\b.*group',                                'Member of disk group (read raw disk)'),
    (r'\badm\b.*group',                                 'Member of adm group (read logs)'),

    # Linux - Network
    (r'127\.0\.0\.1.*LISTEN',                           'Service on localhost only (port forward candidate)'),
]

INFO_PATTERNS = [
    (r'Running as.*root',                               'Already running as root'),
    (r'whoami.*root',                                   'Already root'),
    (r'Current user.*Administrator',                    'Already Administrator'),
    (r'OS Name.*Windows|Windows.*Version.*\d{4}|ProductName.*Windows', 'OS version identified'),
    (r'Linux version \d',                               'Kernel version identified'),
    (r'Hostname[=:\s]',                                 'Hostname identified'),
]

# ==============================================================================
# CORE PARSER
# Deduplicates findings by description to prevent repeated capability/group hits
# ==============================================================================
def parse_peas(content):
    findings = {
        'CRITICAL': [],
        'HIGH':     [],
        'MEDIUM':   [],
        'INFO':     []
    }

    # Track seen descriptions per severity to deduplicate
    seen = {
        'CRITICAL': set(),
        'HIGH':     set(),
        'MEDIUM':   set(),
        'INFO':     set(),
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
                    # Deduplicate by description — avoid 6x cap_net_raw etc.
                    if description not in seen[severity]:
                        seen[severity].add(description)
                        findings[severity].append({
                            'description': description,
                            'raw':         stripped[:200]
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
    if not sys.stdin.isatty():
        content     = sys.stdin.read()
        source_name = 'piped_input'
    elif len(sys.argv) >= 2 and not sys.argv[1].startswith('--'):
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
        print(f"  python3 peas_analyzer.py <peas_output_file> --raw")
        print(f"  cat peas_output.txt | python3 peas_analyzer.py")
        print(f"  ./linpeas.sh | python3 peas_analyzer.py")
        sys.exit(1)

    # Aggressive ANSI/escape code stripping
    content = re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', content)
    content = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', content)
    content = re.sub(r'\x1b\][^\x07]*\x07', '', content)
    content = re.sub(r'\x1b[()][AB012]', '', content)
    content = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', content)

    platform = detect_platform(content)
    findings = parse_peas(content)

    show_raw = '--raw' in sys.argv

    print_findings(findings, platform, show_raw)

    findings_file = save_findings(findings, platform, source_name)
    print(f"{C.GREEN}[*] Findings saved to: {findings_file}{C.RESET}\n")

if __name__ == '__main__':
    main()
