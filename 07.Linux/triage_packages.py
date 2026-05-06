#!/usr/bin/env python3
# triage_packages.py
# Usage: python3 triage_packages.py packages.txt
# Optional: python3 triage_packages.py packages.txt --baseline 2020-07-31

import sys
import re
import argparse
from collections import Counter

# Keywords that suggest interesting/non-standard software
INTERESTING = [
    'apache', 'nginx', 'mysql', 'mariadb', 'php', 'python', 'ruby', 'perl',
    'ssh', 'openssh', 'ftp', 'vsftpd', 'proftpd', 'smb', 'samba',
    'tomcat', 'docker', 'git', 'curl', 'wget', 'netcat', 'ncat', 'socat',
    'screen', 'tmux', 'redis', 'mongodb', 'postgres', 'sqlite',
    'wordpress', 'drupal', 'joomla', 'jenkins', 'gitlab', 'grafana',
    'elastic', 'kibana', 'logstash', 'zabbix', 'nagios',
    'exim', 'postfix', 'sendmail', 'dovecot',
    'openssl', 'libssl', 'sudo', 'polkit', 'pkexec',
    'aerospike', 'memcached', 'rabbitmq', 'activemq'
]

# Known vulnerable versions — (package_keyword, vulnerable_version_substring, CVE, description, searchsploit_hint)
KNOWN_VULNS = [
    # Apache
    ('apache2', '2.4.49', 'CVE-2021-41773', 'Path traversal & RCE (unauthenticated)', 'apache 2.4.49'),
    ('apache2', '2.4.50', 'CVE-2021-42013', 'Path traversal & RCE bypass of 41773 fix', 'apache 2.4.50'),
    ('apache2', '2.4.41', None, 'Apache 2.4.41 — check searchsploit, multiple known issues', 'apache 2.4.41'),

    # OpenSSH
    ('openssh', '7.2p2', 'CVE-2016-6210', 'User enumeration via timing attack', 'openssh 7.2'),
    ('openssh', '8.9p1', 'CVE-2023-38408', 'Remote code execution via ssh-agent', 'openssh 8.9'),

    # Sudo
    ('sudo', '1.8.2', 'CVE-2021-3156', 'Baron Samedit heap overflow -> root', 'sudo 1.8'),
    ('sudo', '1.8.3', 'CVE-2021-3156', 'Baron Samedit heap overflow -> root', 'sudo 1.8'),
    ('sudo', '1.8.31', 'CVE-2021-3156', 'Baron Samedit heap overflow -> root', 'sudo 1.8.31'),
    ('sudo', '1.9.5', 'CVE-2021-3156', 'Baron Samedit heap overflow -> root', 'sudo 1.9.5'),
    ('sudo', '1.9.1', 'CVE-2023-22809', 'sudoedit path traversal -> arbitrary file write', 'sudo 1.9'),

    # Polkit / pkexec
    ('policykit', '0.105', 'CVE-2021-4034', 'PwnKit: local privilege escalation via pkexec', 'polkit'),
    ('polkit', '0.105', 'CVE-2021-4034', 'PwnKit: local privilege escalation via pkexec', 'polkit'),

    # MySQL
    ('mysql', '5.7', None, 'MySQL 5.7 — check searchsploit for version-specific issues', 'mysql 5.7'),
    ('mysql', '8.0', None, 'MySQL 8.0 — check searchsploit for version-specific issues', 'mysql 8.0'),

    # OpenSSL
    ('openssl', '1.1.1', None, 'OpenSSL 1.1.1 — check for Heartbleed variants and recent CVEs', 'openssl 1.1'),
    ('openssl', '3.0', 'CVE-2022-3602', 'OpenSSL 3.0.x buffer overflow', 'openssl 3.0'),

    # Samba
    ('samba', '4.5', 'CVE-2017-7494', 'SambaCry RCE via writable share', 'samba 4.5'),
    ('samba', '4.6', 'CVE-2017-7494', 'SambaCry RCE via writable share', 'samba 4.6'),

    # Redis
    ('redis', '6.', None, 'Redis 6.x — check for unauthenticated access and SLAVEOF RCE', 'redis'),
    ('redis', '7.', None, 'Redis 7.x — check for unauthenticated access', 'redis'),

    # Exim
    ('exim4', '4.87', 'CVE-2019-10149', 'Exim RCE via MAIL FROM command injection', 'exim 4.87'),
    ('exim4', '4.91', 'CVE-2019-10149', 'Exim RCE via MAIL FROM command injection', 'exim 4.91'),

    # PHP
    ('php', '7.4', None, 'PHP 7.4 — check searchsploit for version-specific issues', 'php 7.4'),
    ('php', '8.0', None, 'PHP 8.0 — check searchsploit for version-specific issues', 'php 8.0'),

    # Drupal
    ('drupal', '7.', 'CVE-2018-7600', 'Drupalgeddon2 RCE', 'drupal'),
    ('drupal', '8.', 'CVE-2018-7600', 'Drupalgeddon2 RCE', 'drupal'),

    # Git
    ('git', '2.', None, 'Git installed — check for exposed .git dirs on web server', None),

    # Aerospike
    ('aerospike', '5.1.0', 'CVE-2020-13151', 'OS command execution via UDF', 'aerospike'),
]

def detect_baseline(lines):
    dates = []
    for line in lines:
        line = line.strip().strip('|').strip()
        if ';' not in line:
            continue
        try:
            _, date = line.rsplit(';', 1)
            date = date.strip()[:10]
            if re.match(r'\d{4}-\d{2}-\d{2}', date):
                dates.append(date)
        except:
            continue
    if not dates:
        return None
    return Counter(dates).most_common(1)[0][0]


def parse_packages(lines):
    packages = []
    for line in lines:
        line = line.strip().strip('|').strip()
        if ';' not in line:
            continue
        try:
            pkg, date = line.rsplit(';', 1)
            pkg = pkg.strip()
            date = date.strip()[:10]
            if not re.match(r'\d{4}-\d{2}-\d{2}', date):
                continue
            # Extract name and version from package string
            # Format: name_version_arch
            parts = pkg.split('_')
            name = parts[0] if parts else pkg
            version = parts[1] if len(parts) > 1 else ''
            packages.append({'raw': pkg, 'name': name, 'version': version, 'date': date})
        except:
            continue
    return packages


def check_vulns(pkg):
    hits = []
    for keyword, vuln_ver, cve, desc, ss_hint in KNOWN_VULNS:
        if keyword.lower() in pkg['name'].lower():
            if vuln_ver.lower() in pkg['version'].lower():
                hits.append({
                    'cve': cve or 'No CVE — manual check',
                    'desc': desc,
                    'searchsploit': ss_hint
                })
    return hits


def main():
    parser = argparse.ArgumentParser(description='Triage installed packages for privilege escalation and exploit opportunities')
    parser.add_argument('file', help='Package list file')
    parser.add_argument('--baseline', help='Override baseline date (YYYY-MM-DD)', default=None)
    args = parser.parse_args()

    with open(args.file) as f:
        lines = f.readlines()

    packages = parse_packages(lines)

    if not packages:
        print("[-] No packages parsed — check input format")
        sys.exit(1)

    baseline = args.baseline or detect_baseline(lines)
    print(f"[*] Baseline install date detected: {baseline}")
    print(f"[*] Total packages parsed: {len(packages)}\n")

    later = [p for p in packages if p['date'] > baseline]
    flagged = [p for p in later if any(kw in p['name'].lower() for kw in INTERESTING)]
    vuln_hits = [(p, check_vulns(p)) for p in packages if check_vulns(p)]

    # Output
    print("=" * 60)
    print("=== INSTALLED AFTER BASELINE ===")
    print("=" * 60)
    if later:
        for p in sorted(later, key=lambda x: x['date']):
            print(f"  {p['date']}  {p['raw']}")
    else:
        print("  None found")

    print()
    print("=" * 60)
    print("=== FLAGGED AS INTERESTING (post-baseline) ===")
    print("=" * 60)
    if flagged:
        for p in sorted(flagged, key=lambda x: x['date']):
            print(f"  {p['date']}  {p['raw']}")
    else:
        print("  None found")

    print()
    print("=" * 60)
    print("=== KNOWN VULNERABILITY MATCHES ===")
    print("=" * 60)
    if vuln_hits:
        for p, hits in vuln_hits:
            print(f"\n  [!] {p['raw']}")
            for h in hits:
                print(f"      CVE     : {h['cve']}")
                print(f"      Details : {h['desc']}")
                if h['searchsploit']:
                    print(f"      Run     : searchsploit \"{h['searchsploit']}\"")
    else:
        print("  No direct matches found")

    print()
    print("=" * 60)
    print("=== SEARCHSPLOIT COMMANDS FOR FLAGGED PACKAGES ===")
    print("=" * 60)
    for p in flagged:
        ver = p['version'].split('-')[0]  # strip ubuntu suffix
        print(f"  searchsploit \"{p['name']} {ver}\"")

    print()
    print("[*] Done. Review flagged packages and run searchsploit commands above.")
    print("[*] Also check: https://www.cvedetails.com for any packages not matched above.")


if __name__ == '__main__':
    main()
