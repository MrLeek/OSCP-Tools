#!/usr/bin/env python3
"""
OSCP Commander — Backend Server
Plan order: recon → ports → foothold → os_enum → privesc → ad_enum → ad_attacks
Utils served separately (sidebar collapsible).
"""

import os
import re
import subprocess
import threading
import time
from pathlib import Path
from flask import Flask, jsonify, request
from flask_cors import CORS

BASE_DIR     = Path(__file__).parent.resolve()
COMMANDS_DIR = Path(os.environ.get('COMMANDS_DIR', BASE_DIR / 'commands')).resolve()
CHEATSHEET   = Path(os.environ.get('CHEATSHEET_DIR', Path.home() / 'OSCP-CheatSheet')).resolve()
GIT_LOCK     = threading.Lock()

app = Flask(__name__, static_folder=None)
CORS(app)

# ── In-memory state ───────────────────────────────────────────────────────────
boxes      = {}
git_status = {'last_pull': None, 'changed_files': [], 'new_cmds': [], 'error': None}

# ── Variable definitions ──────────────────────────────────────────────────────
COMMON_VARS = [
    {'key': 'TARGET',      'desc': 'Target IP address'},
    {'key': 'KALI',        'desc': 'Kali IP address'},
    {'key': 'KALI_PORT',   'desc': 'Listener / HTTP server port'},
    {'key': 'DOMAIN',      'desc': 'Domain name (e.g. corp.com)'},
    {'key': 'USER',        'desc': 'Username on target'},
    {'key': 'PASS',        'desc': 'Password on target'},
    {'key': 'FILENAME',    'desc': 'File to transfer'},
    {'key': 'PORTS',       'desc': 'Open ports for nmap (comma-separated)'},
    {'key': 'PORT',        'desc': 'Single service port'},
    {'key': 'SHARE',       'desc': 'SMB share name'},
    {'key': 'KEY_FILE',    'desc': 'SSH private key path'},
]
AD_VARS = [
    {'key': 'DC_IP',       'desc': 'Domain controller IP'},
    {'key': 'DC_HOSTNAME', 'desc': 'DC hostname (e.g. DC01)'},
    {'key': 'DC1',         'desc': 'First DC label (e.g. corp)'},
    {'key': 'DC2',         'desc': 'Second DC label (e.g. com)'},
    {'key': 'DOMAIN_SID',  'desc': 'Domain SID'},
    {'key': 'NTLM_HASH',   'desc': 'NTLM hash'},
    {'key': 'KRBTGT_HASH', 'desc': 'krbtgt NTLM hash (post-root)'},
]

# Predefined extras the user can activate per-box
EXTRA_VARS = [
    {'key': 'SUBNET',        'desc': 'Target subnet (e.g. 192.168.1)'},
    {'key': 'DATABASE',      'desc': 'Database name'},
    {'key': 'SERVICE',       'desc': 'Service name (for sc/systemctl)'},
    {'key': 'SERVICE_PATH',  'desc': 'Service binary path'},
    {'key': 'BINARY',        'desc': 'Binary name for PATH hijack'},
    {'key': 'DLL_NAME',      'desc': 'DLL name for hijacking'},
    {'key': 'BINARY_NAME',   'desc': 'Binary name (msfvenom output)'},
    {'key': 'SID',           'desc': 'SID for ticket attacks'},
    {'key': 'TICKET_FILE',   'desc': 'Kerberos ticket filename'},
    {'key': 'IMAGE',         'desc': 'Docker image name'},
    {'key': 'EXPORT',        'desc': 'NFS export path'},
    {'key': 'SPN_HOST',      'desc': 'SPN hostname'},
    {'key': 'TARGET_USER',   'desc': 'Target user (for ACL abuse)'},
    {'key': 'TARGET_GROUP',  'desc': 'Target group (for ACL abuse)'},
    {'key': 'TARGET_HOST',   'desc': 'Lateral movement target host'},
    {'key': 'KERNEL_VERSION','desc': 'Kernel version string'},
    {'key': 'SERVICE_ACCOUNT','desc': 'Service account name'},
]

# ── Port → command file (for port-specific plan sections) ─────────────────────
PORT_FILE_MAP = {
    '21':   'ftp.txt',
    '22':   'ssh.txt',
    '25':   'smtp.txt',
    '53':   'dns.txt',
    '69':   'ftp.txt',
    '80':   'web.txt',
    '88':   'kerberos.txt',
    '110':  'smtp.txt',
    '111':  'rpc.txt',
    '135':  'rpc.txt',
    '139':  'smb.txt',
    '143':  'smtp.txt',
    '161':  'snmp.txt',
    '389':  'ldap.txt',
    '443':  'web.txt',
    '445':  'smb.txt',
    '593':  'rpc.txt',
    '636':  'ldap.txt',
    '993':  'smtp.txt',
    '1433': 'db.txt',
    '2049': 'nfs.txt',
    '3268': 'ldap.txt',
    '3269': 'ldap.txt',
    '3306': 'db.txt',
    '3389': 'rdp.txt',
    '5432': 'db.txt',
    '5433': 'db.txt',
    '5900': 'rdp.txt',
    '5985': 'winrm.txt',
    '5986': 'winrm.txt',
    '6379': 'db.txt',
    '8080': 'web.txt',
    '8443': 'web.txt',
}

# Port → which foothold sections are relevant
# Maps section header prefixes in foothold.txt to the ports that trigger them
FOOTHOLD_PORT_SECTIONS = {
    'SHELL STABILISATION':   None,        # always included
    'REVERSE SHELL':         None,        # always included
    'WEB:':                  {'80','443','8080','8443'},
    'SMB:':                  {'139','445'},
    'SSH:':                  {'22'},
    'RDP:':                  {'3389'},
    'WINRM:':                {'5985','5986'},
    'MSSQL:':                {'1433'},
    'MYSQL:':                {'3306'},
    'NFS:':                  {'2049'},
    'SNMP:':                 {'161'},
    'KERBEROS:':             {'88'},
    'SQLI':                  {'80','443','8080','8443','1433','3306','5432'},
}

# ── OS plan order ─────────────────────────────────────────────────────────────
OS_PLAN = {
    'linux': [
        {'file': 'recon.txt',         'label': 'Recon',         'phase': 'recon'},
        # port sections inserted here dynamically
        {'file': 'foothold.txt',      'label': 'Foothold',      'phase': 'foothold'},
        {'file': 'linux_enum.txt',    'label': 'Linux Enum',    'phase': 'enum'},
        {'file': 'linux_privesc.txt', 'label': 'PrivEsc',       'phase': 'privesc'},
    ],
    'windows': [
        {'file': 'recon.txt',           'label': 'Recon',         'phase': 'recon'},
        # port sections inserted here dynamically
        {'file': 'foothold.txt',        'label': 'Foothold',      'phase': 'foothold'},
        {'file': 'windows_enum.txt',    'label': 'Windows Enum',  'phase': 'enum'},
        {'file': 'windows_privesc.txt', 'label': 'PrivEsc',       'phase': 'privesc'},
    ],
    'ad': [
        {'file': 'recon.txt',           'label': 'Recon',         'phase': 'recon'},
        # port sections inserted here dynamically
        {'file': 'foothold.txt',        'label': 'Foothold',      'phase': 'foothold'},
        {'file': 'windows_enum.txt',    'label': 'Windows Enum',  'phase': 'enum'},
        {'file': 'windows_privesc.txt', 'label': 'PrivEsc',       'phase': 'privesc'},
        {'file': 'ad_enum.txt',         'label': 'AD Enum',       'phase': 'ad_enum'},
        {'file': 'ad_attacks.txt',      'label': 'AD Attacks',    'phase': 'ad_attacks'},
    ],
}

# ── Command file parser ───────────────────────────────────────────────────────
def parse_command_file(filepath):
    """
    Parse .txt file into sections.
    # === HEADING === → section header
    # comment → label for next command
    Returns [{section, commands:[{cmd,comment}]}]
    """
    sections         = []
    current_section  = 'General'
    current_commands = []
    current_comment  = None

    try:
        lines = Path(filepath).read_text(errors='replace').splitlines()
    except Exception:
        return []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            current_comment = None
            continue
        if stripped.startswith('#'):
            inner = stripped.lstrip('#').strip()
            if inner.startswith('===') and inner.endswith('==='):
                if current_commands:
                    sections.append({'section': current_section, 'commands': current_commands})
                    current_commands = []
                current_section = inner.strip('= ').strip()
                current_comment = None
            else:
                current_comment = inner
        else:
            current_commands.append({'cmd': stripped, 'comment': current_comment})
            current_comment = None

    if current_commands:
        sections.append({'section': current_section, 'commands': current_commands})

    return sections


def read_commands(filename):
    path = COMMANDS_DIR / filename
    if not path.exists():
        return []
    return parse_command_file(path)


def filter_foothold(sections, open_ports):
    """
    Filter foothold.txt sections based on open ports.
    Sections with no port requirement are always included.
    """
    port_set = set(str(p) for p in open_ports)
    filtered = []

    for section in sections:
        heading = section['section'].upper()
        matched = False

        for trigger, required_ports in FOOTHOLD_PORT_SECTIONS.items():
            if heading.startswith(trigger):
                if required_ports is None:
                    # Always include
                    matched = True
                elif required_ports & port_set:
                    matched = True
                break
        else:
            # Section heading not in map → include by default
            matched = True

        if matched:
            filtered.append(section)

    return filtered


# ── Plan builder ──────────────────────────────────────────────────────────────
def build_plan(box):
    """
    Build ordered plan:
    recon → [port sections] → foothold (filtered) → enum → privesc → [ad sections]
    Returns [{id, label, phase, source, sections}]
    """
    os_type    = box.get('os', 'linux')
    open_ports = [str(p) for p in box.get('ports', [])]
    plan       = []
    base       = OS_PLAN.get(os_type, OS_PLAN['linux'])

    for entry in base:
        if entry['phase'] == 'recon':
            # Insert recon, then port-specific sections immediately after
            secs = read_commands(entry['file'])
            if secs:
                plan.append({
                    'id': 'recon', 'label': 'Recon',
                    'phase': 'recon', 'source': entry['file'], 'sections': secs,
                })

            # Port-specific sections (deduplicated by filename)
            seen_files = set()
            for port in open_ports:
                fname = PORT_FILE_MAP.get(port)
                if not fname or fname in seen_files:
                    continue
                seen_files.add(fname)
                psecs = read_commands(fname)
                if psecs:
                    service = fname.replace('.txt', '').upper()
                    plan.append({
                        'id':       f'port_{fname.replace(".txt","")}',
                        'label':    service,
                        'phase':    'port',
                        'source':   fname,
                        'sections': psecs,
                    })

        elif entry['phase'] == 'foothold':
            all_secs = read_commands(entry['file'])
            filtered = filter_foothold(all_secs, open_ports)
            if filtered:
                plan.append({
                    'id': 'foothold', 'label': 'Foothold',
                    'phase': 'foothold', 'source': entry['file'], 'sections': filtered,
                })

        else:
            secs = read_commands(entry['file'])
            if secs:
                plan.append({
                    'id':       entry['phase'],
                    'label':    entry['label'],
                    'phase':    entry['phase'],
                    'source':   entry['file'],
                    'sections': secs,
                })

    return plan


# ── Git sync ──────────────────────────────────────────────────────────────────
def git_pull():
    global git_status
    if not (CHEATSHEET / '.git').exists():
        git_status = {
            'last_pull': time.strftime('%H:%M:%S'),
            'changed_files': [], 'new_cmds': [],
            'error': f'Not a git repo: {CHEATSHEET}',
        }
        return
    with GIT_LOCK:
        try:
            result = subprocess.run(
                ['git', '-C', str(CHEATSHEET), 'pull', '--ff-only'],
                capture_output=True, text=True, timeout=15
            )
            output  = result.stdout + result.stderr
            changed = []
            new_cmds= []

            if 'Already up to date' not in output and result.returncode == 0:
                diff = subprocess.run(
                    ['git', '-C', str(CHEATSHEET), 'diff', '--name-only', 'HEAD@{1}', 'HEAD'],
                    capture_output=True, text=True
                )
                changed = [f.strip() for f in diff.stdout.splitlines() if f.strip()]
                for f in changed:
                    if f.endswith('.txt') and 'commands/' in f:
                        new_cmds.append({'file': f})

            git_status = {
                'last_pull':     time.strftime('%H:%M:%S'),
                'changed_files': changed,
                'new_cmds':      new_cmds,
                'error':         None if result.returncode == 0 else output.strip(),
            }
        except Exception as e:
            git_status = {
                'last_pull': time.strftime('%H:%M:%S'),
                'changed_files': [], 'new_cmds': [], 'error': str(e),
            }


# ── Screen helpers ────────────────────────────────────────────────────────────
def get_screen_sessions():
    try:
        r = subprocess.run(['screen', '-ls'], capture_output=True, text=True)
        return [m.group(1) for l in r.stdout.splitlines()
                if (m := re.search(r'(\d+\.\S+)', l))]
    except Exception:
        return []


def send_to_screen(session, command):
    try:
        r = subprocess.run(
            ['screen', '-S', session, '-X', 'stuff', command + '\n'],
            capture_output=True, text=True
        )
        return r.returncode == 0, r.stderr
    except Exception as e:
        return False, str(e)


def substitute_vars(cmd, variables):
    return re.sub(r'\{\{(\w+)\}\}', lambda m: variables.get(m.group(1), m.group(0)), cmd)


# ── Box helpers ───────────────────────────────────────────────────────────────
def default_variables(os_type):
    schema = COMMON_VARS + (AD_VARS if os_type == 'ad' else [])
    return {v['key']: '' for v in schema}


def vars_schema(os_type):
    return COMMON_VARS + (AD_VARS if os_type == 'ad' else [])


def parse_nmap_output(text):
    ports = set()
    for line in text.splitlines():
        m = re.match(r'\s*(\d+)/(tcp|udp)\s+open', line, re.IGNORECASE)
        if m:
            ports.add(m.group(1))
    return sorted(ports, key=int)


# ── API ───────────────────────────────────────────────────────────────────────

@app.route('/api/init')
def api_init():
    threading.Thread(target=git_pull, daemon=True).start()
    return jsonify({'boxes': list(boxes.values()), 'git': git_status})


@app.route('/api/git')
def api_git():
    return jsonify(git_status)


@app.route('/api/git/pull', methods=['POST'])
def api_git_pull():
    git_pull()
    return jsonify(git_status)


@app.route('/api/boxes')
def api_boxes():
    return jsonify({'boxes': list(boxes.values())})


@app.route('/api/boxes', methods=['POST'])
def api_create_box():
    data    = request.json or {}
    name    = data.get('name', '').strip()
    os_type = data.get('os', 'linux').lower()
    session = data.get('session', '').strip()

    if not name:
        return jsonify({'error': 'Name required'}), 400
    if os_type not in ('linux', 'windows', 'ad'):
        return jsonify({'error': 'os must be linux, windows, or ad'}), 400

    box_id = re.sub(r'[^a-zA-Z0-9_\-]', '_', name.lower())
    if box_id in boxes:
        box_id = f"{box_id}_{len(boxes)}"

    boxes[box_id] = {
        'id':           box_id,
        'name':         name,
        'os':           os_type,
        'session':      session,
        'ports':        [],
        'variables':    default_variables(os_type),
        'done_cmds':    [],
        'nmap_raw':     '',
        'custom_vars':  {},   # user-added key=value pairs
        'active_extras': [],  # keys from EXTRA_VARS the user activated
    }
    return jsonify({'box': boxes[box_id]})


@app.route('/api/boxes/<box_id>', methods=['GET'])
def api_get_box(box_id):
    box = boxes.get(box_id)
    return jsonify({'box': box}) if box else (jsonify({'error': 'Not found'}), 404)


@app.route('/api/boxes/<box_id>', methods=['PATCH'])
def api_update_box(box_id):
    box = boxes.get(box_id)
    if not box:
        return jsonify({'error': 'Not found'}), 404
    data = request.json or {}
    for field in ('name', 'os', 'session', 'nmap_raw', 'ports',
                  'done_cmds', 'active_extras'):
        if field in data:
            box[field] = data[field]
    if 'variables' in data:
        box['variables'].update(data['variables'])
    if 'custom_vars' in data:
        box['custom_vars'].update(data['custom_vars'])
    return jsonify({'box': box})


@app.route('/api/boxes/<box_id>/nmap', methods=['POST'])
def api_parse_nmap(box_id):
    box = boxes.get(box_id)
    if not box:
        return jsonify({'error': 'Not found'}), 404
    text      = (request.json or {}).get('nmap', '')
    new_ports = parse_nmap_output(text)
    existing  = set(str(p) for p in box['ports'])
    for p in new_ports:
        existing.add(p)
    box['ports']    = sorted(existing, key=lambda x: int(x))
    box['nmap_raw'] = text
    return jsonify({'ports': box['ports']})


@app.route('/api/boxes/<box_id>/plan')
def api_plan(box_id):
    box = boxes.get(box_id)
    if not box:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'plan': build_plan(box), 'done_cmds': box['done_cmds']})


@app.route('/api/boxes/<box_id>/run', methods=['POST'])
def api_run(box_id):
    box = boxes.get(box_id)
    if not box:
        return jsonify({'error': 'Not found'}), 404
    data    = request.json or {}
    raw_cmd = data.get('command', '').strip()
    cmd_key = data.get('cmd_key', '')
    session = box.get('session') or data.get('session', '')

    if not session:
        return jsonify({'error': 'No screen session assigned to this box'}), 400
    if not raw_cmd:
        return jsonify({'error': 'No command'}), 400

    # Merge all variable sources: defaults + active extras + custom vars
    all_vars = dict(box['variables'])
    for k in box.get('active_extras', []):
        all_vars.setdefault(k, '')
    all_vars.update(box.get('custom_vars', {}))

    final = substitute_vars(raw_cmd, all_vars)
    ok, err = send_to_screen(session, final)

    if ok and cmd_key and cmd_key not in box['done_cmds']:
        box['done_cmds'].append(cmd_key)

    return (jsonify({'status': 'ok', 'sent': final}) if ok
            else jsonify({'error': err, 'sent': final}), 500)


@app.route('/api/boxes/<box_id>/done', methods=['POST'])
def api_toggle_done(box_id):
    box = boxes.get(box_id)
    if not box:
        return jsonify({'error': 'Not found'}), 404
    key = (request.json or {}).get('cmd_key', '')
    if key in box['done_cmds']:
        box['done_cmds'].remove(key)
    else:
        box['done_cmds'].append(key)
    return jsonify({'done_cmds': box['done_cmds']})


@app.route('/api/sessions')
def api_sessions():
    return jsonify({'sessions': get_screen_sessions()})


@app.route('/api/sessions', methods=['POST'])
def api_create_session():
    name = (request.json or {}).get('name', '').strip()
    if not name or not re.match(r'^[a-zA-Z0-9_\-]+$', name):
        return jsonify({'error': 'Invalid session name'}), 400
    try:
        subprocess.Popen(['screen', '-dmS', name])
        return jsonify({'status': 'ok', 'name': name})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/vars_schema/<os_type>')
def api_vars_schema(os_type):
    return jsonify({
        'schema':      vars_schema(os_type),
        'extra_vars':  EXTRA_VARS,
    })


@app.route('/api/utils')
def api_utils():
    return jsonify({'sections': read_commands('utils.txt')})


@app.route('/')
def serve_index():
    idx = BASE_DIR / 'index.html'
    if not idx.exists():
        return f'index.html not found at {idx}', 404
    return idx.read_text(), 200, {'Content-Type': 'text/html; charset=utf-8'}


if __name__ == '__main__':
    print(f'[*] OSCP Commander → http://localhost:50000')
    print(f'[*] Commands dir:  {COMMANDS_DIR}')
    print(f'[*] Cheatsheet:    {CHEATSHEET}')
    threading.Thread(target=git_pull, daemon=True).start()
    app.run(host='127.0.0.1', port=50000, debug=False)    {'key': 'PORTS',        'desc': 'Comma-separated open ports (for nmap)'},
    {'key': 'PORT',         'desc': 'Single port (for service-specific commands)'},
    {'key': 'SHARE',        'desc': 'SMB share name'},
]
AD_VARS = [
    {'key': 'DC_IP',        'desc': 'Domain controller IP'},
    {'key': 'DC_HOSTNAME',  'desc': 'DC hostname (e.g. DC01)'},
    {'key': 'DC1',          'desc': 'First part of DC domain (e.g. corp)'},
    {'key': 'DC2',          'desc': 'Second part of DC domain (e.g. com)'},
    {'key': 'DOMAIN_SID',   'desc': 'Domain SID'},
    {'key': 'NTLM_HASH',    'desc': 'NTLM hash'},
    {'key': 'KRBTGT_HASH',  'desc': 'krbtgt NTLM hash (post-root)'},
]

# ── Port → command file mapping ───────────────────────────────────────────────
# Maps open port numbers to .txt files in commands/
PORT_FILE_MAP = {
    '21':   'ftp.txt',
    '22':   'ssh.txt',
    '23':   'ssh.txt',      # telnet - use ssh.txt nc commands
    '25':   'smtp.txt',
    '53':   'dns.txt',
    '69':   'ftp.txt',      # TFTP - basic file ops
    '80':   'web.txt',
    '88':   'kerberos.txt',
    '110':  'smtp.txt',     # POP3 - grouped with mail
    '111':  'rpc.txt',
    '135':  'rpc.txt',
    '139':  'smb.txt',
    '143':  'smtp.txt',     # IMAP - grouped with mail
    '161':  'snmp.txt',
    '389':  'ldap.txt',
    '443':  'web.txt',
    '445':  'smb.txt',
    '593':  'rpc.txt',
    '636':  'ldap.txt',
    '993':  'smtp.txt',
    '1433': 'db.txt',
    '2049': 'nfs.txt',
    '3268': 'ldap.txt',
    '3269': 'ldap.txt',
    '3306': 'db.txt',
    '3389': 'rdp.txt',
    '5432': 'db.txt',
    '5433': 'db.txt',
    '5900': 'rdp.txt',      # VNC - similar connect pattern
    '5985': 'winrm.txt',
    '5986': 'winrm.txt',
    '6379': 'db.txt',       # Redis
    '8080': 'web.txt',
    '8443': 'web.txt',
}

# ── OS plan: which files are always included, in order ───────────────────────
OS_PLAN = {
    'linux': [
        {'file': 'recon.txt',         'label': 'Recon',         'phase': 'recon'},
        {'file': 'linux_enum.txt',    'label': 'Linux Enum',    'phase': 'enum'},
        {'file': 'linux_privesc.txt', 'label': 'Linux PrivEsc', 'phase': 'privesc'},
    ],
    'windows': [
        {'file': 'recon.txt',           'label': 'Recon',           'phase': 'recon'},
        {'file': 'windows_enum.txt',    'label': 'Windows Enum',    'phase': 'enum'},
        {'file': 'windows_privesc.txt', 'label': 'Windows PrivEsc', 'phase': 'privesc'},
    ],
    'ad': [
        {'file': 'recon.txt',           'label': 'Recon',           'phase': 'recon'},
        {'file': 'windows_enum.txt',    'label': 'Windows Enum',    'phase': 'enum'},
        {'file': 'windows_privesc.txt', 'label': 'Windows PrivEsc', 'phase': 'privesc'},
        {'file': 'ad_enum.txt',         'label': 'AD Enum',         'phase': 'ad_enum'},
        {'file': 'ad_attacks.txt',      'label': 'AD Attacks',      'phase': 'ad_attacks'},
    ],
}

# ── Command file parser ───────────────────────────────────────────────────────
def parse_command_file(filepath):
    """
    Parse a .txt command file into sections.
    # === HEADING === lines → section headers
    # comment lines → inline notes above next command
    Blank lines → section separators
    Returns: [{section, commands: [{cmd, comment}]}]
    """
    sections         = []
    current_section  = 'General'
    current_commands = []
    current_comment  = None

    try:
        lines = Path(filepath).read_text(errors='replace').splitlines()
    except Exception:
        return []

    for line in lines:
        stripped = line.strip()

        if not stripped:
            current_comment = None
            continue

        if stripped.startswith('#'):
            inner = stripped.lstrip('#').strip()
            if inner.startswith('===') and inner.endswith('==='):
                # Flush section
                if current_commands:
                    sections.append({'section': current_section, 'commands': current_commands})
                    current_commands = []
                current_section = inner.strip('= ').strip()
                current_comment = None
            else:
                current_comment = inner
        else:
            current_commands.append({'cmd': stripped, 'comment': current_comment})
            current_comment = None

    if current_commands:
        sections.append({'section': current_section, 'commands': current_commands})

    return sections


def read_commands(filename):
    """Read and parse a command file by name from COMMANDS_DIR."""
    path = COMMANDS_DIR / filename
    if not path.exists():
        return []
    return parse_command_file(path)


# ── Git sync ──────────────────────────────────────────────────────────────────
def git_pull():
    global git_status
    if not (CHEATSHEET / '.git').exists():
        git_status['error'] = f'Not a git repo: {CHEATSHEET}'
        git_status['last_pull'] = time.strftime('%H:%M:%S')
        return
    with GIT_LOCK:
        try:
            result = subprocess.run(
                ['git', '-C', str(CHEATSHEET), 'pull', '--ff-only'],
                capture_output=True, text=True, timeout=15
            )
            output   = result.stdout + result.stderr
            changed  = []
            new_cmds = []

            if 'Already up to date' not in output and result.returncode == 0:
                diff = subprocess.run(
                    ['git', '-C', str(CHEATSHEET), 'diff', '--name-only', 'HEAD@{1}', 'HEAD'],
                    capture_output=True, text=True
                )
                changed = [f.strip() for f in diff.stdout.splitlines() if f.strip()]
                # Flag any command files in commands/ that are new
                for f in changed:
                    if f.endswith('.txt') and 'commands/' in f:
                        new_cmds.append({'file': f})

            git_status = {
                'last_pull':     time.strftime('%H:%M:%S'),
                'changed_files': changed,
                'new_cmds':      new_cmds,
                'error':         None if result.returncode == 0 else output.strip(),
            }
        except Exception as e:
            git_status['error']      = str(e)
            git_status['last_pull']  = time.strftime('%H:%M:%S')


# ── Screen helpers ────────────────────────────────────────────────────────────
def get_screen_sessions():
    try:
        r = subprocess.run(['screen', '-ls'], capture_output=True, text=True)
        return [re.search(r'(\d+\.\S+)', l).group(1)
                for l in r.stdout.splitlines() if re.search(r'(\d+\.\S+)', l)]
    except Exception:
        return []


def send_to_screen(session, command):
    try:
        r = subprocess.run(
            ['screen', '-S', session, '-X', 'stuff', command + '\n'],
            capture_output=True, text=True
        )
        return r.returncode == 0, r.stderr
    except Exception as e:
        return False, str(e)


def substitute_vars(cmd, variables):
    return re.sub(r'\{\{(\w+)\}\}', lambda m: variables.get(m.group(1), m.group(0)), cmd)


# ── Box helpers ───────────────────────────────────────────────────────────────
def default_variables(os_type):
    schema = COMMON_VARS + (AD_VARS if os_type == 'ad' else [])
    return {v['key']: '' for v in schema}


def vars_schema(os_type):
    return COMMON_VARS + (AD_VARS if os_type == 'ad' else [])


def parse_nmap(text):
    ports = set()
    for line in text.splitlines():
        m = re.match(r'\s*(\d+)/(tcp|udp)\s+open', line, re.IGNORECASE)
        if m:
            ports.add(m.group(1))
    return sorted(ports, key=int)


def build_plan(box):
    """
    Build plan sections for a box:
    1. OS base files (recon → enum → privesc → ad if applicable)
    2. Port-triggered files (deduplicated)
    Returns [{id, label, phase, source, sections}]
    """
    os_type = box.get('os', 'linux')
    ports   = [str(p) for p in box.get('ports', [])]
    plan    = []

    # OS base sections
    for entry in OS_PLAN.get(os_type, []):
        sections = read_commands(entry['file'])
        if sections:
            plan.append({
                'id':       entry['phase'],
                'label':    entry['label'],
                'phase':    entry['phase'],
                'source':   entry['file'],
                'sections': sections,
            })

    # Port-triggered sections (deduplicate by filename)
    seen_files = set()
    for port in ports:
        fname = PORT_FILE_MAP.get(port)
        if not fname or fname in seen_files:
            continue
        seen_files.add(fname)
        sections = read_commands(fname)
        if sections:
            label = fname.replace('.txt', '').upper()
            plan.append({
                'id':       f'port_{fname.replace(".txt","")}',
                'label':    f'Port {port} — {label}',
                'phase':    'port',
                'source':   fname,
                'sections': sections,
            })

    return plan


# ── API ───────────────────────────────────────────────────────────────────────

@app.route('/api/init')
def api_init():
    threading.Thread(target=git_pull, daemon=True).start()
    return jsonify({'boxes': list(boxes.values()), 'git': git_status})


@app.route('/api/git')
def api_git():
    return jsonify(git_status)


@app.route('/api/git/pull', methods=['POST'])
def api_git_pull():
    git_pull()
    return jsonify(git_status)


@app.route('/api/boxes')
def api_boxes():
    return jsonify({'boxes': list(boxes.values())})


@app.route('/api/boxes', methods=['POST'])
def api_create_box():
    data    = request.json or {}
    name    = data.get('name', '').strip()
    os_type = data.get('os', 'linux').lower()
    session = data.get('session', '').strip()
    if not name:
        return jsonify({'error': 'Name required'}), 400
    if os_type not in ('linux', 'windows', 'ad'):
        return jsonify({'error': 'os must be linux, windows, or ad'}), 400

    box_id = re.sub(r'[^a-zA-Z0-9_\-]', '_', name.lower())
    if box_id in boxes:
        box_id = f"{box_id}_{len(boxes)}"

    boxes[box_id] = {
        'id':        box_id,
        'name':      name,
        'os':        os_type,
        'session':   session,
        'ports':     [],
        'variables': default_variables(os_type),
        'done_cmds': [],
        'nmap_raw':  '',
    }
    return jsonify({'box': boxes[box_id]})


@app.route('/api/boxes/<box_id>', methods=['GET'])
def api_get_box(box_id):
    box = boxes.get(box_id)
    return jsonify({'box': box}) if box else (jsonify({'error': 'Not found'}), 404)


@app.route('/api/boxes/<box_id>', methods=['PATCH'])
def api_update_box(box_id):
    box = boxes.get(box_id)
    if not box:
        return jsonify({'error': 'Not found'}), 404
    data = request.json or {}
    for field in ('name', 'os', 'session', 'nmap_raw', 'ports'):
        if field in data:
            box[field] = data[field]
    if 'variables' in data:
        box['variables'].update(data['variables'])
    if 'done_cmds' in data:
        box['done_cmds'] = data['done_cmds']
    return jsonify({'box': box})


@app.route('/api/boxes/<box_id>/nmap', methods=['POST'])
def api_parse_nmap(box_id):
    box = boxes.get(box_id)
    if not box:
        return jsonify({'error': 'Not found'}), 404
    nmap_text = (request.json or {}).get('nmap', '')
    new_ports = parse_nmap(nmap_text)
    existing  = set(str(p) for p in box['ports'])
    for p in new_ports:
        existing.add(p)
    box['ports']    = sorted(existing, key=lambda x: int(x))
    box['nmap_raw'] = nmap_text
    return jsonify({'ports': box['ports']})


@app.route('/api/boxes/<box_id>/plan')
def api_plan(box_id):
    box = boxes.get(box_id)
    if not box:
        return jsonify({'error': 'Not found'}), 404
    return jsonify({'plan': build_plan(box), 'done_cmds': box['done_cmds']})


@app.route('/api/boxes/<box_id>/run', methods=['POST'])
def api_run(box_id):
    box = boxes.get(box_id)
    if not box:
        return jsonify({'error': 'Not found'}), 404
    data    = request.json or {}
    raw_cmd = data.get('command', '').strip()
    cmd_key = data.get('cmd_key', '')
    session = box.get('session') or data.get('session', '')
    if not session:
        return jsonify({'error': 'No screen session assigned'}), 400
    if not raw_cmd:
        return jsonify({'error': 'No command'}), 400
    final = substitute_vars(raw_cmd, box['variables'])
    ok, err = send_to_screen(session, final)
    if ok and cmd_key and cmd_key not in box['done_cmds']:
        box['done_cmds'].append(cmd_key)
    return jsonify({'status': 'ok', 'sent': final}) if ok else (jsonify({'error': err, 'sent': final}), 500)


@app.route('/api/boxes/<box_id>/done', methods=['POST'])
def api_toggle_done(box_id):
    box = boxes.get(box_id)
    if not box:
        return jsonify({'error': 'Not found'}), 404
    key = (request.json or {}).get('cmd_key', '')
    if key in box['done_cmds']:
        box['done_cmds'].remove(key)
    else:
        box['done_cmds'].append(key)
    return jsonify({'done_cmds': box['done_cmds']})


@app.route('/api/sessions')
def api_sessions():
    return jsonify({'sessions': get_screen_sessions()})


@app.route('/api/sessions', methods=['POST'])
def api_create_session():
    name = (request.json or {}).get('name', '').strip()
    if not name or not re.match(r'^[a-zA-Z0-9_\-]+$', name):
        return jsonify({'error': 'Invalid session name'}), 400
    try:
        subprocess.Popen(['screen', '-dmS', name])
        return jsonify({'status': 'ok', 'name': name})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/vars_schema/<os_type>')
def api_vars_schema(os_type):
    return jsonify({'schema': vars_schema(os_type)})


@app.route('/')
def serve_index():
    idx = BASE_DIR / 'index.html'
    if not idx.exists():
        return f'index.html not found at {idx}', 404
    return idx.read_text(), 200, {'Content-Type': 'text/html; charset=utf-8'}


if __name__ == '__main__':
    print(f'[*] OSCP Commander on http://localhost:50000')
    print(f'[*] Commands dir:  {COMMANDS_DIR}')
    print(f'[*] Cheatsheet:    {CHEATSHEET}')
    threading.Thread(target=git_pull, daemon=True).start()
    app.run(host='0.0.0.0', port=50000, debug=False)
