#!/usr/bin/env python3
"""
OSCP Commander - Backend Server
Plan order: recon -> ports -> foothold -> os_enum -> privesc -> ad_enum -> ad_attacks
Utils are OS-specific (utils_linux.txt / utils_windows.txt).
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
EXTRA_VARS = [
    {'key': 'SUBNET',         'desc': 'Target subnet (e.g. 192.168.1)'},
    {'key': 'DATABASE',       'desc': 'Database name'},
    {'key': 'SERVICE',        'desc': 'Service name (sc/systemctl)'},
    {'key': 'SERVICE_PATH',   'desc': 'Service binary path'},
    {'key': 'BINARY',         'desc': 'Binary name for PATH hijack'},
    {'key': 'DLL_NAME',       'desc': 'DLL name for hijacking'},
    {'key': 'IMAGE',          'desc': 'Docker image name'},
    {'key': 'EXPORT',         'desc': 'NFS export path'},
    {'key': 'TARGET_USER',    'desc': 'Target user (ACL abuse)'},
    {'key': 'TARGET_GROUP',   'desc': 'Target group (ACL abuse)'},
    {'key': 'TARGET_HOST',    'desc': 'Lateral movement target host'},
    {'key': 'KERNEL_VERSION', 'desc': 'Kernel version string'},
    {'key': 'SPN_HOST',       'desc': 'SPN hostname'},
    {'key': 'TICKET_FILE',    'desc': 'Kerberos ticket filename'},
]

# ── Port → command file ───────────────────────────────────────────────────────
PORT_FILE_MAP = {
    '21':   ('ftp.txt',     'FTP'),
    '22':   ('ssh.txt',     'SSH'),
    '25':   ('smtp.txt',    'SMTP'),
    '53':   ('dns.txt',     'DNS'),
    '69':   ('ftp.txt',     'TFTP'),
    '80':   ('web.txt',     'HTTP'),
    '88':   ('kerberos.txt','KRB5'),
    '110':  ('smtp.txt',    'POP3'),
    '111':  ('rpc.txt',     'RPC'),
    '135':  ('rpc.txt',     'RPC'),
    '139':  ('smb.txt',     'SMB'),
    '143':  ('smtp.txt',    'IMAP'),
    '161':  ('snmp.txt',    'SNMP'),
    '389':  ('ldap.txt',    'LDAP'),
    '443':  ('web.txt',     'HTTPS'),
    '445':  ('smb.txt',     'SMB'),
    '593':  ('rpc.txt',     'RPC'),
    '636':  ('ldap.txt',    'LDAPS'),
    '993':  ('smtp.txt',    'IMAPS'),
    '1433': ('db.txt',      'MSSQL'),
    '2049': ('nfs.txt',     'NFS'),
    '3268': ('ldap.txt',    'GC'),
    '3269': ('ldap.txt',    'GCS'),
    '3306': ('db.txt',      'MySQL'),
    '3389': ('rdp.txt',     'RDP'),
    '5432': ('db.txt',      'PgSQL'),
    '5433': ('db.txt',      'PgSQL'),
    '5900': ('rdp.txt',     'VNC'),
    '5985': ('winrm.txt',   'WinRM'),
    '5986': ('winrm.txt',   'WinRM'),
    '6379': ('db.txt',      'Redis'),
    '8080': ('web.txt',     'HTTP'),
    '8443': ('web.txt',     'HTTPS'),
}

# ── Foothold: which section headers are triggered by which ports ──────────────
# None = always included regardless of ports
FOOTHOLD_TRIGGERS = {
    'SHELL STABILISATION':  None,
    'REVERSE SHELL':        None,
    'WEB:':                 {'80','443','8080','8443'},
    'SQLI':                 {'80','443','8080','8443','1433','3306','5432'},
    'SMB:':                 {'139','445'},
    'SSH:':                 {'22'},
    'RDP:':                 {'3389'},
    'WINRM:':               {'5985','5986'},
    'MSSQL:':               {'1433'},
    'MYSQL:':               {'3306'},
    'NFS:':                 {'2049'},
    'SNMP:':                {'161'},
    'KERBEROS:':            {'88'},
}

# ── OS plan definition ────────────────────────────────────────────────────────
OS_PLAN = {
    'linux': [
        {'file': 'recon.txt',            'label': 'Recon',      'phase': 'recon'},
        {'file': 'foothold_linux.txt',   'label': 'Foothold',   'phase': 'foothold'},
        {'file': 'linux_enum.txt',       'label': 'Lin Enum',   'phase': 'enum'},
        {'file': 'linux_privesc.txt',    'label': 'PrivEsc',    'phase': 'privesc'},
    ],
    'windows': [
        {'file': 'recon.txt',            'label': 'Recon',      'phase': 'recon'},
        {'file': 'foothold_windows.txt', 'label': 'Foothold',   'phase': 'foothold'},
        {'file': 'windows_enum.txt',     'label': 'Win Enum',   'phase': 'enum'},
        {'file': 'windows_privesc.txt',  'label': 'PrivEsc',    'phase': 'privesc'},
    ],
    'ad': [
        {'file': 'recon.txt',            'label': 'Recon',      'phase': 'recon'},
        {'file': 'foothold_windows.txt', 'label': 'Foothold',   'phase': 'foothold'},
        {'file': 'windows_enum.txt',     'label': 'Win Enum',   'phase': 'enum'},
        {'file': 'windows_privesc.txt',  'label': 'PrivEsc',    'phase': 'privesc'},
        {'file': 'ad_enum.txt',          'label': 'AD Enum',    'phase': 'ad_enum'},
        {'file': 'ad_attacks.txt',       'label': 'AD Atk',     'phase': 'ad_attacks'},
    ],
}

# ── Utils file per OS ─────────────────────────────────────────────────────────
UTILS_FILE = {
    'linux':   'utils_linux.txt',
    'windows': 'utils_windows.txt',
    'ad':      'utils_windows.txt',
}

# ── Command file parser ───────────────────────────────────────────────────────
def parse_command_file(filepath):
    sections         = []
    current_section  = 'General'
    current_commands = []
    current_comment  = None
    try:
        lines = Path(filepath).read_text(errors='replace').splitlines()
    except Exception:
        return []
    for line in lines:
        s = line.strip()
        if not s:
            current_comment = None
            continue
        if s.startswith('#'):
            inner = s.lstrip('#').strip()
            if inner.startswith('===') and inner.endswith('==='):
                if current_commands:
                    sections.append({'section': current_section, 'commands': current_commands})
                    current_commands = []
                current_section = inner.strip('= ').strip()
                current_comment = None
            else:
                current_comment = inner
        else:
            current_commands.append({'cmd': s, 'comment': current_comment})
            current_comment = None
    if current_commands:
        sections.append({'section': current_section, 'commands': current_commands})
    return sections


def read_cmd(filename):
    p = COMMANDS_DIR / filename
    return parse_command_file(p) if p.exists() else []


def filter_foothold(sections, open_ports):
    port_set = set(str(p) for p in open_ports)
    out = []
    for sec in sections:
        heading = sec['section'].upper()
        include = True
        for trigger, ports in FOOTHOLD_TRIGGERS.items():
            if heading.startswith(trigger):
                include = (ports is None) or bool(ports & port_set)
                break
        if include:
            out.append(sec)
    return out


def build_plan(box):
    os_type    = box.get('os', 'linux')
    open_ports = [str(p) for p in box.get('ports', [])]
    plan       = []

    for entry in OS_PLAN.get(os_type, []):
        phase = entry['phase']

        if phase == 'recon':
            # Standard recon sections
            secs = read_cmd(entry['file'])
            # Port-specific sections appended to recon with a divider marker
            seen = set()
            for port in open_ports:
                mapping = PORT_FILE_MAP.get(port)
                if not mapping:
                    continue
                fname, label = mapping
                if fname in seen:
                    continue
                seen.add(fname)
                psecs = read_cmd(fname)
                for ps in psecs:
                    # Tag each section so the frontend can render the divider
                    ps['port_label'] = label
                    secs.append(ps)
            if secs:
                plan.append({'id': 'recon', 'label': 'Recon',
                             'phase': 'recon', 'sections': secs})

        elif phase == 'foothold':
            all_secs = read_cmd(entry['file'])
            filtered = filter_foothold(all_secs, open_ports)
            if filtered:
                plan.append({'id': 'foothold', 'label': 'Foothold',
                             'phase': 'foothold', 'sections': filtered})

        else:
            secs = read_cmd(entry['file'])
            if secs:
                plan.append({'id': phase, 'label': entry['label'],
                             'phase': phase, 'sections': secs})

    return plan


# ── Git sync ──────────────────────────────────────────────────────────────────
def git_pull():
    global git_status
    if not (CHEATSHEET / '.git').exists():
        git_status = {'last_pull': time.strftime('%H:%M:%S'),
                      'changed_files': [], 'new_cmds': [],
                      'error': f'Not a git repo: {CHEATSHEET}'}
        return
    with GIT_LOCK:
        try:
            r = subprocess.run(['git', '-C', str(CHEATSHEET), 'pull', '--ff-only'],
                               capture_output=True, text=True, timeout=15)
            out     = r.stdout + r.stderr
            changed = []
            new_cmds= []
            if 'Already up to date' not in out and r.returncode == 0:
                diff = subprocess.run(
                    ['git', '-C', str(CHEATSHEET), 'diff', '--name-only', 'HEAD@{1}', 'HEAD'],
                    capture_output=True, text=True)
                changed = [f.strip() for f in diff.stdout.splitlines() if f.strip()]
                new_cmds = [{'file': f} for f in changed if f.endswith('.txt')]
            git_status = {'last_pull': time.strftime('%H:%M:%S'),
                          'changed_files': changed, 'new_cmds': new_cmds,
                          'error': None if r.returncode == 0 else out.strip()}
        except Exception as e:
            git_status = {'last_pull': time.strftime('%H:%M:%S'),
                          'changed_files': [], 'new_cmds': [], 'error': str(e)}


# ── Screen helpers ────────────────────────────────────────────────────────────
def get_screen_sessions():
    try:
        r = subprocess.run(['screen', '-ls'], capture_output=True, text=True)
        sessions = []
        for line in r.stdout.splitlines():
            # Only match genuine session lines: PID.name (timestamp) (Detached|Attached)
            m = re.search(r'(\d+\.\S+)\s+\([^)]+\)\s+\((Detached|Attached)\)', line)
            if m:
                sessions.append(m.group(1))
        return sessions
    except Exception:
        return []


def send_to_screen(session, command):
    try:
        r = subprocess.run(
            ['screen', '-S', session, '-X', 'stuff', command + '\n'],
            capture_output=True, text=True)
        return r.returncode == 0, r.stderr
    except Exception as e:
        return False, str(e)


def substitute_vars(cmd, variables):
    return re.sub(r'\{\{(\w+)\}\}',
                  lambda m: variables.get(m.group(1), m.group(0)), cmd)


def default_variables(os_type):
    schema = COMMON_VARS + (AD_VARS if os_type == 'ad' else [])
    return {v['key']: '' for v in schema}


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
        box_id = f'{box_id}_{len(boxes)}'
    boxes[box_id] = {
        'id': box_id, 'name': name, 'os': os_type,
        'session': session, 'ports': [],
        'variables': default_variables(os_type),
        'done_cmds': [], 'nmap_raw': '',
        'custom_vars': {}, 'active_extras': [],
    }
    return jsonify({'box': boxes[box_id]})


@app.route('/api/boxes/<box_id>')
def api_get_box(box_id):
    box = boxes.get(box_id)
    return jsonify({'box': box}) if box else (jsonify({'error': 'Not found'}), 404)


@app.route('/api/boxes/<box_id>', methods=['PATCH'])
def api_update_box(box_id):
    box = boxes.get(box_id)
    if not box:
        return jsonify({'error': 'Not found'}), 404
    data = request.json or {}
    for f in ('name', 'os', 'session', 'nmap_raw', 'ports', 'done_cmds', 'active_extras'):
        if f in data:
            box[f] = data[f]
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
    text = (request.json or {}).get('nmap', '')
    existing = set(str(p) for p in box['ports'])
    for p in parse_nmap_output(text):
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
    session = box.get('session', '')
    if not session:
        return jsonify({'error': 'No screen session assigned to this box'}), 400
    if not raw_cmd:
        return jsonify({'error': 'No command'}), 400
    all_vars = {**box['variables'], **box.get('custom_vars', {})}
    final    = substitute_vars(raw_cmd, all_vars)
    ok, err  = send_to_screen(session, final)
    if ok and cmd_key and cmd_key not in box['done_cmds']:
        box['done_cmds'].append(cmd_key)
    return (jsonify({'status': 'ok', 'sent': final}) if ok
            else (jsonify({'error': err, 'sent': final}), 500))


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
    schema = COMMON_VARS + (AD_VARS if os_type == 'ad' else [])
    return jsonify({'schema': schema, 'extra_vars': EXTRA_VARS})


@app.route('/api/utils/<os_type>')
def api_utils(os_type):
    fname = UTILS_FILE.get(os_type, 'utils_linux.txt')
    return jsonify({'sections': read_cmd(fname), 'file': fname})


@app.route('/')
def serve_index():
    idx = BASE_DIR / 'index.html'
    if not idx.exists():
        return f'index.html not found at {idx}', 404
    return idx.read_text(), 200, {'Content-Type': 'text/html; charset=utf-8'}


if __name__ == '__main__':
    print(f'[*] OSCP Commander -> http://localhost:50000')
    print(f'[*] Commands dir:  {COMMANDS_DIR}')
    print(f'[*] Cheatsheet:    {CHEATSHEET}')
    threading.Thread(target=git_pull, daemon=True).start()
    app.run(host='127.0.0.1', port=50000, debug=False)
    
