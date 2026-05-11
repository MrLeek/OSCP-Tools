#!/usr/bin/env python3
"""
OSCP Commander — Backend Server
Single-folder deployment. All files live alongside this script.
"""

import os
import re
import subprocess
import json
import threading
import time
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory, Response
from flask_cors import CORS

BASE_DIR      = Path(__file__).parent.resolve()
CHEATSHEET    = Path(os.environ.get('CHEATSHEET_DIR', Path.home() / 'OSCP-CheatSheet')).resolve()
GIT_LOCK      = threading.Lock()

app = Flask(__name__, static_folder=None)
CORS(app)

# ── In-memory state (resets on server restart — by design) ───────────────────
boxes       = {}   # box_id -> { name, os, session, ports, variables, done_cmds }
git_status  = {'last_pull': None, 'changed_files': [], 'new_cmds': [], 'error': None}

# ── Variable defaults per OS ──────────────────────────────────────────────────
COMMON_VARS = [
    {'key': 'TARGET',      'desc': 'Target IP address'},
    {'key': 'KALI',        'desc': 'Kali IP address'},
    {'key': 'KALI_PORT',   'desc': 'Listener / HTTP server port'},
    {'key': 'FILENAME',    'desc': 'File to transfer'},
    {'key': 'USER',        'desc': 'Username on target'},
    {'key': 'PASS',        'desc': 'Password on target'},
]
AD_VARS = [
    {'key': 'DOMAIN',      'desc': 'AD domain name (e.g. corp.com)'},
    {'key': 'DOMAIN_USER', 'desc': 'Domain username'},
    {'key': 'DC_IP',       'desc': 'Domain controller IP'},
    {'key': 'DOMAIN_SID',  'desc': 'Domain SID'},
    {'key': 'KRBTGT_HASH', 'desc': 'krbtgt NTLM hash (post-root)'},
]

# ── Port → cheatsheet section mapping ─────────────────────────────────────────
PORT_MAP = {
    '21':        {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '21: FTP'},
    '22':        {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '22: SSH'},
    '23':        {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '23: Telnet'},
    '25':        {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '25: SMTP'},
    '53':        {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '53: DNS'},
    '69':        {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '69: TFTP'},
    '80':        {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '80/443: HTTP(S)'},
    '88':        {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '88: Kerberos'},
    '110':       {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '110: POP3'},
    '111':       {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '111: RPC / Portmapper'},
    '135':       {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '135, 593: MSRPC'},
    '139':       {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '139, 445: SMB'},
    '143':       {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '143, 993: IMAP'},
    '161':       {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '161 (UDP): SNMP'},
    '389':       {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '389, 636, 3268, 3269: LDAP'},
    '443':       {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '80/443: HTTP(S)'},
    '445':       {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '139, 445: SMB'},
    '593':       {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '135, 593: MSRPC'},
    '636':       {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '389, 636, 3268, 3269: LDAP'},
    '993':       {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '143, 993: IMAP'},
    '1433':      {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '1433: MSSQL'},
    '2049':      {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '2049: NFS'},
    '3268':      {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '389, 636, 3268, 3269: LDAP'},
    '3269':      {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '389, 636, 3268, 3269: LDAP'},
    '3306':      {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '3306: MySQL'},
    '3389':      {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '3389: RDP'},
    '5432':      {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '5432, 5433: PostgreSQL'},
    '5433':      {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '5432, 5433: PostgreSQL'},
    '5900':      {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '5900: VNC'},
    '5985':      {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '5985, 5986: WinRM'},
    '5986':      {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '5985, 5986: WinRM'},
    '6379':      {'file': '01.info_gathering/Specific_Port_Services.md', 'heading': '6379: Redis'},
}

OS_PLAN = {
    'linux': [
        {'file': '07.Linux/linux_enumeration.md',                  'heading': None, 'label': 'Linux Enumeration'},
        {'file': '07.Linux/Linux_Privilege_Escalation_Playbook.md','heading': None, 'label': 'Linux PrivEsc'},
    ],
    'windows': [
        {'file': '06.Windows/Basic_Enumeration.md',                'heading': None, 'label': 'Windows Enumeration'},
        {'file': '06.Windows/Windows_Privilege_Escalation.md',     'heading': None, 'label': 'Windows PrivEsc'},
    ],
    'ad': [
        {'file': '06.Windows/Basic_Enumeration.md',                'heading': None, 'label': 'Windows Enumeration'},
        {'file': '06.Windows/Windows_Privilege_Escalation.md',     'heading': None, 'label': 'Windows PrivEsc'},
        {'file': '09.Active_Directory/Active_Directory_Enumeration.md', 'heading': None, 'label': 'AD Enumeration'},
        {'file': '09.Active_Directory/Active_Directory_Attacks.md','heading': None, 'label': 'AD Attacks & Post-Root'},
    ],
}

# ── Markdown parser ────────────────────────────────────────────────────────────
VAR_SUBS = [
    (r'<ip>',           '{{TARGET}}'),
    (r'<kali_ip>',      '{{KALI}}'),
    (r'<kali_ip>',      '{{KALI}}'),
    (r'KALI_IP',        '{{KALI}}'),
    (r'<port>',         '{{KALI_PORT}}'),
    (r'<kali_port>',    '{{KALI_PORT}}'),
    (r'KALI_PORT',      '{{KALI_PORT}}'),
    (r'<user>',         '{{USER}}'),
    (r'<username>',     '{{USER}}'),
    (r'<pass>',         '{{PASS}}'),
    (r'<password>',     '{{PASS}}'),
    (r'<domain>',       '{{DOMAIN}}'),
    (r'<dc_ip>',        '{{DC_IP}}'),
    (r'\[IP_ADDR\]',    '{{DC_IP}}'),
    (r'\[attacker_ip\]','{{KALI}}'),
]

def apply_var_subs(cmd):
    for pattern, replacement in VAR_SUBS:
        cmd = re.sub(pattern, replacement, cmd, flags=re.IGNORECASE)
    return cmd

def extract_code_blocks(md_text, heading_filter=None):
    """
    Extract fenced code blocks from markdown.
    If heading_filter is set, only extract blocks under that heading.
    Returns list of {lang, code, context} dicts.
    """
    blocks = []
    lines  = md_text.splitlines()
    current_heading = None
    in_target       = heading_filter is None
    in_fence        = False
    fence_lang      = ''
    fence_lines     = []
    context_comment = None

    i = 0
    while i < len(lines):
        line = lines[i]

        # Track headings
        h = re.match(r'^#{1,4}\s+(.+)', line)
        if h and not in_fence:
            current_heading = h.group(1).strip()
            if heading_filter:
                in_target = current_heading.startswith(heading_filter.split(':')[0].strip())
            i += 1
            continue

        if not in_target:
            i += 1
            continue

        # Inline comment context (bold lines, > blockquotes before code)
        if not in_fence:
            stripped = line.strip()
            if stripped.startswith('>') or stripped.startswith('**') or stripped.startswith('*'):
                context_comment = stripped.lstrip('>#* ').rstrip('*')

        # Fence open
        if re.match(r'^```', line) and not in_fence:
            fence_lang  = line.strip().lstrip('`').strip()
            fence_lines = []
            in_fence    = True
            i += 1
            continue

        # Fence close
        if re.match(r'^```', line) and in_fence:
            in_fence = False
            code = '\n'.join(fence_lines).strip()
            if code:
                blocks.append({
                    'lang':    fence_lang or 'bash',
                    'code':    code,
                    'context': context_comment,
                    'heading': current_heading or '',
                })
            context_comment = None
            fence_lines = []
            i += 1
            continue

        if in_fence:
            fence_lines.append(line)
        i += 1

    return blocks


def blocks_to_commands(blocks):
    """
    Convert code blocks into flat command list.
    Each command gets its own entry with comment context.
    """
    cmds = []
    for block in blocks:
        raw_lines = block['code'].splitlines()
        current_comment = block['context']
        for line in raw_lines:
            stripped = line.strip()
            if not stripped:
                continue
            # Comment line inside code block
            if stripped.startswith('#') or stripped.startswith('rem ') or stripped.startswith('--'):
                current_comment = stripped.lstrip('#-rem ').strip()
                continue
            cmd = apply_var_subs(stripped)
            cmds.append({
                'cmd':     cmd,
                'comment': current_comment,
                'heading': block['heading'],
                'lang':    block['lang'],
            })
            current_comment = None
    return cmds


def read_md_section(rel_path, heading_filter=None):
    """Read a markdown file from the cheatsheet and extract commands."""
    full_path = CHEATSHEET / rel_path
    if not full_path.exists():
        return []
    text   = full_path.read_text(errors='replace')
    blocks = extract_code_blocks(text, heading_filter)
    return blocks_to_commands(blocks)


def parse_nmap(nmap_text):
    """Extract open port numbers from nmap output."""
    ports = set()
    for line in nmap_text.splitlines():
        m = re.match(r'\s*(\d+)/(tcp|udp)\s+open', line, re.IGNORECASE)
        if m:
            ports.add(m.group(1))
    return sorted(ports, key=int)

# ── Git sync ──────────────────────────────────────────────────────────────────
def git_pull():
    """Run git pull on the cheatsheet repo and record changed files."""
    global git_status
    if not (CHEATSHEET / '.git').exists():
        git_status['error'] = f'Not a git repo: {CHEATSHEET}'
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

            if 'Already up to date' not in output:
                # Get list of changed files
                diff = subprocess.run(
                    ['git', '-C', str(CHEATSHEET), 'diff', '--name-only', 'HEAD@{1}', 'HEAD'],
                    capture_output=True, text=True
                )
                changed = [f.strip() for f in diff.stdout.splitlines() if f.strip().endswith('.md')]

                # For each changed md file, extract commands and flag as new
                for f in changed:
                    cmds = read_md_section(f)
                    for c in cmds:
                        new_cmds.append({'file': f, 'cmd': c['cmd'], 'comment': c['comment']})

            git_status = {
                'last_pull':    time.strftime('%H:%M:%S'),
                'changed_files': changed,
                'new_cmds':     new_cmds,
                'error':        None if result.returncode == 0 else output.strip(),
            }
        except Exception as e:
            git_status['error'] = str(e)
            git_status['last_pull'] = time.strftime('%H:%M:%S')


# ── Screen helpers ────────────────────────────────────────────────────────────
def get_screen_sessions():
    try:
        r = subprocess.run(['screen', '-ls'], capture_output=True, text=True)
        sessions = []
        for line in r.stdout.splitlines():
            m = re.search(r'(\d+\.\S+)', line)
            if m:
                sessions.append(m.group(1))
        return sessions
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
    def rep(m):
        return variables.get(m.group(1), m.group(0))
    return re.sub(r'\{\{(\w+)\}\}', rep, cmd)

# ── Box helpers ───────────────────────────────────────────────────────────────
def default_variables(os_type):
    vars_list = COMMON_VARS[:]
    if os_type == 'ad':
        vars_list += AD_VARS
    return {v['key']: '' for v in vars_list}

def vars_schema(os_type):
    schema = COMMON_VARS[:]
    if os_type == 'ad':
        schema += AD_VARS
    return schema

def build_plan(box):
    """
    Build the full plan for a box as a list of sections:
    [{ id, label, source, commands: [{cmd, comment, lang}] }]
    """
    os_type = box.get('os', 'linux')
    ports   = box.get('ports', [])
    plan    = []

    # OS-based sections
    for entry in OS_PLAN.get(os_type, []):
        cmds = read_md_section(entry['file'], entry.get('heading'))
        if cmds:
            plan.append({
                'id':       entry['label'].lower().replace(' ', '_'),
                'label':    entry['label'],
                'source':   entry['file'],
                'commands': cmds,
            })

    # Port-based sections — deduplicate headings already added
    seen_headings = set()
    for port in ports:
        port = str(port)
        mapping = PORT_MAP.get(port)
        if not mapping:
            continue
        key = mapping['heading']
        if key in seen_headings:
            continue
        seen_headings.add(key)
        cmds = read_md_section(mapping['file'], mapping['heading'])
        if cmds:
            plan.append({
                'id':       f"port_{port}",
                'label':    mapping['heading'],
                'source':   mapping['file'],
                'commands': cmds,
            })

    return plan

# ── API ───────────────────────────────────────────────────────────────────────

@app.route('/api/init', methods=['GET'])
def api_init():
    """Called on page load — triggers git pull, returns current state."""
    threading.Thread(target=git_pull, daemon=True).start()
    return jsonify({'boxes': list(boxes.values()), 'git': git_status})


@app.route('/api/git', methods=['GET'])
def api_git():
    return jsonify(git_status)


@app.route('/api/git/pull', methods=['POST'])
def api_git_pull():
    git_pull()
    return jsonify(git_status)


@app.route('/api/boxes', methods=['GET'])
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
    if not box:
        return jsonify({'error': 'Box not found'}), 404
    return jsonify({'box': box})


@app.route('/api/boxes/<box_id>', methods=['PATCH'])
def api_update_box(box_id):
    box = boxes.get(box_id)
    if not box:
        return jsonify({'error': 'Box not found'}), 404
    data = request.json or {}
    for field in ('name', 'os', 'session', 'nmap_raw'):
        if field in data:
            box[field] = data[field]
    if 'variables' in data:
        box['variables'].update(data['variables'])
    if 'ports' in data:
        box['ports'] = data['ports']
    if 'done_cmds' in data:
        box['done_cmds'] = data['done_cmds']
    return jsonify({'box': box})


@app.route('/api/boxes/<box_id>/nmap', methods=['POST'])
def api_parse_nmap(box_id):
    box = boxes.get(box_id)
    if not box:
        return jsonify({'error': 'Box not found'}), 404
    nmap_text = (request.json or {}).get('nmap', '')
    ports     = parse_nmap(nmap_text)
    box['nmap_raw'] = nmap_text
    # Merge with any manually added ports
    existing  = set(str(p) for p in box['ports'])
    for p in ports:
        existing.add(str(p))
    box['ports'] = sorted(existing, key=lambda x: int(x))
    return jsonify({'ports': box['ports']})


@app.route('/api/boxes/<box_id>/plan', methods=['GET'])
def api_plan(box_id):
    box = boxes.get(box_id)
    if not box:
        return jsonify({'error': 'Box not found'}), 404
    plan = build_plan(box)
    return jsonify({'plan': plan, 'done_cmds': box['done_cmds']})


@app.route('/api/boxes/<box_id>/run', methods=['POST'])
def api_run(box_id):
    box = boxes.get(box_id)
    if not box:
        return jsonify({'error': 'Box not found'}), 404

    data    = request.json or {}
    raw_cmd = data.get('command', '').strip()
    cmd_key = data.get('cmd_key', '')
    session = box.get('session') or data.get('session', '')

    if not session:
        return jsonify({'error': 'No screen session assigned to this box'}), 400
    if not raw_cmd:
        return jsonify({'error': 'No command'}), 400

    final_cmd = substitute_vars(raw_cmd, box['variables'])
    ok, err   = send_to_screen(session, final_cmd)

    if ok and cmd_key and cmd_key not in box['done_cmds']:
        box['done_cmds'].append(cmd_key)

    if ok:
        return jsonify({'status': 'ok', 'sent': final_cmd})
    return jsonify({'error': err, 'sent': final_cmd}), 500


@app.route('/api/boxes/<box_id>/done', methods=['POST'])
def api_toggle_done(box_id):
    box = boxes.get(box_id)
    if not box:
        return jsonify({'error': 'Box not found'}), 404
    cmd_key = (request.json or {}).get('cmd_key', '')
    if cmd_key in box['done_cmds']:
        box['done_cmds'].remove(cmd_key)
    else:
        box['done_cmds'].append(cmd_key)
    return jsonify({'done_cmds': box['done_cmds']})


@app.route('/api/sessions', methods=['GET'])
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


@app.route('/api/vars_schema/<os_type>', methods=['GET'])
def api_vars_schema(os_type):
    return jsonify({'schema': vars_schema(os_type)})


# ── Static serving — everything from BASE_DIR ─────────────────────────────────
@app.route('/')
def serve_index():
    idx = BASE_DIR / 'index.html'
    if not idx.exists():
        return f'index.html not found at {idx}', 404
    return idx.read_text(), 200, {'Content-Type': 'text/html; charset=utf-8'}


if __name__ == '__main__':
    print(f'[*] OSCP Commander on http://localhost:50000')
    print(f'[*] Script dir:    {BASE_DIR}')
    print(f'[*] Cheatsheet:    {CHEATSHEET}')
    # Kick off initial git pull in background
    threading.Thread(target=git_pull, daemon=True).start()
    app.run(host='0.0.0.0', port=50000, debug=False)
