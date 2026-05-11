#!/usr/bin/env python3
"""
OSCP Commander - Backend Server
Serves command files, manages screen sessions, handles variable substitution.
"""

import os
import re
import subprocess
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory

# Resolve paths relative to this file, not the working directory
BASE_DIR     = Path(__file__).parent.resolve()
STATIC_DIR   = BASE_DIR / 'static'
COMMANDS_DIR = Path(os.environ.get('COMMANDS_DIR', BASE_DIR / 'commands')).resolve()

app = Flask(__name__, static_folder=str(STATIC_DIR))

# In-memory variable store keyed by session name
session_variables = {}

DEFAULT_VARS = [
    {'key': 'RHOST',       'description': 'Target IP address'},
    {'key': 'LHOST',       'description': 'Kali IP address'},
    {'key': 'LPORT',       'description': 'Listener port'},
    {'key': 'FILENAME',    'description': 'File to transfer'},
    {'key': 'DOMAIN',      'description': 'AD domain name'},
    {'key': 'DOMAIN_USER', 'description': 'Domain username'},
    {'key': 'DC_IP',       'description': 'Domain controller IP'},
    {'key': 'DOMAIN_SID',  'description': 'Domain SID'},
    {'key': 'KRBTGT_HASH', 'description': 'krbtgt NTLM hash'},
]


def get_screen_sessions():
    try:
        result = subprocess.run(['screen', '-ls'], capture_output=True, text=True)
        sessions = []
        for line in result.stdout.splitlines():
            match = re.search(r'\d+\.(\S+)', line)
            if match:
                sessions.append(match.group(0))
        return sessions
    except Exception:
        return []


def substitute_vars(command, variables):
    def replacer(m):
        return variables.get(m.group(1), m.group(0))
    return re.sub(r'\{\{(\w+)\}\}', replacer, command)


def send_to_screen(session, command):
    try:
        result = subprocess.run(
            ['screen', '-S', session, '-X', 'stuff', command + '\n'],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            return False, result.stderr or 'Unknown error'
        return True, None
    except Exception as e:
        return False, str(e)


def parse_command_file(filepath):
    sections         = []
    current_section  = None
    current_commands = []
    current_comment  = None

    with open(filepath, 'r') as f:
        lines = f.readlines()

    for line in lines:
        line = line.rstrip('\n')

        if not line.strip():
            if current_commands:
                sections.append({'section': current_section or '', 'commands': current_commands})
                current_commands = []
                current_section  = None
                current_comment  = None
            continue

        if line.strip().startswith('#'):
            comment = line.strip().lstrip('#').strip()
            if comment.startswith('==='):
                if current_commands:
                    sections.append({'section': current_section or '', 'commands': current_commands})
                    current_commands = []
                current_section = comment.strip('= ').strip()
                current_comment = None
            else:
                current_comment = comment
        else:
            cmd = line.strip()
            if cmd:
                current_commands.append({'cmd': cmd, 'comment': current_comment})
                current_comment = None

    if current_commands:
        sections.append({'section': current_section or '', 'commands': current_commands})

    return sections


# --- API Routes ---------------------------------------------------------------

@app.route('/api/commands/<tab>')
def get_commands(tab):
    filepath = COMMANDS_DIR / f"{tab}.txt"
    if not filepath.exists():
        return jsonify({'error': f'Command file not found: {tab}.txt'}), 404
    try:
        return jsonify({'tab': tab, 'sections': parse_command_file(filepath)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/sessions', methods=['GET'])
def get_sessions():
    return jsonify({'sessions': get_screen_sessions()})


@app.route('/api/sessions', methods=['POST'])
def create_session():
    data = request.json or {}
    name = data.get('name', '').strip()
    if not name or not re.match(r'^[a-zA-Z0-9_\-]+$', name):
        return jsonify({'error': 'Invalid session name'}), 400
    try:
        subprocess.Popen(['screen', '-dmS', name])
        return jsonify({'status': 'ok', 'name': name})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/run', methods=['POST'])
def run_command():
    data        = request.json or {}
    session     = data.get('session')
    raw_command = data.get('command')
    variables   = data.get('variables', {})

    if not session:
        return jsonify({'error': 'No session specified'}), 400
    if not raw_command:
        return jsonify({'error': 'No command specified'}), 400

    command = substitute_vars(raw_command, variables)
    ok, err = send_to_screen(session, command)

    if ok:
        return jsonify({'status': 'ok', 'sent': command})
    return jsonify({'error': err, 'sent': command}), 500


@app.route('/api/variables/<session>', methods=['GET'])
def get_variables(session):
    stored = session_variables.get(session, {})
    result = [
        {'key': v['key'], 'description': v['description'], 'value': stored.get(v['key'], '')}
        for v in DEFAULT_VARS
    ]
    return jsonify({'variables': result})


@app.route('/api/variables/<session>', methods=['POST'])
def set_variables(session):
    data = request.json or {}
    if session not in session_variables:
        session_variables[session] = {}
    session_variables[session].update(data.get('variables', {}))
    return jsonify({'status': 'ok', 'variables': session_variables[session]})


@app.route('/api/tabs')
def get_tabs():
    tab_meta = [
        {'id': 'linux',            'label': 'Linux',           'icon': '🐧'},
        {'id': 'windows',          'label': 'Windows',         'icon': '🪟'},
        {'id': 'active_directory', 'label': 'Active Directory','icon': '🏰'},
        {'id': 'utils',            'label': 'Utils',           'icon': '🔧'},
    ]
    tabs = [t for t in tab_meta if (COMMANDS_DIR / f"{t['id']}.txt").exists()]
    return jsonify({'tabs': tabs})


# --- Static Frontend ----------------------------------------------------------

@app.route('/')
def index():
    return send_from_directory(str(STATIC_DIR), 'index.html')


if __name__ == '__main__':
    print(f"[*] OSCP Commander starting on http://localhost:50000")
    print(f"[*] Base dir:     {BASE_DIR}")
    print(f"[*] Static dir:   {STATIC_DIR}")
    print(f"[*] Commands dir: {COMMANDS_DIR}")
    app.run(host='0.0.0.0', port=50000, debug=False)
