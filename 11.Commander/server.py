#!/usr/bin/env python3
"""
OSCP Commander — Backend Server
Serves command files, manages screen sessions, handles variable substitution.
"""

import os
import re
import subprocess
import json
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory

# Resolve paths relative to this file, not the working directory
BASE_DIR     = Path(__file__).parent.resolve()
STATIC_DIR   = BASE_DIR / 'static'
COMMANDS_DIR = Path(os.environ.get('COMMANDS_DIR', BASE_DIR / 'commands')).resolve()

app = Flask(__name__, static_folder=str(STATIC_DIR))

# Default variables per session (in-memory only)
session_variables = {}

# Default variable definitions (shown in UI, user fills in values)
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
    """List all active screen sessions."""
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
    """Replace {{VAR}} placeholders with values from variables dict."""
    def replacer(m):
        key = m.group(1)
        return variables.get(key, m.group(0))
    return re.sub(r'\{\{(\w+)\}\}', replacer, command)


def send_to_screen(session, command):
    """Send a command to a named screen session."""
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
    """
    Parse a command file into sections and commands.
    # === HEADING === lines become section headers.
    # comment lines become inline notes above the next command.
    Blank lines separate sections.
    """
    sections = []
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


# ─── API Routes ───────────────────────────────────────────────────────────────

@app.route('/api/commands/<tab>')
def get_commands(tab):
    filename = f"{tab}.txt"
    filepath = COMMANDS_DIR / filename
    if not filepath.exists():
        return jsonify({'error': f'Command file not found: {filename}'}), 404
    try:
        sections = parse_command_file(filepath)
        return jsonify({'tab': tab, 'sections': sections})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/sessions', methods=['GET'])
def get_sessions():
    return jsonify({'sessions': get_screen_sessions()})


@app.route('/api/sessions', methods=['POST'])
def create_session():
    data = request.json
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
    data       = request.json
    session    = data.get('session')
    raw_command= data.get('command')
    variables  = data.get('variables', {})

    if not session:
        return jsonify({'error': 'No session specified'}), 400
    if not raw_command:
        return jsonify({'error': 'No command specified'}), 400

    command = substitute_vars(raw_command, variables)
    ok, err = send_to_screen(session, command)

    if ok:
        return jsonify({'status': 'ok', 'sent': command})
    else:
        return jsonify({'error': err, 'sent': command}), 500


@app.route('/api/variables/<session>', methods=['GET'])
def get_variables(session):
    vars_for_session = session_variables.get(session, {})
    result = []
    for v in DEFAULT_VARS:
        result.append({
            'key':         v['key'],
            'description': v['description'],
            'value':       vars_for_session.get(v['key'], '')
        })
    return jsonify({'variables': result})


@app.route('/api/variables/<session>', methods=['POST'])
def set_variables(session):
    data = request.json
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


# ─── Static Frontend ──────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory(str(STATIC_DIR), 'index.html')


if __name__ == '__main__':
    print(f"[*] OSCP Commander starting on http://localhost:50000")
    print(f"[*] Base directory:     {BASE_DIR}")
    print(f"[*] Static directory:   {STATIC_DIR}")
    print(f"[*] Commands directory: {COMMANDS_DIR}")
    app.run(host='0.0.0.0', port=50000, debug=False)    """List all active screen sessions."""
    try:
        result = subprocess.run(['screen', '-ls'], capture_output=True, text=True)
        sessions = []
        for line in result.stdout.splitlines():
            # Lines like: "\t12345.box1\t(Detached)"
            match = re.search(r'\d+\.(\S+)', line)
            if match:
                sessions.append(match.group(0))  # full "PID.name" form
        return sessions
    except Exception as e:
        return []


def substitute_vars(command, variables):
    """Replace {{VAR}} placeholders with values from variables dict."""
    def replacer(m):
        key = m.group(1)
        return variables.get(key, m.group(0))  # leave unreplaced if not set
    return re.sub(r'\{\{(\w+)\}\}', replacer, command)


def send_to_screen(session, command):
    """Send a command to a named screen session."""
    try:
        # screen -S <session> -X stuff '<command>\n'
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
    """
    Parse a command file into sections and commands.
    Lines starting with # are comments/section headers.
    Blank lines separate sections.
    Returns list of {section, commands[]} dicts.
    """
    sections = []
    current_section = None
    current_commands = []
    current_comment = None

    with open(filepath, 'r') as f:
        lines = f.readlines()

    for line in lines:
        line = line.rstrip('\n')

        if not line.strip():
            # Blank line — flush current section if any
            if current_commands:
                sections.append({
                    'section': current_section or '',
                    'commands': current_commands
                })
                current_commands = []
                current_section = None
                current_comment = None
            continue

        if line.strip().startswith('#'):
            comment = line.strip().lstrip('#').strip()
            # Section headers use === pattern
            if comment.startswith('==='):
                # Flush previous
                if current_commands:
                    sections.append({
                        'section': current_section or '',
                        'commands': current_commands
                    })
                    current_commands = []
                current_section = comment.strip('= ').strip()
                current_comment = None
            else:
                current_comment = comment
        else:
            cmd = line.strip()
            if cmd:
                current_commands.append({
                    'cmd': cmd,
                    'comment': current_comment
                })
                current_comment = None  # comment consumed

    # Flush last section
    if current_commands:
        sections.append({
            'section': current_section or '',
            'commands': current_commands
        })

    return sections


# ─── API Routes ───────────────────────────────────────────────────────────────

@app.route('/api/commands/<tab>')
def get_commands(tab):
    """Return parsed commands for a tab (linux, windows, active_directory, utils)."""
    filename = f"{tab}.txt"
    filepath = COMMANDS_DIR / filename
    if not filepath.exists():
        return jsonify({'error': f'Command file not found: {filename}'}), 404
    try:
        sections = parse_command_file(filepath)
        return jsonify({'tab': tab, 'sections': sections})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/sessions')
def get_sessions():
    """Return list of active screen sessions."""
    sessions = get_screen_sessions()
    return jsonify({'sessions': sessions})


@app.route('/api/run', methods=['POST'])
def run_command():
    """Send a command to a screen session with variable substitution."""
    data = request.json
    session = data.get('session')
    raw_command = data.get('command')
    variables = data.get('variables', {})

    if not session:
        return jsonify({'error': 'No session specified'}), 400
    if not raw_command:
        return jsonify({'error': 'No command specified'}), 400

    command = substitute_vars(raw_command, variables)
    ok, err = send_to_screen(session, command)

    if ok:
        return jsonify({'status': 'ok', 'sent': command})
    else:
        return jsonify({'error': err, 'sent': command}), 500


@app.route('/api/variables/<session>', methods=['GET'])
def get_variables(session):
    """Get variables for a session."""
    vars_for_session = session_variables.get(session, {})
    # Build response with defaults + current values
    result = []
    for v in DEFAULT_VARS:
        result.append({
            'key': v['key'],
            'description': v['description'],
            'value': vars_for_session.get(v['key'], '')
        })
    return jsonify({'variables': result})


@app.route('/api/variables/<session>', methods=['POST'])
def set_variables(session):
    """Set variables for a session."""
    data = request.json
    if session not in session_variables:
        session_variables[session] = {}
    session_variables[session].update(data.get('variables', {}))
    return jsonify({'status': 'ok', 'variables': session_variables[session]})


@app.route('/api/sessions', methods=['POST'])
def create_session():
    """Create a new detached screen session."""
    data = request.json
    name = data.get('name', '').strip()
    if not name or not re.match(r'^[a-zA-Z0-9_\-]+$', name):
        return jsonify({'error': 'Invalid session name'}), 400
    try:
        subprocess.Popen(['screen', '-dmS', name])
        return jsonify({'status': 'ok', 'name': name})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/tabs')
def get_tabs():
    """Return available command tabs based on files present."""
    tabs = []
    tab_meta = [
        {'id': 'linux',           'label': 'Linux',           'icon': '🐧'},
        {'id': 'windows',         'label': 'Windows',         'icon': '🪟'},
        {'id': 'active_directory','label': 'Active Directory','icon': '🏰'},
        {'id': 'utils',           'label': 'Utils',           'icon': '🔧'},
    ]
    for t in tab_meta:
        if (COMMANDS_DIR / f"{t['id']}.txt").exists():
            tabs.append(t)
    return jsonify({'tabs': tabs})


# ─── Static Frontend ──────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')


if __name__ == '__main__':
    print(f"[*] OSCP Commander starting on http://localhost:50000")
    print(f"[*] Commands directory: {COMMANDS_DIR.resolve()}")
    app.run(host='0.0.0.0', port=50000, debug=False)
