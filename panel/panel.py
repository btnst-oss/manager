#!/usr/bin/env python3
"""
MJERUMANI CYBER web control panel backend.

Paths, service names and the users database format match menu.sh.
Run by systemd (mjerumanicyber-panel.service). The same file is also run by
an `at` job for trial cleanup:  panel.py --cleanup-trial <username>
"""
import glob
import hashlib
import hmac
import json
import math
import os
import pwd
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

# ---------------------------------------------------------------------
# Paths and constants (must match menu.sh)
# ---------------------------------------------------------------------
DB_DIR = "/etc/mjerumanicyber"
DB_FILE = f"{DB_DIR}/users.db"
RESELLERS_DB = f"{DB_DIR}/resellers.db"
BW_DIR = f"{DB_DIR}/bandwidth"
BANNER_DIR = f"{DB_DIR}/banners"
BANNERS_FLAG = f"{DB_DIR}/banners_enabled"
SSHD_MAIN_CONFIG = "/etc/ssh/sshd_config"
SSHD_FF_CONFIG = "/etc/ssh/sshd_config.d/mjerumanicyber.conf"
PANEL_CONF = f"{DB_DIR}/panel.conf"
PANEL_DIR = f"{DB_DIR}/panel"
PANEL_HTML = f"{PANEL_DIR}/index.html"
PANEL_LOGO = f"{PANEL_DIR}/logo.png"
SESSION_FILE = f"{DB_DIR}/sessions.json"
PANEL_SCRIPT = os.path.abspath(__file__)
FF_USERS_GROUP = "ffusers"
PORT = int(os.environ.get("PANEL_PORT", "44380"))
MAX_BODY_BYTES = 3 * 1024 * 1024
SESSION_TTL = 86400
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
DEFAULT_BRAND = "MJERUMANI CYBER"
DEFAULT_LOGO = "🦅"

VALID_USER = re.compile(r"^[A-Za-z0-9._-]{1,32}$")   # names accepted in URLs
CREATE_USER = re.compile(r"^[A-Za-z0-9_]{3,32}$")     # names the panel may create
SECRET_RE = re.compile(r"^[A-Za-z0-9_-]{3,64}$")
NUMBER_RE = re.compile(r"^\d+(\.\d+)?$")

sessions = {}                  # token -> {"username", "role", "created_at"}
session_lock = threading.Lock()
db_lock = threading.Lock()


def log(msg):
    print(msg, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------
def load_sessions():
    global sessions
    try:
        with open(SESSION_FILE, "r") as f:
            data = json.load(f)
        if isinstance(data, dict):
            sessions = data
    except Exception:
        sessions = {}


def save_sessions():
    try:
        os.makedirs(DB_DIR, exist_ok=True)
        tmp = SESSION_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(sessions, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, SESSION_FILE)
    except Exception as e:
        log(f"Could not save sessions: {e}")


def cleanup_sessions():
    now = time.time()
    with session_lock:
        expired = [t for t, s in sessions.items() if now - s.get("created_at", 0) > SESSION_TTL]
        for t in expired:
            del sessions[t]
        if expired:
            save_sessions()


def drop_sessions_for(username, role):
    with session_lock:
        tokens = [t for t, s in sessions.items()
                  if s.get("username") == username and s.get("role") == role]
        for t in tokens:
            del sessions[t]
        if tokens:
            save_sessions()


# ---------------------------------------------------------------------
# Shell helpers (argument lists only, never shell strings)
# ---------------------------------------------------------------------
def run_cmd(args, ignore_errors=False, input_text=None, timeout=15):
    try:
        res = subprocess.run(args, capture_output=True, text=True,
                             input=input_text, timeout=timeout)
        if not ignore_errors and res.returncode != 0:
            log(f"Command failed {args}: {res.stderr.strip()}")
        return res.returncode, res.stdout.strip(), res.stderr.strip()
    except Exception as e:
        log(f"Could not run {args}: {e}")
        return -1, "", str(e)


def set_linux_password(username, password):
    code, _, _ = run_cmd(["chpasswd"], input_text=f"{username}:{password}\n")
    return code == 0


def linux_user_exists(username):
    try:
        pwd.getpwnam(username)
        return True
    except KeyError:
        return False


def force_delete_system_user(username):
    """Kill a managed user's processes and delete the account. System accounts are never touched."""
    try:
        if pwd.getpwnam(username).pw_uid < 1000:
            log(f"Refusing to delete system account {username}")
            return
    except KeyError:
        return
    run_cmd(["pkill", "-9", "-u", username], ignore_errors=True)
    time.sleep(0.5)
    code, _, _ = run_cmd(["userdel", "-rf", username], ignore_errors=True)
    if code != 0:
        run_cmd(["pkill", "-9", "-u", username], ignore_errors=True)
        time.sleep(1)
        run_cmd(["userdel", "-rf", username], ignore_errors=True)


def kill_user_sessions(username):
    run_cmd(["pkill", "-9", "-u", username], ignore_errors=True)


def _remove_path(path):
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path, ignore_errors=True)
        elif os.path.lexists(path):
            os.remove(path)
    except OSError:
        pass


def remove_user_artifacts(username):
    for suffix in (".usage", ".daily_usage", ".conn_locked", ".daily_locked"):
        _remove_path(os.path.join(BW_DIR, username + suffix))
    for f in glob.glob(os.path.join(BW_DIR, "pidtrack", glob.escape(username) + "__*.last")):
        _remove_path(f)
    _remove_path(os.path.join(BW_DIR, "pidtrack", username))
    _remove_path(os.path.join(BANNER_DIR, username + ".txt"))


def reset_bandwidth_counters(username):
    os.makedirs(BW_DIR, exist_ok=True)
    for suffix in (".usage", ".daily_usage"):
        with open(os.path.join(BW_DIR, username + suffix), "w") as f:
            f.write("0")
    for suffix in (".conn_locked", ".daily_locked"):
        _remove_path(os.path.join(BW_DIR, username + suffix))


def read_text(path):
    try:
        with open(path, "r") as f:
            return f.read()
    except OSError:
        return ""


def read_file_int(path):
    try:
        return int(read_text(path).strip())
    except ValueError:
        return 0


def system_locked_users():
    """Accounts whose shadow hash starts with '!' are locked (what usermod -L does)."""
    locked = set()
    for line in read_text("/etc/shadow").splitlines():
        parts = line.split(":")
        if len(parts) > 1 and parts[1].startswith("!"):
            locked.add(parts[0])
    return locked


def get_ssh_session_counts(names):
    """Live SSH sessions per managed user, using the same process owner check as menu.sh's limiter."""
    code, out, _ = run_cmd(["ps", "-C", "sshd,sshd-session", "-o", "pid=,user="], ignore_errors=True)
    counts = {}
    if code != 0 or not out:
        return counts
    pids = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] in names:
            pids.setdefault(parts[1], set()).add(parts[0])
    return {k: len(v) for k, v in pids.items()}


# ---------------------------------------------------------------------
# Users database (format shared with menu.sh)
#   user:password:expire(YYYY-MM-DD|Never):conn_limit:bandwidth_gb:daily_gb:type:owner
# ---------------------------------------------------------------------
def _to_float(text, default=0.0):
    try:
        return float(text)
    except (TypeError, ValueError):
        return default


def parse_db_line(line):
    parts = line.strip().split(":")
    if len(parts) < 5 or not parts[0]:
        return None
    user = {
        "username": parts[0],
        "password": parts[1],
        "expire_date": parts[2],
        "conn_limit": int(parts[3]) if parts[3].isdigit() else 1,
        "bandwidth_gb": _to_float(parts[4]),
        "daily_bandwidth_gb": 0.0,
        "account_type": "",
        "owner": "admin",
    }
    if len(parts) > 5:
        if NUMBER_RE.match(parts[5]):
            user["daily_bandwidth_gb"] = _to_float(parts[5])
        elif parts[5]:
            user["account_type"] = parts[5]        # menu.sh 6-field trial rows
    if len(parts) > 6 and parts[6]:
        user["account_type"] = parts[6]
    if len(parts) > 7 and parts[7]:
        user["owner"] = parts[7]
    return user


def read_db():
    users = []
    for line in read_text(DB_FILE).splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        u = parse_db_line(line)
        if u:
            users.append(u)
    return users


def _fmt_gb(v):
    f = float(v)
    return str(int(f)) if f == int(f) else str(f)


def format_db_line(u):
    return (f"{u['username']}:{u['password']}:{u['expire_date']}:{u['conn_limit']}:"
            f"{_fmt_gb(u.get('bandwidth_gb', 0))}:{_fmt_gb(u.get('daily_bandwidth_gb', 0))}:"
            f"{u.get('account_type') or 'web'}:{u.get('owner') or 'admin'}\n")


def write_db(users):
    os.makedirs(DB_DIR, exist_ok=True)
    tmp = DB_FILE + ".tmp"
    with open(tmp, "w") as f:
        for u in users:
            f.write(format_db_line(u))
    os.replace(tmp, DB_FILE)


def find_db_user(username):
    return next((u for u in read_db() if u["username"] == username), None)


def append_db_user(u):
    os.makedirs(DB_DIR, exist_ok=True)
    with open(DB_FILE, "a") as f:
        f.write(format_db_line(u))


# ---------------------------------------------------------------------
# Resellers database (panel only)
# ---------------------------------------------------------------------
def read_resellers():
    resellers = []
    for line in read_text(RESELLERS_DB).splitlines():
        parts = line.strip().split(":")
        if not line.strip() or line.startswith("#") or len(parts) < 5:
            continue
        resellers.append({
            "username": parts[0],
            "password": parts[1],
            "expire_date": parts[2],
            "max_users": int(parts[3]) if parts[3].isdigit() else 10,
            "enabled": parts[4] == "1",
        })
    return resellers


def write_resellers(resellers):
    os.makedirs(DB_DIR, exist_ok=True)
    tmp = RESELLERS_DB + ".tmp"
    with open(tmp, "w") as f:
        for r in resellers:
            enabled = "1" if r.get("enabled", True) else "0"
            f.write(f"{r['username']}:{r['password']}:{r['expire_date']}:{r['max_users']}:{enabled}\n")
    os.replace(tmp, RESELLERS_DB)


def calculate_expire_date(days):
    return (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d")


def is_past_date(date_text):
    try:
        return datetime.strptime(date_text, "%Y-%m-%d") < datetime.now()
    except (ValueError, TypeError):
        return False


def generate_password(length=8):
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(secrets.choice(chars) for _ in range(length))


# ---------------------------------------------------------------------
# Panel credentials. panel.conf is also `source`d by menu.sh, so every
# value is written in double quotes with $, `, " and \ escaped.
# ---------------------------------------------------------------------
PANEL_KEYS = ("PANEL_USER", "PANEL_PASS_HASH", "PANEL_PASS_PLAIN",
              "PANEL_SECRET", "PANEL_NAME", "PANEL_LOGO")


def _quote(value):
    value = str(value)
    value = value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("`", "\\`")
    return f'"{value}"'


def _unquote(raw):
    v = raw.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        inner = v[1:-1]
        if v[0] == "'":
            return inner
        out, i = [], 0
        while i < len(inner):
            if inner[i] == "\\" and i + 1 < len(inner) and inner[i + 1] in '\\"$`':
                out.append(inner[i + 1])
                i += 2
            else:
                out.append(inner[i])
                i += 1
        return "".join(out)
    return v


def get_panel_creds():
    creds = {"PANEL_USER": "", "PANEL_PASS_HASH": "", "PANEL_PASS_PLAIN": "",
             "PANEL_SECRET": "", "PANEL_NAME": DEFAULT_BRAND, "PANEL_LOGO": DEFAULT_LOGO}
    for raw in read_text(PANEL_CONF).splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key in creds:
            creds[key] = _unquote(value)
    return creds


def save_panel_creds(creds):
    os.makedirs(DB_DIR, exist_ok=True)
    tmp = PANEL_CONF + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        for key in PANEL_KEYS:
            f.write(f"{key}={_quote(creds.get(key, ''))}\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, PANEL_CONF)


def panel_secret(creds=None):
    creds = creds or get_panel_creds()
    return creds.get("PANEL_SECRET", "").strip().strip("/")


def has_custom_logo(creds):
    return os.path.exists(PANEL_LOGO) and creds.get("PANEL_LOGO") == "custom"


def sha256_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------
# Protocols (service names and files created by menu.sh)
# ---------------------------------------------------------------------
PROTOCOLS = [
    {"name": "BadVPN (UDPGW)", "service": "badvpn", "all": False,
     "services": ["badvpn.service"],
     "check_files": ["/etc/systemd/system/badvpn.service"], "port": "7300"},
    {"name": "UDP Custom", "service": "udp-custom", "all": False,
     "services": ["udp-custom.service", "udpgw.service"],
     "check_files": ["/etc/systemd/system/udp-custom.service"], "port": "36712"},
    {"name": "WebSocket", "service": "mjerumanicyber-ws-backend", "all": True,
     "services": ["mjerumanicyber-ws-backend.service", "mjerumanicyber-ws-stunnel.service",
                  "mjerumanicyber-ws-http.service", "mjerumanicyber-ws-tls.service"],
     "check_files": ["/etc/systemd/system/mjerumanicyber-ws-http.service",
                     "/etc/systemd/system/mjerumanicyber-ws-tls.service"], "port": "80/443"},
    {"name": "SlowDNS (MJERUMANI CYBER)", "service": "server-sldns", "all": True,
     "services": ["server-sldns.service", "edns-proxy.service"],
     "check_files": ["/etc/systemd/system/server-sldns.service",
                     "/etc/systemd/system/edns-proxy.service",
                     f"{DB_DIR}/slowdns-amkhn"], "port": "53"},
    {"name": "ZiVPN", "service": "zivpn", "all": False,
     "services": ["zivpn.service"],
     "check_files": ["/etc/systemd/system/zivpn.service"], "port": "5667"},
    {"name": "X-UI Panel", "service": "x-ui", "all": False,
     "services": ["x-ui.service"],
     "check_files": ["/etc/systemd/system/x-ui.service"], "port": "2053"},
]


def get_protocols_status():
    result = []
    for p in PROTOCOLS:
        installed = any(os.path.exists(path) for path in p["check_files"])
        states = []
        for svc in p["services"]:
            code, out, _ = run_cmd(["systemctl", "is-active", svc], ignore_errors=True)
            active = code == 0 and out == "active"
            states.append(active)
            if active:
                installed = True
            _, load, _ = run_cmd(["systemctl", "show", "-p", "LoadState", "--value", svc], ignore_errors=True)
            if load == "loaded":
                installed = True
        running = all(states) if p["all"] else any(states)
        result.append({
            "name": p["name"],
            "service": p["service"],
            "installed": installed,
            "running": running,
            "status": "Active" if running else ("Installed" if installed else "Inactive"),
            "port": p["port"],
        })
    return result


def restart_protocol(service):
    """Only protocols listed above can be restarted. Returns (http_status, error_text)."""
    proto = next((p for p in PROTOCOLS if p["service"] == service), None)
    if proto is None:
        return 404, "Unknown protocol"
    restarted, failed = 0, []
    for svc in proto["services"]:
        _, load, _ = run_cmd(["systemctl", "show", "-p", "LoadState", "--value", svc], ignore_errors=True)
        if load != "loaded":
            continue
        code, _, err = run_cmd(["systemctl", "restart", svc], ignore_errors=True)
        if code == 0:
            restarted += 1
        else:
            failed.append(f"{svc}: {err or 'restart failed'}")
    if failed:
        return 500, "; ".join(failed)
    if restarted == 0:
        return 404, "Protocol is not installed"
    return 200, ""


# ---------------------------------------------------------------------
# Dynamic SSH banner. menu.sh's limiter writes the banner text; the panel
# keeps the per-user Match rules in sync with the users database.
# ---------------------------------------------------------------------
def _sshd_include_present():
    return bool(re.search(r"^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf\s*$",
                          read_text(SSHD_MAIN_CONFIG), re.M))


def _reload_sshd():
    for svc in ("sshd", "ssh"):
        code, _, _ = run_cmd(["systemctl", "reload", svc], ignore_errors=True)
        if code == 0:
            break
    run_cmd(["systemctl", "reload", "mjerumanicyber-ws-backend.service"], ignore_errors=True)


def refresh_ssh_banner_config():
    if not os.path.exists(BANNERS_FLAG):
        return
    os.makedirs(BANNER_DIR, exist_ok=True)
    lines = ["# MJERUMANI CYBER - Dynamic per-user SSH banners\n"]
    for u in read_db():
        name = u["username"]
        if not VALID_USER.match(name) or not linux_user_exists(name):
            continue
        lines.append(f"Match User {name}\n    Banner {BANNER_DIR}/{name}.txt\n")
    new_content = "".join(lines)
    old_content = read_text(SSHD_FF_CONFIG)
    if new_content == old_content:
        return

    if not _sshd_include_present():
        with open(SSHD_MAIN_CONFIG, "a") as f:
            f.write("\nInclude /etc/ssh/sshd_config.d/*.conf\n")

    os.makedirs(os.path.dirname(SSHD_FF_CONFIG), exist_ok=True)
    with open(SSHD_FF_CONFIG, "w") as f:
        f.write(new_content)
    sshd_bin = shutil.which("sshd") or "/usr/sbin/sshd"
    code, _, err = run_cmd([sshd_bin, "-t"], ignore_errors=True)
    if code != 0:
        log(f"sshd rejected the banner config, reverting: {err}")
        if old_content:
            with open(SSHD_FF_CONFIG, "w") as f:
                f.write(old_content)
        else:
            _remove_path(SSHD_FF_CONFIG)
        return
    _reload_sshd()


# ---------------------------------------------------------------------
# Trial accounts: removal is scheduled with `at`, running this same file
# ---------------------------------------------------------------------
def schedule_trial_cleanup(username, hours):
    if not shutil.which("at"):
        return False
    cmd = (f"{shlex.quote(sys.executable)} {shlex.quote(PANEL_SCRIPT)} "
           f"--cleanup-trial {shlex.quote(username)}\n")
    code, _, _ = run_cmd(["at", f"now + {int(hours)} hours"], input_text=cmd, ignore_errors=True)
    return code == 0


def cleanup_trial(username):
    if not VALID_USER.match(username):
        return 1
    with db_lock:
        users = read_db()
        target = next((u for u in users if u["username"] == username), None)
        if target is None or target.get("account_type") != "trial":
            return 0
        force_delete_system_user(username)
        write_db([u for u in users if u["username"] != username])
    remove_user_artifacts(username)
    refresh_ssh_banner_config()
    return 0


# ---------------------------------------------------------------------
# Input helpers
# ---------------------------------------------------------------------
def _num(value, default, cast, lo, hi, name):
    if value is None or value == "":
        value = default
    try:
        v = cast(value)
    except (TypeError, ValueError):
        raise ValueError(f"Invalid {name}")
    if isinstance(v, float) and not math.isfinite(v):
        raise ValueError(f"Invalid {name}")
    if v < lo or v > hi:
        raise ValueError(f"{name} must be between {lo} and {hi}")
    return v


def parse_json(raw):
    if not raw:
        return {}
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def reseller_quota(session):
    """None for admin. For a reseller: (remaining_slots, max_users)."""
    if session.get("role") != "reseller":
        return None
    r = next((x for x in read_resellers() if x["username"] == session["username"]), None)
    if r is None:
        raise PermissionError("Reseller account not found")
    owned = sum(1 for u in read_db() if u.get("owner") == session["username"])
    return max(0, r["max_users"] - owned), r["max_users"]


def owner_for(session):
    return session.get("username", "admin") if session.get("role") == "reseller" else "admin"


def create_managed_user(un, pwd_text, days, conn, bw, dbw, acct_type="web", owner="admin"):
    if not CREATE_USER.match(un):
        raise ValueError("Invalid username (3-32 letters, numbers or underscore)")
    with db_lock:
        if find_db_user(un) or linux_user_exists(un):
            raise ValueError("User already exists")
        expire = calculate_expire_date(days)
        code, _, err = run_cmd(["useradd", "-m", "-s", "/usr/sbin/nologin", un])
        if code != 0:
            raise RuntimeError(f"Could not create system user: {err}")
        run_cmd(["usermod", "-aG", FF_USERS_GROUP, un], ignore_errors=True)
        if not set_linux_password(un, pwd_text):
            run_cmd(["userdel", "-rf", un], ignore_errors=True)
            raise RuntimeError("Could not set password")
        run_cmd(["chage", "-E", expire, un], ignore_errors=True)
        new_u = {
            "username": un, "password": pwd_text, "expire_date": expire,
            "conn_limit": conn, "bandwidth_gb": bw, "daily_bandwidth_gb": dbw,
            "account_type": acct_type, "owner": owner,
        }
        append_db_user(new_u)
    reset_bandwidth_counters(un)
    refresh_ssh_banner_config()
    return new_u


# ---------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------
class PanelAPIHandler(BaseHTTPRequestHandler):
    server_version = "MjerumaniPanel"
    sys_version = ""

    def log_message(self, format, *args):
        pass

    # --- responses ---
    def send_json(self, status, data, extra_headers=None):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def send_bytes(self, status, content_type, data, cache=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        if cache:
            self.send_header("Cache-Control", cache)
        self.end_headers()
        self.wfile.write(data)

    def read_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            length = 0
        if length <= 0:
            return b""
        if length > MAX_BODY_BYTES:
            raise ValueError("Request body too large")
        return self.rfile.read(length)

    # --- routing helpers ---
    def _api_path(self, raw_path):
        """Map /<secret>/api/... (or /api/... when no secret is set) to /api/..."""
        secret = panel_secret()
        if secret:
            prefix = f"/{secret}/api"
            if raw_path == prefix or raw_path.startswith(prefix + "/"):
                return raw_path[len(f"/{secret}"):]
            return None
        if raw_path == "/api" or raw_path.startswith("/api/"):
            return raw_path
        return None

    def _request_api_path(self):
        return self._api_path(urlparse(self.path).path)

    def _get_session(self):
        s = check_session(self.headers)
        if s is None:
            self.send_json(401, {"error": "Unauthorized"})
        return s

    def _require_admin(self, session):
        if session.get("role") != "admin":
            self.send_json(403, {"error": "Admin access required"})
            return False
        return True

    def _managed_user(self, username, session):
        """The DB record of a user this session may manage; sends the error and returns None otherwise."""
        if not VALID_USER.match(username):
            self.send_json(400, {"error": "Invalid username"})
            return None
        u = find_db_user(username)
        if u is None:
            self.send_json(404, {"error": "User not found"})
            return None
        if session.get("role") != "admin" and u.get("owner") != session.get("username"):
            self.send_json(403, {"error": "Access denied"})
            return None
        return u

    # --- GET ---
    def do_GET(self):
        try:
            raw_path = urlparse(self.path).path or "/"
            creds = get_panel_creds()
            secret = panel_secret(creds)

            if secret:
                is_page = raw_path in (f"/{secret}", f"/{secret}/", f"/{secret}/index.html")
            else:
                is_page = raw_path in ("/", "/index.html")
            if is_page:
                if os.path.exists(PANEL_HTML):
                    with open(PANEL_HTML, "rb") as f:
                        return self.send_bytes(200, "text/html; charset=utf-8", f.read(), cache="no-cache")
                return self.send_bytes(404, "text/plain", b"HTML not found")

            api_path = self._api_path(raw_path)
            if not api_path:
                return self.send_bytes(404, "text/plain", b"Not Found")

            if api_path == "/api/branding":
                return self.send_json(200, {
                    "panel_name": creds.get("PANEL_NAME", DEFAULT_BRAND),
                    "panel_logo": creds.get("PANEL_LOGO", DEFAULT_LOGO),
                    "has_custom_logo": has_custom_logo(creds),
                })

            if api_path == "/api/logo.png":
                if os.path.exists(PANEL_LOGO):
                    with open(PANEL_LOGO, "rb") as f:
                        return self.send_bytes(200, "image/png", f.read(), cache="public, max-age=3600")
                return self.send_bytes(404, "text/plain", b"No custom logo")

            session = self._get_session()
            if session is None:
                return

            if api_path == "/api/me":
                return self.handle_get_me(session)
            if api_path == "/api/dashboard":
                return self.handle_get_dashboard(session)
            if api_path == "/api/users":
                return self.handle_get_users(session)
            if api_path == "/api/protocols":
                if self._require_admin(session):
                    self.send_json(200, get_protocols_status())
                return
            if api_path == "/api/settings":
                if self._require_admin(session):
                    self.handle_get_settings()
                return
            if api_path == "/api/resellers":
                if self._require_admin(session):
                    self.handle_get_resellers()
                return
            self.send_json(404, {"error": "Not Found"})
        except Exception as e:
            log(f"Error handling GET {self.path}: {e}")
            self.send_json(500, {"error": "Internal error"})

    # --- POST ---
    def do_POST(self):
        try:
            path = self._request_api_path()
            if path is None:
                return self.send_json(404, {"error": "Not Found"})
            raw = self.read_body()

            if path == "/api/logo/upload":
                session = self._get_session()
                if session is None or not self._require_admin(session):
                    return
                return self.handle_logo_upload(raw)

            body = parse_json(raw)
            if path == "/api/login":
                return self.handle_login(body)

            session = self._get_session()
            if session is None:
                return

            if path == "/api/logout":
                return self.handle_logout()
            if path == "/api/logo/delete":
                if self._require_admin(session):
                    self.handle_logo_delete()
                return
            if path == "/api/users":
                return self.handle_post_users(body, session)
            if path == "/api/users/bulk":
                return self.handle_post_users_bulk(body, session)
            if path == "/api/users/trial":
                return self.handle_post_trial_user(body, session)
            if path == "/api/resellers":
                if self._require_admin(session):
                    self.handle_post_reseller(body)
                return
            if path == "/api/system/reboot":
                if self._require_admin(session):
                    self.handle_system_reboot()
                return

            m = re.fullmatch(r"/api/users/([^/]+)/(lock|unlock|renew|reset-bandwidth)", path)
            if m:
                return self.handle_user_action(m.group(1), m.group(2), body, session)

            m = re.fullmatch(r"/api/protocols/([^/]+)/restart", path)
            if m:
                if self._require_admin(session):
                    self.handle_protocol_restart(m.group(1))
                return

            m = re.fullmatch(r"/api/resellers/([^/]+)/toggle", path)
            if m:
                if self._require_admin(session):
                    self.handle_toggle_reseller(m.group(1))
                return

            self.send_json(404, {"error": "Not Found"})
        except ValueError as e:
            self.send_json(400, {"error": str(e)})
        except Exception as e:
            log(f"Error handling POST {self.path}: {e}")
            self.send_json(500, {"error": "Internal error"})

    # --- PUT ---
    def do_PUT(self):
        try:
            path = self._request_api_path()
            if path is None:
                return self.send_json(404, {"error": "Not Found"})
            body = parse_json(self.read_body())
            session = self._get_session()
            if session is None:
                return

            m = re.fullmatch(r"/api/users/([^/]+)", path)
            if m:
                return self.handle_put_user(m.group(1), body, session)
            if path == "/api/settings":
                if self._require_admin(session):
                    self.handle_put_settings(body)
                return
            m = re.fullmatch(r"/api/resellers/([^/]+)", path)
            if m:
                if self._require_admin(session):
                    self.handle_put_reseller(m.group(1), body)
                return
            self.send_json(404, {"error": "Not Found"})
        except ValueError as e:
            self.send_json(400, {"error": str(e)})
        except Exception as e:
            log(f"Error handling PUT {self.path}: {e}")
            self.send_json(500, {"error": "Internal error"})

    # --- DELETE ---
    def do_DELETE(self):
        try:
            parsed = urlparse(self.path)
            path = self._api_path(parsed.path)
            if path is None:
                return self.send_json(404, {"error": "Not Found"})
            session = self._get_session()
            if session is None:
                return

            m = re.fullmatch(r"/api/users/([^/]+)", path)
            if m:
                return self.handle_delete_user(m.group(1), session)
            m = re.fullmatch(r"/api/resellers/([^/]+)", path)
            if m:
                if self._require_admin(session):
                    delete_users = parse_qs(parsed.query).get("delete_users", ["0"])[0] == "1"
                    self.handle_delete_reseller(m.group(1), delete_users)
                return
            self.send_json(404, {"error": "Not Found"})
        except Exception as e:
            log(f"Error handling DELETE {self.path}: {e}")
            self.send_json(500, {"error": "Internal error"})

    # --- auth ---
    def handle_login(self, body):
        user = str(body.get("username", ""))
        pwd_text = str(body.get("password", ""))
        if not user or not pwd_text:
            return self.send_json(401, {"error": "Invalid credentials"})

        creds = get_panel_creds()
        if (creds["PANEL_USER"] and user == creds["PANEL_USER"]
                and hmac.compare_digest(sha256_text(pwd_text).encode(), creds["PANEL_PASS_HASH"].encode())):
            return self._start_session(user, "admin")

        for r in read_resellers():
            if r["username"] == user and hmac.compare_digest(r["password"].encode(), pwd_text.encode()):
                if not r["enabled"]:
                    return self.send_json(401, {"error": "Account is disabled"})
                if is_past_date(r["expire_date"]):
                    return self.send_json(401, {"error": "Account has expired"})
                return self._start_session(user, "reseller")

        self.send_json(401, {"error": "Invalid credentials"})

    def _start_session(self, username, role):
        token = secrets.token_hex(32)
        with session_lock:
            sessions[token] = {"username": username, "role": role, "created_at": time.time()}
            save_sessions()
        cookie = f"session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}"
        self.send_json(200, {"success": True, "role": role}, {"Set-Cookie": cookie})

    def handle_logout(self):
        token = _token_from_headers(self.headers)
        if token:
            with session_lock:
                if sessions.pop(token, None) is not None:
                    save_sessions()
        self.send_json(200, {"success": True}, {"Set-Cookie": "session=; Path=/; HttpOnly; Max-Age=0"})

    def handle_get_me(self, session):
        creds = get_panel_creds()
        data = {
            "role": session.get("role", "admin"),
            "username": session.get("username", ""),
            "panel_name": creds.get("PANEL_NAME", DEFAULT_BRAND),
            "panel_logo": creds.get("PANEL_LOGO", DEFAULT_LOGO),
            "has_custom_logo": has_custom_logo(creds),
        }
        if session.get("role") == "reseller":
            r = next((x for x in read_resellers() if x["username"] == session["username"]), None)
            if r:
                owned = sum(1 for u in read_db() if u.get("owner") == session["username"])
                data.update({"expire_date": r["expire_date"], "max_users": r["max_users"],
                             "created_users": owned})
        self.send_json(200, data)

    # --- dashboard ---
    def handle_get_dashboard(self, session):
        users = read_db()
        if session.get("role") == "reseller":
            owned = [u for u in users if u.get("owner") == session["username"]]
            names = {u["username"] for u in owned}
            r = next((x for x in read_resellers() if x["username"] == session["username"]), None)
            self.send_json(200, {
                "user_count": len(owned),
                "online_sessions": sum(get_ssh_session_counts(names).values()),
                "protocols": [],
                "reseller_info": {
                    "max_users": r["max_users"] if r else 0,
                    "created_users": len(owned),
                    "expire_date": r["expire_date"] if r else "N/A",
                },
            })
            return

        _, ip, _ = run_cmd(["curl", "-s", "-4", "--max-time", "3", "icanhazip.com"], ignore_errors=True)
        os_name = "Unknown OS"
        for line in read_text("/etc/os-release").splitlines():
            if line.startswith("PRETTY_NAME="):
                os_name = line.split("=", 1)[1].strip().strip('"')
                break
        _, uptime_str, _ = run_cmd(["uptime", "-p"], ignore_errors=True)
        if uptime_str.startswith("up "):
            uptime_str = uptime_str[3:]

        ram_total = ram_available = 0
        for line in read_text("/proc/meminfo").splitlines():
            if line.startswith("MemTotal:"):
                ram_total = int(line.split()[1]) // 1024
            elif line.startswith("MemAvailable:"):
                ram_available = int(line.split()[1]) // 1024
        ram_used = ram_total - ram_available if ram_total > 0 else 0
        ram_percent = round((ram_used / ram_total) * 100, 1) if ram_total > 0 else 0.0

        loadavg = read_text("/proc/loadavg").split()
        cpu_load = _to_float(loadavg[0]) if loadavg else 0.0

        names = {u["username"] for u in users}
        self.send_json(200, {
            "server_ip": ip,
            "os_name": os_name,
            "uptime": uptime_str,
            "ram_percent": ram_percent,
            "ram_used_mb": ram_used,
            "ram_total_mb": ram_total,
            "cpu_load_1m": cpu_load,
            "user_count": len(users),
            "online_sessions": sum(get_ssh_session_counts(names).values()),
            "protocols": get_protocols_status(),
        })

    # --- users ---
    def handle_get_users(self, session):
        users = read_db()
        if session.get("role") == "reseller":
            users = [u for u in users if u.get("owner") == session["username"]]
        online = get_ssh_session_counts({u["username"] for u in users})
        locked = system_locked_users()

        result = []
        for u in users:
            un = u["username"]
            count = online.get(un, 0)
            u_ext = dict(u)
            u_ext.update({
                "total_used_bytes": read_file_int(os.path.join(BW_DIR, un + ".usage")),
                "daily_used_bytes": read_file_int(os.path.join(BW_DIR, un + ".daily_usage")),
                "is_locked": un in locked,
                "is_expired": u["expire_date"] != "Never" and is_past_date(u["expire_date"]),
                "is_online": count > 0,
                "online_sessions": count,
                "exists_on_system": linux_user_exists(un),
            })
            result.append(u_ext)
        self.send_json(200, {"users": result})

    def handle_post_users(self, body, session):
        try:
            quota = reseller_quota(session)
            if quota is not None and quota[0] <= 0:
                return self.send_json(403, {"error": f"User limit reached ({quota[1]})"})
            un = str(body.get("username", "")).strip()
            pwd_text = str(body.get("password", "") or "") or generate_password()
            days = _num(body.get("days"), 30, int, 0, 36500, "days")
            conn = _num(body.get("conn_limit"), 1, int, 1, 10000, "connection limit")
            bw = _num(body.get("bandwidth_gb"), 0, float, 0, 1_000_000, "bandwidth")
            dbw = _num(body.get("daily_bandwidth_gb"), 0, float, 0, 1_000_000, "daily bandwidth")
            new_u = create_managed_user(un, pwd_text, days, conn, bw, dbw, owner=owner_for(session))
            self.send_json(200, new_u)
        except PermissionError as e:
            self.send_json(403, {"error": str(e)})
        except (ValueError, RuntimeError) as e:
            self.send_json(400, {"error": str(e)})

    def handle_post_users_bulk(self, body, session):
        try:
            quota = reseller_quota(session)
            remaining = quota[0] if quota is not None else 10**9
            if remaining <= 0:
                return self.send_json(403, {"error": f"User limit reached ({quota[1]})"})
            prefix = str(body.get("prefix", "user")).strip() or "user"
            count = min(_num(body.get("count"), 1, int, 1, 100, "count"), remaining)
            days = _num(body.get("days"), 30, int, 0, 36500, "days")
            conn = _num(body.get("conn_limit"), 1, int, 1, 10000, "connection limit")
            bw = _num(body.get("bandwidth_gb"), 0, float, 0, 1_000_000, "bandwidth")
            dbw = _num(body.get("daily_bandwidth_gb"), 0, float, 0, 1_000_000, "daily bandwidth")
            owner = owner_for(session)

            created, idx = [], 1
            while len(created) < count and idx < 100000:
                un = f"{prefix}{idx}"
                idx += 1
                if find_db_user(un) or linux_user_exists(un):
                    continue
                try:
                    created.append(create_managed_user(un, generate_password(), days, conn, bw, dbw, "bulk", owner))
                except (ValueError, RuntimeError) as e:
                    log(f"Bulk create skipped {un}: {e}")
            self.send_json(200, {"users": created})
        except PermissionError as e:
            self.send_json(403, {"error": str(e)})
        except ValueError as e:
            self.send_json(400, {"error": str(e)})

    def handle_post_trial_user(self, body, session):
        try:
            quota = reseller_quota(session)
            if quota is not None and quota[0] <= 0:
                return self.send_json(403, {"error": f"User limit reached ({quota[1]})"})
            un = str(body.get("username", "")).strip()
            if not un:
                un = "trial_" + "".join(secrets.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(5))
            pwd_text = str(body.get("password", "") or "") or generate_password()
            hours = _num(body.get("hours"), 1, int, 1, 8760, "hours")
            conn = _num(body.get("conn_limit"), 1, int, 1, 10000, "connection limit")
            bw = _num(body.get("bandwidth_gb"), 0, float, 0, 1_000_000, "bandwidth")
            # chage needs a date; the `at` job removes the account at the real expiry time
            days = max(1, hours // 24)
            new_u = create_managed_user(un, pwd_text, days, conn, bw, 0.0, "trial", owner_for(session))
            scheduled = schedule_trial_cleanup(un, hours)
            if not scheduled:
                log(f"Trial {un} created, but auto-cleanup could not be scheduled (is 'at' installed?)")
            new_u["expiry_time"] = (datetime.now() + timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
            new_u["hours"] = hours
            new_u["cleanup_scheduled"] = scheduled
            self.send_json(200, new_u)
        except PermissionError as e:
            self.send_json(403, {"error": str(e)})
        except (ValueError, RuntimeError) as e:
            self.send_json(400, {"error": str(e)})

    def handle_put_user(self, username, body, session):
        if self._managed_user(username, session) is None:
            return
        try:
            with db_lock:
                users = read_db()
                u = next((x for x in users if x["username"] == username), None)
                if u is None:
                    return self.send_json(404, {"error": "User not found"})
                if body.get("password"):
                    new_pwd = str(body["password"])
                    set_linux_password(username, new_pwd)
                    u["password"] = new_pwd
                if body.get("days") not in (None, ""):
                    u["expire_date"] = calculate_expire_date(_num(body["days"], 30, int, 0, 36500, "days"))
                    run_cmd(["chage", "-E", u["expire_date"], username], ignore_errors=True)
                if "conn_limit" in body:
                    u["conn_limit"] = _num(body["conn_limit"], 1, int, 1, 10000, "connection limit")
                if "bandwidth_gb" in body:
                    u["bandwidth_gb"] = _num(body["bandwidth_gb"], 0, float, 0, 1_000_000, "bandwidth")
                if "daily_bandwidth_gb" in body:
                    u["daily_bandwidth_gb"] = _num(body["daily_bandwidth_gb"], 0, float, 0, 1_000_000,
                                                   "daily bandwidth")
                write_db(users)
            refresh_ssh_banner_config()
            self.send_json(200, u)
        except ValueError as e:
            self.send_json(400, {"error": str(e)})

    def handle_delete_user(self, username, session):
        if self._managed_user(username, session) is None:
            return
        with db_lock:
            force_delete_system_user(username)
            write_db([u for u in read_db() if u["username"] != username])
        remove_user_artifacts(username)
        refresh_ssh_banner_config()
        self.send_json(200, {"success": True})

    def handle_user_action(self, username, action, body, session):
        if self._managed_user(username, session) is None:
            return
        if action == "lock":
            run_cmd(["usermod", "-L", username], ignore_errors=True)
            kill_user_sessions(username)
            self.send_json(200, {"success": True})
        elif action == "unlock":
            run_cmd(["usermod", "-U", username], ignore_errors=True)
            _remove_path(os.path.join(BW_DIR, username + ".conn_locked"))
            _remove_path(os.path.join(BW_DIR, username + ".daily_locked"))
            self.send_json(200, {"success": True})
        elif action == "renew":
            try:
                days = _num(body.get("days"), 30, int, 0, 36500, "days")
            except ValueError as e:
                return self.send_json(400, {"error": str(e)})
            with db_lock:
                users = read_db()
                target = next((x for x in users if x["username"] == username), None)
                if target is None:
                    return self.send_json(404, {"error": "User not found"})
                target["expire_date"] = calculate_expire_date(days)
                run_cmd(["chage", "-E", target["expire_date"], username], ignore_errors=True)
                write_db(users)
            self.send_json(200, {"success": True, "expire_date": target["expire_date"]})
        elif action == "reset-bandwidth":
            reset_bandwidth_counters(username)
            run_cmd(["usermod", "-U", username], ignore_errors=True)
            self.send_json(200, {"success": True})

    # --- protocols & system ---
    def handle_protocol_restart(self, service):
        status, err = restart_protocol(service)
        if status == 200:
            self.send_json(200, {"success": True})
        else:
            self.send_json(status, {"success": False, "error": err})

    def handle_system_reboot(self):
        self.send_json(200, {"success": True, "message": "Rebooting system..."})
        threading.Timer(2.0, lambda: subprocess.run(["reboot"])).start()

    # --- settings & branding ---
    def handle_get_settings(self):
        creds = get_panel_creds()
        self.send_json(200, {
            "username": creds.get("PANEL_USER", ""),
            "secret": creds.get("PANEL_SECRET", ""),
            "panel_name": creds.get("PANEL_NAME", DEFAULT_BRAND),
            "panel_logo": creds.get("PANEL_LOGO", DEFAULT_LOGO),
            "has_custom_logo": has_custom_logo(creds),
        })

    def handle_put_settings(self, body):
        creds = get_panel_creds()
        curr_pwd = str(body.get("current_password", ""))
        if not hmac.compare_digest(sha256_text(curr_pwd).encode(), creds["PANEL_PASS_HASH"].encode()):
            return self.send_json(401, {"error": "Invalid current password"})

        new_user = str(body.get("new_username", "")).strip() or creds["PANEL_USER"]
        new_pwd = str(body.get("new_password", "")).strip() or creds["PANEL_PASS_PLAIN"]
        if not new_user or not new_pwd:
            return self.send_json(400, {"error": "Username and password cannot be empty"})
        if any(r["username"] == new_user for r in read_resellers()):
            return self.send_json(400, {"error": "Username conflicts with a reseller"})

        new_secret = str(body.get("new_secret", "")).strip().strip("/")
        if new_secret:
            if not SECRET_RE.match(new_secret):
                return self.send_json(400, {"error": "Secret path: 3-64 letters, numbers, - or _"})
        else:
            # An empty field keeps the current path; it must never open the panel at "/"
            new_secret = creds["PANEL_SECRET"]

        new_name = str(body.get("panel_name", "")).strip()[:40] or creds["PANEL_NAME"]
        new_logo = str(body.get("panel_logo", "")).strip()[:16] or creds["PANEL_LOGO"]

        creds.update({
            "PANEL_USER": new_user,
            "PANEL_PASS_PLAIN": new_pwd,
            "PANEL_PASS_HASH": sha256_text(new_pwd),
            "PANEL_SECRET": new_secret,
            "PANEL_NAME": new_name,
            "PANEL_LOGO": new_logo,
        })
        save_panel_creds(creds)
        self.send_json(200, {"success": True, "secret": new_secret,
                             "panel_name": new_name, "panel_logo": new_logo})

    def handle_logo_upload(self, raw):
        if not raw:
            return self.send_json(400, {"error": "No file data"})
        if len(raw) > 2 * 1024 * 1024:
            return self.send_json(400, {"error": "File too large (max 2MB)"})
        if not raw.startswith(PNG_SIGNATURE):
            return self.send_json(400, {"error": "File must be a PNG image"})
        os.makedirs(PANEL_DIR, exist_ok=True)
        tmp = PANEL_LOGO + ".tmp"
        with open(tmp, "wb") as f:
            f.write(raw)
        os.replace(tmp, PANEL_LOGO)
        creds = get_panel_creds()
        creds["PANEL_LOGO"] = "custom"
        save_panel_creds(creds)
        self.send_json(200, {"success": True, "panel_logo": "custom"})

    def handle_logo_delete(self):
        _remove_path(PANEL_LOGO)
        creds = get_panel_creds()
        creds["PANEL_LOGO"] = DEFAULT_LOGO
        save_panel_creds(creds)
        self.send_json(200, {"success": True, "panel_logo": DEFAULT_LOGO})

    # --- resellers (admin only) ---
    def handle_get_resellers(self):
        resellers = read_resellers()
        users = read_db()
        result = []
        for r in resellers:
            owned = sum(1 for u in users if u.get("owner") == r["username"])
            result.append({
                "username": r["username"],
                "password": r["password"],
                "expire_date": r["expire_date"],
                "max_users": r["max_users"],
                "created_users": owned,
                "enabled": r["enabled"],
                "is_expired": is_past_date(r["expire_date"]),
            })
        self.send_json(200, {"resellers": result})

    def handle_post_reseller(self, body):
        try:
            un = str(body.get("username", "")).strip()
            pwd_text = str(body.get("password", "") or "") or generate_password()
            days = _num(body.get("days"), 30, int, 0, 36500, "days")
            max_users = _num(body.get("max_users"), 10, int, 1, 100000, "max users")
        except ValueError as e:
            return self.send_json(400, {"error": str(e)})
        if not CREATE_USER.match(un):
            return self.send_json(400, {"error": "Invalid username (3-32 chars, alphanumeric + underscore)"})
        if un == get_panel_creds().get("PANEL_USER") or linux_user_exists(un):
            return self.send_json(400, {"error": "Username is already in use"})
        resellers = read_resellers()
        if any(r["username"] == un for r in resellers):
            return self.send_json(400, {"error": "Reseller already exists"})
        new_r = {"username": un, "password": pwd_text, "expire_date": calculate_expire_date(days),
                 "max_users": max_users, "enabled": True}
        resellers.append(new_r)
        write_resellers(resellers)
        self.send_json(200, new_r)

    def handle_put_reseller(self, username, body):
        resellers = read_resellers()
        r = next((x for x in resellers if x["username"] == username), None)
        if r is None:
            return self.send_json(404, {"error": "Reseller not found"})
        try:
            if body.get("password"):
                r["password"] = str(body["password"])
            if body.get("days") not in (None, ""):
                r["expire_date"] = calculate_expire_date(_num(body["days"], 30, int, 0, 36500, "days"))
            if "max_users" in body:
                r["max_users"] = _num(body["max_users"], 10, int, 1, 100000, "max users")
        except ValueError as e:
            return self.send_json(400, {"error": str(e)})
        write_resellers(resellers)
        self.send_json(200, r)

    def handle_toggle_reseller(self, username):
        resellers = read_resellers()
        r = next((x for x in resellers if x["username"] == username), None)
        if r is None:
            return self.send_json(404, {"error": "Reseller not found"})
        r["enabled"] = not r["enabled"]
        write_resellers(resellers)
        if not r["enabled"]:
            drop_sessions_for(username, "reseller")
        self.send_json(200, {"success": True, "enabled": r["enabled"]})

    def handle_delete_reseller(self, username, delete_users=False):
        resellers = read_resellers()
        if not any(r["username"] == username for r in resellers):
            return self.send_json(404, {"error": "Reseller not found"})
        if delete_users:
            with db_lock:
                owned = [u["username"] for u in read_db() if u.get("owner") == username]
                for un in owned:
                    force_delete_system_user(un)
                    remove_user_artifacts(un)
                write_db([u for u in read_db() if u["username"] not in owned])
        write_resellers([r for r in resellers if r["username"] != username])
        drop_sessions_for(username, "reseller")
        refresh_ssh_banner_config()
        self.send_json(200, {"success": True})


def _token_from_headers(headers):
    if "Cookie" not in headers:
        return None
    jar = cookies.SimpleCookie(headers["Cookie"])
    return jar["session"].value if "session" in jar else None


def check_session(headers):
    cleanup_sessions()
    token = _token_from_headers(headers)
    if not token:
        return None
    with session_lock:
        return sessions.get(token)


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--cleanup-trial":
        return cleanup_trial(sys.argv[2])

    os.makedirs(DB_DIR, exist_ok=True)
    load_sessions()
    server = ThreadingHTTPServer(("0.0.0.0", PORT), PanelAPIHandler)
    server.daemon_threads = True
    log(f"Starting panel on port {PORT}...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
