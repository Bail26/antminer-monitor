#!/usr/bin/env python3
"""
miner.py - Watchman for Antminer (final integrated version)

Features:
 - Telegram commands: /status, /restart, /help (command replies only -> Telegram)
 - Alerts: power, API, zero-hash (real-time), temp, live log scanner (alerts -> Telegram + Email if EMAIL_TO set)
 - Auto-restart logic (API->HTTP->SSH) (can be disabled)
 - Restart suppression windows and boot grace handling
 - Rotating logs (5 MB, 7 rotated backups)
 - Log scanning with toggles: reduce chatter, alerts-only, throttle interval
"""

import socket, json, time, subprocess, sys, re, traceback
from datetime import datetime
import requests
from requests.auth import HTTPDigestAuth
from email.mime.text import MIMEText
import smtplib
import logging
from logging.handlers import RotatingFileHandler
from collections import deque

# Optional SSH (paramiko used for SSH restart/log fetch)
try:
    import paramiko
    HAS_PARAMIKO = True
except Exception:
    HAS_PARAMIKO = False

# ===================== CONFIG - EDIT THESE =====================
MINER_IP = "192.168.1.31"
API_PORT = 4028
POLL_INTERVAL = 60               # seconds between main loop cycles

# Telegram
TELEGRAM_TOKEN = "8378274795:AAH7Dh1ABoSItyCWbwki6tlQhogBLjwqArU"
TELEGRAM_CHAT_ID = "6507077625"

# Email (optional - App password recommended for Gmail)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = ""   # sender gmail address
SMTP_PASS = ""   # app password
EMAIL_TO = ""    # recipient; leave empty to disable email alerts

# Email master toggle (if you want to temporarily disable email while credentials remain)
EMAIL_ENABLED = True if EMAIL_TO else False

# Auto-restart policy
AUTO_RESTART_ENABLED = True    # set False to disable auto restarts
RESTART_MIN_INTERVAL = 4 * 3600   # seconds between automatic restarts (4 hours)
RESTART_TIMEOUT = 300             # wait for miner to recover after restart (seconds)
RESTART_POLL_INTERVAL = 15        # how often to poll during recovery wait
MAX_RESTART_ATTEMPTS_PER_EVENT = 1

# Zero-hash thresholds and sleep window
GHS_ZERO_THRESHOLD = 0.001     # GH/s threshold considered as zero (applies to avg or realtime)
TEMP_SLEEP_MIN = 30            # deg C (sleep temp lower bound)
TEMP_SLEEP_MAX = 50            # deg C (sleep temp upper bound)
TEMP_HIGH_LIMIT = 75           # deg C - block restarts if >= this
FAN_ON_THRESHOLD = 1           # RPM considered "on"

# Uptime & power rules
MIN_UPTIME_BEFORE_AUTO_RESTART = 15 * 60   # 15 minutes (avoid auto restart during early boot)
POWER_RECENT_SUPPRESSION = 12 * 60         # 12 minutes after power restore wait for hashing
POWER_REMINDER_INTERVAL = 5 * 60           # remind every 5 minutes when offline

# HTTP/SSH credentials (for reboot + log fetch)
RESTART_HTTP_USERNAME = "root"
RESTART_HTTP_PASSWORD = "root"
SSH_USERNAME = "root"
SSH_PASSWORD = "root"
SSH_PORT = 22
SSH_TIMEOUT = 10

# Suppress power alerts for short time after we initiated restart
REBOOT_SUPPRESS_WINDOW = 180  # seconds

# DRY_RUN flag (prevent real reboots while testing)
DRY_RUN = False   # Set True to avoid making restart calls

# Logging config - rotation
LOGFILE = "miner_watchman.log"
LOG_MAX_BYTES = 5 * 1024 * 1024   # 5 MB
LOG_BACKUP_COUNT = 7
# ===============================================================

# ---------------- Log polling config & tokens ----------------
LOG_HTTP_ENDPOINTS = [
    "/cgi-bin/get_log.cgi",
    "/cgi-bin/minerLog.cgi",
    "/cgi-bin/get_system_info.cgi",
    "/cgi-bin/minerStatus.cgi",
    "/cgi-bin/get_log",
    "/log",
    "/tmp/log",
]
LOG_SSH_PATHS = [
    "/var/log/messages",
    "/var/log/syslog",
    "/var/log/miner.log",
    "/tmp/log",
]
LOG_DEQUE_MAX = 400

LOGSCAN_REDUCE_CHATTER = True        # if True, suppress "no new log lines" messages
LOGSCAN_ALERTS_ONLY = True         # if True, only notify on matches and don't log "scanned X lines; no matches"
LOGSCAN_THROTTLE_INTERVAL = 300      # seconds between log fetches (0 = no throttle)

LOG_ERROR_TOKENS = [
    "reg crc", "regcrc", "regc", "crc", "reg_crc", "!!! reg crc error",
    "error_power", "voltage", "sleep", "sleeping", "cannot", "connection refused",
    "lost connection", "disconnect", "fatal", "panic", "hw error", "hardware error",
    "no matching work", "no work", "no share"
]
# ===============================================================

# ---------- Logging setup ----------
logger = logging.getLogger("miner_watchman")
logger.setLevel(logging.INFO)
fmt = logging.Formatter("[%(asctime)s] %(message)s", "%Y-%m-%d %H:%M:%S")

ch = logging.StreamHandler()
ch.setFormatter(fmt)
logger.addHandler(ch)

fh = RotatingFileHandler(LOGFILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT, encoding="utf-8")
fh.setFormatter(fmt)
logger.addHandler(fh)

def log(msg):
    try:
        logger.info(msg)
    except Exception:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def now(): return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def format_elapsed(seconds):
    try:
        seconds = int(seconds)
    except:
        return str(seconds)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, sec = divmod(rem, 60)
    parts = []
    if days: parts.append(f"{days}d")
    if hours: parts.append(f"{hours}h")
    if minutes: parts.append(f"{minutes}m")
    if sec and seconds < 3600: parts.append(f"{sec}s")
    return "".join(parts) if parts else "0s"

# ---------------- Notifications ----------------
def send_telegram_to(chat_id, text):
    if not TELEGRAM_TOKEN:
        log("Telegram not configured")
        return False
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        r = requests.post(url, json={"chat_id": chat_id, "text": text})
        if r.status_code != 200:
            log(f"Telegram HTTP error to {chat_id}: {r.status_code} {r.text[:200]}")
        return r.status_code == 200
    except Exception as e:
        log("Telegram error (to chat): " + str(e))
        return False

def send_telegram(text):
    return send_telegram_to(TELEGRAM_CHAT_ID, text)

def send_email(subject, body):
    if not EMAIL_TO or not EMAIL_ENABLED:
        return False
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = SMTP_USER
        msg["To"] = EMAIL_TO
        s = smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=15)
        s.starttls()
        s.login(SMTP_USER, SMTP_PASS)
        s.sendmail(SMTP_USER, [EMAIL_TO], msg.as_string())
        s.quit()
        return True
    except Exception as e:
        log("Email send error: " + str(e))
        return False

def notify(title, body, email=True):
    """
    Central notify function.
    title: short subject/title
    body: detailed text
    email: boolean; if False -> only send Telegram (used for command replies).
           If True and EMAIL_TO set and EMAIL_ENABLED is True -> send email.
    """
    message = f"{title}\n\n{body}"
    # Always log
    log("NOTIFY -> " + title + " | " + " / ".join(line.strip() for line in body.splitlines() if line.strip()))
    # Telegram broadcast
    try:
        send_telegram(message)
    except Exception as e:
        log("Telegram broadcast failed: " + str(e))
    # Email if allowed and requested
    if email and EMAIL_TO and EMAIL_ENABLED:
        send_email(title, body)

# ---------------- Network / API ----------------
def ping(host, timeout=2):
    try:
        if sys.platform.startswith("win"):
            cmd = ["ping", "-n", "1", "-w", str(int(timeout*1000)), host]
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(timeout)), host]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return res.returncode == 0
    except Exception as e:
        log("Ping error: " + str(e))
        return False

def query_api(cmd_json, timeout=5):
    raw = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((MINER_IP, API_PORT))
        s.sendall(cmd_json.encode())
        chunks = []
        while True:
            try:
                part = s.recv(4096)
                if not part: break
                chunks.append(part)
            except socket.timeout:
                break
        s.close()
        raw = b"".join(chunks).decode(errors="ignore")
        start = raw.find("{"); end = raw.rfind("}")
        if start!=-1 and end!=-1 and end>start:
            try:
                return json.loads(raw[start:end+1]), raw
            except Exception:
                pass
        try:
            return json.loads(raw), raw
        except Exception:
            return {"__raw__": raw}, raw
    except Exception as e:
        return {"__error__": str(e)}, str(e)

# ---------------- Restart methods ----------------
def restart_via_api():
    if DRY_RUN:
        log("[DRY_RUN] would send API reboot command (skipped)")
        return False
    try:
        for cmd in ('{"command":"reboot"}','{"command":"restart"}'):
            data, raw = query_api(cmd)
            if "__error__" in data:
                log("API restart attempt error: " + str(data.get("__error__")))
                continue
            if isinstance(data, dict) and "STATUS" in data:
                statuses = data["STATUS"]
                if isinstance(statuses, list) and statuses:
                    msg = str(statuses[0].get("Msg","")).lower()
                    st = statuses[0].get("STATUS","")
                    if "invalid" in msg or str(st).upper() == "E" or "error" in msg:
                        log("API restart rejected: " + msg)
                        continue
            log("API restart accepted; raw excerpt: " + (raw[:200] if raw else ""))
            return True
        return False
    except Exception as e:
        log("restart_via_api exception: " + str(e))
        return False

def restart_via_http():
    endpoints = [
        "/cgi-bin/minerControl.cgi?action=reboot",
        "/cgi-bin/minerControl.cgi?action=restart",
        "/reboot.cgi",
        "/reboot",
        "/cgi-bin/reboot",
        "/cgi-bin/miner/reboot",
        "/cgi-bin/reboot.cgi"
    ]
    if DRY_RUN:
        log("[DRY_RUN] Would try HTTP reboot endpoints with user %s" % RESTART_HTTP_USERNAME)
        return False
    auth = HTTPDigestAuth(RESTART_HTTP_USERNAME, RESTART_HTTP_PASSWORD)
    for p in endpoints:
        url = f"http://{MINER_IP}{p}"
        try:
            log("HTTP reboot try: GET " + url)
            r = requests.get(url, auth=auth, timeout=8, allow_redirects=True)
            if r.status_code in (200,202,301,302):
                log("HTTP reboot returned status %s, body excerpt: %s" % (r.status_code, r.text[:200]))
                return True
            log("HTTP reboot try: POST " + url)
            r2 = requests.post(url, data={"action":"reboot"}, auth=auth, timeout=8, allow_redirects=True)
            if r2.status_code in (200,202,301,302):
                log("HTTP reboot POST returned status %s" % r2.status_code)
                return True
        except Exception as e:
            log("HTTP reboot endpoint error for %s : %s" % (url, e))
            continue
    return False

def restart_via_ssh():
    if DRY_RUN:
        log("[DRY_RUN] Would SSH reboot %s (user=%s)" % (MINER_IP, SSH_USERNAME))
        return False
    if not HAS_PARAMIKO:
        log("Paramiko not installed; SSH restart unavailable.")
        return False
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(MINER_IP, port=SSH_PORT, username=SSH_USERNAME, password=SSH_PASSWORD, timeout=SSH_TIMEOUT)
        stdin, stdout, stderr = ssh.exec_command("/sbin/reboot")
        out = stdout.read().decode(errors="ignore") if stdout else ""
        err = stderr.read().decode(errors="ignore") if stderr else ""
        log("SSH reboot executed; stdout excerpt: %s stderr excerpt: %s" % (out[:200], err[:200]))
        ssh.close()
        return True
    except Exception as e:
        log("SSH reboot failed: " + str(e))
        return False

def attempt_restart(trigger="auto", notify_email=True):
    """
    Attempt restart using API -> HTTP -> SSH.
    trigger: "auto" or "manual"
    notify_email: if False, do not send email notifications for the restart event
    Returns True if any method accepted the restart command (does not guarantee recovery).
    """
    nowt = time.time()
    if trigger == "auto" and nowt - state.get('last_auto_restart_time', 0) < RESTART_MIN_INTERVAL:
        log("Auto-restart suppressed due to minimum interval.")
        return False

    notify("🔁 AUTO-RESTART: Initiating" if trigger=="auto" else "🔁 MANUAL RESTART: Initiating",
           f"Attempting restart of miner {MINER_IP}. Methods: API -> HTTP -> SSH. DRY_RUN={DRY_RUN}. Trigger={trigger}",
           email=notify_email)

    if restart_via_api():
        state['last_auto_restart_time'] = time.time()
        state['last_restart_attempt_time'] = time.time()
        notify("🔁 RESTART SUCCESS", "Restart via API accepted.", email=notify_email)
        return True

    if restart_via_http():
        state['last_auto_restart_time'] = time.time()
        state['last_restart_attempt_time'] = time.time()
        notify("🔁 RESTART SUCCESS", "Restart via HTTP reboot endpoint succeeded.", email=notify_email)
        return True

    if restart_via_ssh():
        state['last_auto_restart_time'] = time.time()
        state['last_restart_attempt_time'] = time.time()
        notify("🔁 RESTART SUCCESS", "Restart via SSH succeeded.", email=notify_email)
        return True

    notify("🔴 RESTART FAILED", "All restart methods failed.", email=notify_email)
    return False

# ---------------- Parsing helpers ----------------
def format_fans(fans):
    if not fans: return "No fan data"
    return ", ".join(f"{k}={v}" for k,v in sorted(fans.items()))

def format_boards_summary(boards):
    if not boards: return "No board data"
    parts=[]
    for b in boards:
        in_s = f"In={b['inlet']}°C" if b.get('inlet') is not None else "In=?"
        out_s = f"Out={b['outlet']}°C" if b.get('outlet') is not None else "Out=?"
        parts.append(f"{b['name']}: chips={b['chips']} hw={b['hw_err']} hr={int(b.get('mhs',0))}MH/s {in_s} {out_s}")
    return " | ".join(parts)

# ---------------- Quick status payload (for /status) ----------------
def quick_status_payload():
    try:
        ping_ok = ping(MINER_IP)
        if not ping_ok:
            return "🔴 Miner OFFLINE (ping failed)."
        data, raw = query_api('{"command":"summary"}')
        if "__error__" in data:
            return "🟠 Miner reachable but API query failed (timeout/refused)."
        ghs = None; elapsed=None; acc=None; rej=None
        if "SUMMARY" in data and data["SUMMARY"]:
            s = data["SUMMARY"][0]
            try: ghs = float(s.get("GHS 30m") or s.get("GHS av") or s.get("GHS 5s") or 0)
            except: ghs=None
            try: elapsed = int(s.get("Elapsed") or 0)
            except: elapsed=None
            try: acc = int(s.get("Accepted",0) or 0)
            except: acc=None
            try: rej = int(s.get("Rejected",0) or 0)
            except: rej=None

        stats_data, stats_raw = query_api('{"command":"stats"}')
        fans={}; boards=[]
        if isinstance(stats_data, dict) and "STATS" in stats_data and isinstance(stats_data["STATS"], list):
            st = stats_data["STATS"][1] if len(stats_data["STATS"])>1 else stats_data["STATS"][0]
            fan_num = int(st.get("fan_num",0) or 0)
            for i in range(1, fan_num+1):
                try: fans[f"fan{i}"] = int(st.get(f"fan{i}",0) or 0)
                except: pass
            for bi in range(1,4):
                inlet=None; outlet=None
                chip_str = st.get(f"temp_chip{bi}")
                if chip_str:
                    try:
                        parts=[p for p in chip_str.split("-") if p.strip().isdigit()]
                        vals=[int(x) for x in parts] if parts else []
                        if vals:
                            inlet=vals[0]; outlet=vals[-1]
                    except: pass
                try: mhs = float(st.get(f"chain_rate{bi}",0) or 0)
                except: mhs=0.0
                try: chips = int(st.get(f"chain_acn{bi}",77) or 77)
                except: chips=77
                try: hw_err = int(st.get(f"chain_hw{bi}",0) or 0)
                except: hw_err=0
                boards.append({"name":f"Board{bi}","inlet":inlet,"outlet":outlet,"mhs":mhs,"chips":chips,"hw_err":hw_err})
        lines=["✅ Miner ONLINE"]
        if ghs is not None: lines.append(f"Hashrate (30m): {ghs:,.2f} GH/s")
        if elapsed is not None: lines.append(f"Uptime: {format_elapsed(elapsed)}")
        if acc is not None and rej is not None: lines.append(f"Acc/Rej: {acc}/{rej}")
        lines.append("Fans: " + format_fans(fans))
        if boards:
            bparts=[f"{b['name']} In={b['inlet']}C Out={b['outlet']}C" for b in boards]
            lines.append("Boards: " + " | ".join(bparts))
        return "\n".join(lines)
    except Exception as e:
        return "Error building status: " + str(e)

# ---------------- Telegram polling / commands ----------------
def process_telegram_commands():
    if not TELEGRAM_TOKEN:
        return
    try:
        offset = state.get('tg_update_offset', 0)
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getUpdates"
        r = requests.get(url, params={"offset": offset, "timeout": 0}, timeout=5)
        if r.status_code != 200:
            return
        data = r.json()
        if not data.get("ok"): return
        updates = data.get("result", [])
        if len(updates) > 1:
            log(f"[INFO] Processing {len(updates)} queued Telegram updates.")
        for upd in updates:
            uid = upd.get("update_id")
            state['tg_update_offset'] = uid + 1
            msg = upd.get("message") or upd.get("edited_message")
            if not msg: continue
            chat = msg.get("chat", {})
            chat_id = chat.get("id")
            text = (msg.get("text") or "").strip()
            if not text: continue
            cmd = text.split()[0].lower()
            if cmd == "/status":
                log(f"Telegram command /status from {chat_id}")
                payload = quick_status_payload()
                send_telegram_to(chat_id, payload)   # only telegram (no email)
            elif cmd == "/restart":
                log(f"Telegram command /restart from {chat_id}")
                send_telegram_to(chat_id, f"🔁 Manual restart requested. DRY_RUN={DRY_RUN}. Attempting restart now...")
                # Manual restart: do not trigger email notifications from attempt_restart()
                success = attempt_restart(trigger="manual", notify_email=False)
                if success:
                    send_telegram_to(chat_id, "✅ Manual restart attempt executed (check logs for details).")
                    # wait for miner to resume hashing (non-blocking short loop with timeout)
                    recovered = wait_for_recovery(timeout=RESTART_TIMEOUT, poll=RESTART_POLL_INTERVAL, ghs_threshold=1.0)
                    if recovered:
                        notify("✅ Manual restart — miner resumed hashing", f"Miner {MINER_IP} resumed hashing after manual restart.")
                        # let chat know as well
                        send_telegram_to(chat_id, "✅ Miner resumed hashing after manual restart.")
                    else:
                        # not recovered within wait window
                        send_telegram_to(chat_id, f"⚠️ Miner did not resume hashing within {RESTART_TIMEOUT} seconds after restart. Manual check required.")
                else:
                    send_telegram_to(chat_id, "❌ Manual restart failed. See logs.")
            elif cmd == "/help":
                help_text = ("/status - show live status\n/restart - manual restart (override)\n/help - this help\n"
                             f"DRY_RUN={DRY_RUN} AUTO_RESTART_ENABLED={AUTO_RESTART_ENABLED}\nEmail enabled: {EMAIL_ENABLED}")
                send_telegram_to(chat_id, help_text)
    except Exception as e:
        log("process_telegram_commands error: " + str(e))

# ---------------- State ----------------
state = {
    'power_off_notified': False,
    'last_power_notify_time': 0,
    'last_auto_restart_time': 0,
    'restart_attempts_for_event': 0,
    'last_elapsed': None,
    'temp_alert_times': {},
    'temp_alert_active': {},
    'last_power_off_time': 0,
    'last_power_restore_time': 0,
    'awaiting_hash_after_restore': False,
    'suppress_until': 0,
    'tg_update_offset': 0,
    'last_ghs': None,
    'last_restart_attempt_time': 0,
    # log scanner:
    'seen_log_lines': deque(maxlen=LOG_DEQUE_MAX),
    'log_alerted_lines': set(),
    'last_log_scan_time': 0,
}

# ---------------- Log scanning helpers ----------------
def scan_for_errors_line(line):
    """Return token matched or None."""
    if not isinstance(line, str): return None
    low = line.lower()
    for t in LOG_ERROR_TOKENS:
        if t in low:
            return t
    return None

def fetch_logs():
    """
    Try: API -> HTTP endpoints -> SSH file tails.
    Returns (ok_bool, text, method_str)
    """
    # 1) API 'log' command
    try:
        data, raw = query_api('{"command":"log"}', timeout=4)
        if "__error__" not in data:
            # try extracting strings from JSON, else fallback to raw
            if isinstance(data, dict):
                txts = []
                def extract_strings(obj):
                    out = []
                    if isinstance(obj, dict):
                        for v in obj.values(): out.extend(extract_strings(v))
                    elif isinstance(obj, list):
                        for i in obj: out.extend(extract_strings(i))
                    elif isinstance(obj, str):
                        out.append(obj)
                    return out
                txts = extract_strings(data)
                txt = "\n".join(txts).strip()
                if not txt:
                    txt = raw if isinstance(raw, str) else ""
                if txt:
                    return True, txt, "api_log"
    except Exception:
        pass

    # 2) HTTP endpoints
    auth = HTTPDigestAuth(RESTART_HTTP_USERNAME, RESTART_HTTP_PASSWORD)
    for p in LOG_HTTP_ENDPOINTS:
        url = f"http://{MINER_IP}{p}"
        try:
            r = requests.get(url, auth=auth, timeout=6, allow_redirects=True)
            if r.status_code == 200 and r.text:
                body = r.text
                if "<html" in body.lower() or "<div" in body.lower() or "<table" in body.lower():
                    text = re.sub(r"<[^>]+>", "", body)
                else:
                    text = body
                text = text.strip()
                if text:
                    return True, text, f"http:{p}"
        except Exception as e:
            log(f"[logfetch] HTTP log try {url} error: {e}")
            continue

    # 3) SSH tail files
    if HAS_PARAMIKO:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(MINER_IP, port=SSH_PORT, username=SSH_USERNAME, password=SSH_PASSWORD, timeout=SSH_TIMEOUT)
            for path in LOG_SSH_PATHS:
                try:
                    cmd = f"tail -n 500 {path}"
                    stdin, stdout, stderr = ssh.exec_command(cmd, timeout=8)
                    out = stdout.read().decode(errors="ignore") if stdout else ""
                    if out and len(out.strip())>5:
                        ssh.close()
                        return True, out.strip(), f"ssh:{path}"
                except Exception:
                    continue
            ssh.close()
        except Exception as e:
            log("SSH log fetch failed: " + str(e))

    return False, "", "none"

def process_logs_once():
    # throttle
    if LOGSCAN_THROTTLE_INTERVAL > 0:
        if time.time() - state.get('last_log_scan_time', 0) < LOGSCAN_THROTTLE_INTERVAL:
            return
        state['last_log_scan_time'] = time.time()

    ok, text, method = fetch_logs()
    if not ok or not text:
        if not LOGSCAN_REDUCE_CHATTER:
            log(f"[logscan] No logs fetched via method {method}")
        return

    lines = [l.strip() for l in text.splitlines() if l.strip()]
    if not lines:
        if not LOGSCAN_REDUCE_CHATTER:
            log(f"[logscan] No lines parsed from logs (method {method})")
        return

    new_lines = []
    seen = state['seen_log_lines']
    for l in lines:
        if l not in seen:
            new_lines.append(l)
            seen.append(l)

    if not new_lines:
        if not LOGSCAN_REDUCE_CHATTER:
            log(f"[logscan] no new log lines to scan (method {method})")
        return

    alerted = []
    for l in new_lines:
        token = scan_for_errors_line(l)
        if token:
            if l in state['log_alerted_lines']:
                continue
            excerpt = (l[:800]) if len(l)>800 else l
            body = f"Miner: {MINER_IP}\nLog method: {method}\nMatched token: {token}\n\nLog line:\n{excerpt}"
            notify(f"⚠️ LOG ALERT: {token.upper()}", body)
            state['log_alerted_lines'].add(l)
            alerted.append((token, l))

    if alerted:
        log(f"[logscan] alerted on {len(alerted)} new log lines (method {method})")
    else:
        if not LOGSCAN_ALERTS_ONLY:
            log(f"[logscan] scanned {len(new_lines)} new lines; no matches (method {method})")

# ---------------- API raw scanning ----------------
def scan_for_errors(raw):
    if not isinstance(raw, str): return None
    low = raw.lower()
    # avoid noisy matches for generic 'hardware error' unless reg crc included
    if "hardware error" in low and "reg crc" not in low:
        return None
    tokens = ["regc", "reg crc", "crc", "reg_crc",
              "error_power", "cannot", "connection refused", "lost connection",
              "disconnect", "fatal", "panic"]
    for t in tokens:
        if t in low:
            return t
    return None

# ---------------- Main check cycle ----------------
def check_cycle():
    # 0) process logs first
    try:
        process_logs_once()
    except Exception as e:
        log("process_logs_once error: " + str(e))

    # 1) ping for power detection
    ping_ok = ping(MINER_IP)
    if not ping_ok:
        time.sleep(1)
        if not ping(MINER_IP):
            nowt = time.time()
            if nowt - state.get('last_restart_attempt_time',0) < REBOOT_SUPPRESS_WINDOW:
                log(f"[INFO] Suppressing power offline alert because we initiated restart {int(nowt-state['last_restart_attempt_time'])}s ago.")
                return
            if not state['power_off_notified']:
                state['last_power_off_time'] = nowt
                notify("⚡ POWER ALERT",
                       f"Miner {MINER_IP} unreachable (ping failed).\nPossible power cut or NIC down.\nI will remind every {POWER_REMINDER_INTERVAL//60} minutes.")
                state['power_off_notified'] = True
                state['last_power_notify_time'] = nowt
            else:
                if nowt - state['last_power_notify_time'] >= POWER_REMINDER_INTERVAL:
                    notify("⚡ POWER REMINDER", f"Miner {MINER_IP} still not reachable by ping.")
                    state['last_power_notify_time'] = nowt
            return

    # Ping ok but previously flagged power off -> require API responding to declare restore
    if state['power_off_notified']:
        data, raw = query_api('{"command":"summary"}')
        if "__error__" in data:
            nowt = time.time()
            if nowt - state['last_power_notify_time'] >= POWER_REMINDER_INTERVAL:
                notify("⚡ POWER REMINDER", f"Miner {MINER_IP} still offline (API not responding).")
                state['last_power_notify_time'] = nowt
            return
        else:
            nowt = time.time()
            state['last_power_restore_time'] = nowt
            state['awaiting_hash_after_restore'] = True
            state['suppress_until'] = nowt + POWER_RECENT_SUPPRESSION
            notify("✅ POWER RESTORED",
                f"Miner {MINER_IP} is fully reachable again (API responding).\n"
                f"Waiting up to {int(POWER_RECENT_SUPPRESSION/60)} minutes for hashing to resume.")
            state['power_off_notified'] = False
            state['last_power_notify_time'] = 0

    # 2) query summary
    data, raw = query_api('{"command":"summary"}')
    if "__error__" in data:
        nowt = time.time()
        if state.get('awaiting_hash_after_restore') and nowt < state.get('suppress_until',0):
            log(f"[TRANSIENT] API query failed after restore; suppressed: {data.get('__error__')}")
            return
        if state.get('last_power_off_time') and (nowt - state.get('last_power_off_time') < POWER_RECENT_SUPPRESSION):
            log(f"[TRANSIENT] API query failed shortly after power off; suppressed: {data.get('__error__')}")
            return
        notify("⚠️ API ERROR", f"Miner reachable by ping, but API query failed:\n{data.get('__error__')}")
        return

    # parse summary & stats
    ghs_30m = None; elapsed=None; fans={}; temp_max=None; boards=[]; boards_summary=""
    try:
        if "SUMMARY" in data and data["SUMMARY"]:
            s = data["SUMMARY"][0]
            # try to extract 30m avg or fallback to any available summary value
            try: ghs_30m = float(s.get("GHS 30m") or s.get("GHS av") or s.get("GHS 5s") or 0)
            except: ghs_30m = 0.0
            try: elapsed = int(s.get("Elapsed") or 0)
            except: elapsed = None

        # fetch stats for per-board info (used to compute realtime hash)
        stats_data, stats_raw = query_api('{"command":"stats"}')
        if isinstance(stats_data, dict) and "STATS" in stats_data and isinstance(stats_data["STATS"], list):
            st = stats_data["STATS"][1] if len(stats_data["STATS"])>1 else stats_data["STATS"][0]
            # fans
            try:
                fan_num = int(st.get("fan_num",0) or 0)
            except:
                fan_num = 0
            for i in range(1, fan_num+1):
                fi = st.get(f"fan{i}")
                if fi is not None:
                    try:
                        fans[f"fan{i}"] = int(fi)
                    except:
                        pass
            # per-board parsing
            for bi in range(1,4):
                inlet=None; outlet=None
                chip_str = st.get(f"temp_chip{bi}")
                if chip_str:
                    try:
                        parts=[p for p in chip_str.split("-") if p.strip().isdigit()]
                        vals=[int(x) for x in parts] if parts else []
                        if vals:
                            inlet=vals[0]; outlet=vals[-1]
                    except:
                        pass
                try:
                    mhs = float(st.get(f"chain_rate{bi}",0) or 0)
                except:
                    mhs = 0.0
                try:
                    chips = int(st.get(f"chain_acn{bi}",77) or 77)
                except:
                    chips = 77
                try:
                    hw_err = int(st.get(f"chain_hw{bi}",0) or 0)
                except:
                    hw_err = 0
                boards.append({
                    "id": bi,
                    "name": f"Board{bi}",
                    "chips": chips,
                    "hw_err": hw_err,
                    "mhs": mhs,       # mhs is likely in MH/s (as reported by many firmwares)
                    "inlet": inlet,
                    "outlet": outlet
                })
            boards_summary = format_boards_summary(boards)
    except Exception as e:
        log("Parse error: " + str(e))

    # compute realtime GH/s from boards (sum of chain_rate mhs -> convert MH/s -> GH/s)
    try:
        realtime_mhs = sum((b.get('mhs') or 0.0) for b in boards)
        realtime_ghs = realtime_mhs / 1000.0  # convert MH/s to GH/s
    except Exception:
        realtime_ghs = None

    elapsed_str = format_elapsed(elapsed) if elapsed is not None else "?"
    if boards_summary:
        log(f"GHS30m={ghs_30m}, realtimeGHs={realtime_ghs}, elapsed={elapsed_str}, fans={format_fans(fans)}\nBoards: {boards_summary}")
    else:
        log(f"GHS30m={ghs_30m}, realtimeGHs={realtime_ghs}, elapsed={elapsed_str}, fans={format_fans(fans)}")

    # scan API raw for tokens (short scan)
    try:
        token = scan_for_errors(raw)
        if token:
            try:
                s0 = data["SUMMARY"][0] if "SUMMARY" in data and data["SUMMARY"] else {}
                ghs = float(s0.get("GHS 30m", s0.get("GHS av", 0)) or 0)
                elapsed2 = int(s0.get("Elapsed", 0) or 0)
                acc = int(s0.get("Accepted", 0) or 0)
                rej = int(s0.get("Rejected", 0) or 0)
            except:
                ghs=None; elapsed2=None; acc=None; rej=None
            short_lines=[]
            if ghs is not None: short_lines.append(f"30m: {ghs:,.2f} GH/s")
            if elapsed2 is not None: short_lines.append(f"Elapsed: {format_elapsed(elapsed2)}")
            if acc is not None and rej is not None: short_lines.append(f"Acc/Rej: {acc}/{rej}")
            short_body = " | ".join(short_lines)
            raw_excerpt = (raw or "")[:400].replace("\n"," ").replace("\r"," ")
            notify(f"⚠️ ERROR: {token.upper()}", f"{short_body}\n\nToken: {token}\nRaw excerpt: {raw_excerpt}")
    except Exception as e:
        log("scan_for_errors(api) error: " + str(e))

    # ------------------- Zero-hash handling & auto-restart decision -------------------
    # Use realtime_ghs primarily for detecting current zero-hash; fallback to ghs_30m if realtime unknown
    current_ghs_to_check = None
    if realtime_ghs is not None:
        current_ghs_to_check = realtime_ghs
    else:
        current_ghs_to_check = ghs_30m

    if current_ghs_to_check is not None and current_ghs_to_check <= GHS_ZERO_THRESHOLD:
        nowt = time.time()
        fans_on = any(v > FAN_ON_THRESHOLD for v in fans.values()) if fans else False

        # gather inlet/outlet values
        inlet_vals = [b['inlet'] for b in boards if b.get('inlet') is not None]
        outlet_vals = [b['outlet'] for b in boards if b.get('outlet') is not None]
        max_temp = None
        temp_ok_for_sleep = False
        if inlet_vals or outlet_vals:
            vals=[]
            if outlet_vals: vals.extend(outlet_vals)
            if inlet_vals: vals.extend(inlet_vals)
            if vals:
                max_temp = max(vals)
            ok = True
            for b in boards:
                bi_ok = False
                if b.get('inlet') is not None and TEMP_SLEEP_MIN <= b['inlet'] <= TEMP_SLEEP_MAX:
                    bi_ok = True
                if b.get('outlet') is not None and TEMP_SLEEP_MIN <= b['outlet'] <= TEMP_SLEEP_MAX:
                    bi_ok = True
                if not bi_ok:
                    ok = False
                    break
            temp_ok_for_sleep = ok

        body_common = (f"Miner: {MINER_IP}\nHashrate (30m): {ghs_30m} GH/s\nRealtime GH/s: {realtime_ghs}\nUptime: {elapsed_str}\nFans: {format_fans(fans)}\nBoards: {boards_summary}\n")

        # If we are in power-restore grace window — special handling
        if state.get('awaiting_hash_after_restore'):
            if current_ghs_to_check > GHS_ZERO_THRESHOLD:
                notify("✅ Miner resumed hashing after power restore", body_common + "\nMiner resumed hashing within the grace period after power restore.")
                state['last_elapsed'] = elapsed
                state['awaiting_hash_after_restore'] = False
                state['suppress_until'] = 0
                state['restart_attempts_for_event'] = 0
                state['last_auto_restart_time'] = 0
                return
            # still in grace window: suppress alerts
            if nowt < state.get('suppress_until',0):
                remaining = int(state['suppress_until'] - nowt)
                log(f"[INFO] Suppressing zero-hash alerts for {remaining}s while waiting for miner to boot after power restore.")
                return
            # grace expired and still zero -> report manual check
            try:
                s0 = data["SUMMARY"][0] if "SUMMARY" in data and data["SUMMARY"] else {}
                accepted = int(s0.get("Accepted",0) or 0)
                rejected = int(s0.get("Rejected",0) or 0)
            except:
                accepted=None; rejected=None
            details = body_common
            if accepted is not None and rejected is not None:
                details += f"\nAcc/Rej: {accepted}/{rejected}"
            details += "\n\nNo hashing after the grace period. Manual inspection required."
            notify("⏳ NO HASH AFTER POWER RESTORE", details)
            state['awaiting_hash_after_restore'] = False
            state['suppress_until'] = 0
            return

        # Normal running-but-not-hashing case:
        if elapsed is None:
            log("Elapsed unknown; sending notification.")
            notify("🛑 ZERO HASH (unknown uptime)", body_common + "\nUptime unknown; manual check required.")
            return

        if elapsed < MIN_UPTIME_BEFORE_AUTO_RESTART:
            log(f"Zero-hash but uptime {elapsed_str} < required {MIN_UPTIME_BEFORE_AUTO_RESTART}s; suppressing.")
            return

        if not fans_on:
            log("Zero-hash but fans are off; notifying.")
            notify("🛑 ZERO HASH (fans off)", body_common + "\nFans appear off. Manual inspection required.")
            return

        if not temp_ok_for_sleep:
            log("Temps not in expected sleep range — notifying for manual inspection.")
            notify("🛑 ZERO HASH (temp mismatch)", body_common + "\nBoard temps not in 30-50°C range; manual inspection recommended.")
            return

        if max_temp is not None and max_temp >= TEMP_HIGH_LIMIT:
            log(f"Temps too high ({max_temp}°C) — blocking auto-restart.")
            notify("🔥 NO AUTO-RESTART (high temp)", body_common + f"\nMax temp {max_temp}°C >= {TEMP_HIGH_LIMIT}°C. Do not auto-restart; inspect cooling.")
            return

        # Check 4-hour gap since last auto restart
        nowt = time.time()
        if nowt - state.get('last_auto_restart_time',0) < RESTART_MIN_INTERVAL:
            rem = int((RESTART_MIN_INTERVAL - (nowt - state['last_auto_restart_time']))/60)
            notify("⚠️ AUTO-RESTART SUPPRESSED (recent restart)", body_common + f"\nA restart was done within the last {RESTART_MIN_INTERVAL//3600} hours. Remaining ~{rem} minutes.")
            return

        if state.get('restart_attempts_for_event',0) >= MAX_RESTART_ATTEMPTS_PER_EVENT:
            notify("⚠️ AUTO-RESTART LIMIT REACHED", body_common + "\nAlready attempted allowed auto-restarts for this event.")
            return

        # Passed all checks: attempt auto-restart
        log("Conditions met for AUTO-RESTART (zero-hash mid-run). Attempting restart.")
        notify("🚨 AUTO-RESTART: Attempting safe restart", body_common + "\nConditions met: zero-hash mid-run, fans on, temps ~30-50°C, uptime >=15m.")
        state['last_restart_attempt_time'] = time.time()
        state['restart_attempts_for_event'] = state.get('restart_attempts_for_event',0) + 1

        if not AUTO_RESTART_ENABLED:
            notify("ℹ️ AUTO-RESTART DISABLED", "Auto-restart is disabled in configuration. Please restart manually.")
            return

        attempted = attempt_restart(trigger="auto", notify_email=True)
        if attempted:
            recovered = wait_for_recovery(timeout=RESTART_TIMEOUT, poll=RESTART_POLL_INTERVAL)
            if recovered:
                notify("✅ AUTO-RESTART SUCCESSFUL", "Auto-restart succeeded and miner resumed hashing.")
                state['restart_attempts_for_event'] = 0
            else:
                notify("❌ AUTO-RESTART FAILED", f"Auto-restart attempted but miner did not resume hashing within {RESTART_TIMEOUT}s.")
        else:
            notify("❌ AUTO-RESTART ATTEMPT FAILED", "Restart attempts (API/HTTP/SSH) all failed. Manual intervention required.")
        return

    # If hashing healthy -> reset counters and handle 'resumed after power restore'
    if current_ghs_to_check is not None and current_ghs_to_check > GHS_ZERO_THRESHOLD:
        if state.get('restart_attempts_for_event',0) != 0:
            log("Miner hashing again; resetting restart attempts.")
        state['restart_attempts_for_event'] = 0
        state['last_auto_restart_time'] = state.get('last_auto_restart_time',0) if state.get('last_auto_restart_time',0) else 0
        if state.get('awaiting_hash_after_restore'):
            notify("✅ Miner resumed hashing after power restore", f"Miner {MINER_IP} resumed hashing: {current_ghs_to_check} GH/s. Uptime: {elapsed_str}\nBoards: {boards_summary}")
            state['last_elapsed'] = elapsed
            state['awaiting_hash_after_restore'] = False
            state['suppress_until'] = 0

    # detect elapsed reset (reboot)
    if elapsed is not None:
        last = state.get('last_elapsed')
        if last is not None and elapsed < last - 10:
            notify("♻️ Miner restarted (elapsed reset)", f"Elapsed changed {format_elapsed(last)} -> {format_elapsed(elapsed)}. Miner likely rebooted.")
        state['last_elapsed'] = elapsed

    # temperature alerts (board-level)
    try:
        nowt = time.time()
        if boards:
            for b in boards:
                bid = b.get("id") or b.get("name","board")
                state['temp_alert_times'].setdefault(str(bid)+"_inlet", 0)
                state['temp_alert_times'].setdefault(str(bid)+"_outlet", 0)
                state['temp_alert_active'].setdefault(str(bid)+"_inlet", False)
                state['temp_alert_active'].setdefault(str(bid)+"_outlet", False)

                inlet = b.get("inlet")
                if inlet is not None and inlet >= TEMP_HIGH_LIMIT:
                    key = str(bid)+"_inlet"
                    if nowt - state['temp_alert_times'][key] >= 30*60:
                        state['temp_alert_times'][key] = nowt
                        state['temp_alert_active'][key] = True
                        notify("🔥 TEMPERATURE ALERT", f"Board {b.get('name')} inlet = {inlet}°C (threshold {TEMP_HIGH_LIMIT}°C)\n\nFans: {format_fans(fans)}\nBoards: {boards_summary}")
                else:
                    key = str(bid)+"_inlet"
                    if state['temp_alert_active'].get(key):
                        state['temp_alert_active'][key] = False
                        notify("✅ TEMP OK", f"Board {b.get('name')} inlet now = {inlet}°C (below {TEMP_HIGH_LIMIT}°C)\n\nFans: {format_fans(fans)}\nBoards: {boards_summary}")

                outlet = b.get("outlet")
                if outlet is not None and outlet >= TEMP_HIGH_LIMIT:
                    key = str(bid)+"_outlet"
                    if nowt - state['temp_alert_times'][key] >= 30*60:
                        state['temp_alert_times'][key] = nowt
                        state['temp_alert_active'][key] = True
                        notify("🔥 TEMPERATURE ALERT", f"Board {b.get('name')} outlet = {outlet}°C (threshold {TEMP_HIGH_LIMIT}°C)\n\nFans: {format_fans(fans)}\nBoards: {boards_summary}")
                else:
                    key = str(bid)+"_outlet"
                    if state['temp_alert_active'].get(key):
                        state['temp_alert_active'][key] = False
                        notify("✅ TEMP OK", f"Board {b.get('name')} outlet now = {outlet}°C (below {TEMP_HIGH_LIMIT}°C)\n\nFans: {format_fans(fans)}\nBoards: {boards_summary}")
    except Exception as e:
        log("Temp-alert check error: " + str(e))

# ---------------- Wait for recovery helper ----------------
def wait_for_recovery(timeout=RESTART_TIMEOUT, poll=RESTART_POLL_INTERVAL, ghs_threshold=1.0):
    """
    Poll until the miner's realtime GH/s >= ghs_threshold or timeout.
    Returns True if recovered.
    """
    start = time.time()
    while time.time() - start < timeout:
        try:
            process_telegram_commands()
        except Exception:
            log("process_telegram_commands (during recovery) error: " + traceback.format_exc())
        # query summary and stats to compute realtime
        data, raw = query_api('{"command":"summary"}')
        if "__error__" not in data:
            # try to get realtime from stats
            stats_data, stats_raw = query_api('{"command":"stats"}')
            realtime = None
            try:
                if isinstance(stats_data, dict) and "STATS" in stats_data and isinstance(stats_data["STATS"], list):
                    st = stats_data["STATS"][1] if len(stats_data["STATS"])>1 else stats_data["STATS"][0]
                    mhs_sum = 0.0
                    for bi in range(1,4):
                        try:
                            mhs_sum += float(st.get(f"chain_rate{bi}",0) or 0.0)
                        except:
                            pass
                    realtime = mhs_sum / 1000.0  # MH/s -> GH/s
            except Exception:
                pass
            # also check SUMMARY's GHS 5s or 30m if realtime not available
            try:
                ghs30 = float(data["SUMMARY"][0].get("GHS 30m") or data["SUMMARY"][0].get("GHS av") or data["SUMMARY"][0].get("GHS 5s") or 0)
            except:
                ghs30 = 0.0
            cur = realtime if realtime is not None else ghs30
            log(f"Recovery poll: realtime GH/s = {realtime}, summary GH/s = {ghs30}")
            if cur is not None and cur >= ghs_threshold:
                return True
        time.sleep(max(1.0, poll))
    return False

# (We keep the earlier quick_status_payload implementation; to avoid duplication we reuse its name)
# Note: above we already defined quick_status_payload earlier; ensure correct binding - it's fine.

# ---------------- Main ----------------
def main():
    if not HAS_PARAMIKO:
        log("Paramiko not installed - SSH log/restart disabled.")
    log(f"Starting miner_watchman (AUTO_RESTART_ENABLED={AUTO_RESTART_ENABLED}, DRY_RUN={DRY_RUN}) for {MINER_IP}")
    while True:
        try:
            process_telegram_commands()
            check_cycle()
        except Exception:
            log("Exception in main cycle:\n" + traceback.format_exc())
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
