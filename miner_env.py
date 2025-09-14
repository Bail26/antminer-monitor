#!/usr/bin/env python3
"""
miner.py - Watchman for Antminer (sanitized)

Configuration is read from environment variables or a .env file (use python-dotenv).
Set variables in a local .env (DO NOT commit .env to repo).
"""

import os
from dotenv import load_dotenv
load_dotenv()

import socket, json, time, subprocess, sys, traceback
from datetime import datetime
import requests
from requests.auth import HTTPDigestAuth
from email.mime.text import MIMEText
import smtplib
import logging
from logging.handlers import RotatingFileHandler

# Optional SSH
try:
    import paramiko
    HAS_PARAMIKO = True
except Exception:
    HAS_PARAMIKO = False

# ===================== CONFIG (loaded from env) =====================
MINER_IP = os.getenv("MINER_IP", "192.168.1.31")
API_PORT = int(os.getenv("API_PORT", "4028"))
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "60"))

# Telegram (bot)
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

# Email (optional - App password recommended for Gmail)
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
EMAIL_TO = os.getenv("EMAIL_TO", "")   # leave empty to disable email alerts

# Auto-restart policy
AUTO_RESTART_ENABLED = os.getenv("AUTO_RESTART_ENABLED", "true").lower() in ("1","true","yes")
RESTART_MIN_INTERVAL = int(os.getenv("RESTART_MIN_INTERVAL", str(4 * 3600)))
RESTART_TIMEOUT = int(os.getenv("RESTART_TIMEOUT", "300"))
RESTART_POLL_INTERVAL = int(os.getenv("RESTART_POLL_INTERVAL", "15"))
MAX_RESTART_ATTEMPTS_PER_EVENT = int(os.getenv("MAX_RESTART_ATTEMPTS_PER_EVENT", "1"))

# Zero-hash thresholds and sleep window
GHS_ZERO_THRESHOLD = float(os.getenv("GHS_ZERO_THRESHOLD", "0.001"))
TEMP_SLEEP_MIN = int(os.getenv("TEMP_SLEEP_MIN", "30"))
TEMP_SLEEP_MAX = int(os.getenv("TEMP_SLEEP_MAX", "50"))
TEMP_HIGH_LIMIT = int(os.getenv("TEMP_HIGH_LIMIT", "75"))
FAN_ON_THRESHOLD = int(os.getenv("FAN_ON_THRESHOLD", "1"))

# Uptime & power rules
MIN_UPTIME_BEFORE_AUTO_RESTART = int(os.getenv("MIN_UPTIME_BEFORE_AUTO_RESTART", str(15 * 60)))
POWER_RECENT_SUPPRESSION = int(os.getenv("POWER_RECENT_SUPPRESSION", str(10 * 60)))
POWER_REMINDER_INTERVAL = int(os.getenv("POWER_REMINDER_INTERVAL", str(5 * 60)))

# HTTP/SSH credentials for fallback
RESTART_HTTP_USERNAME = os.getenv("RESTART_HTTP_USERNAME", "root")
RESTART_HTTP_PASSWORD = os.getenv("RESTART_HTTP_PASSWORD", "root")
SSH_USERNAME = os.getenv("SSH_USERNAME", "root")
SSH_PASSWORD = os.getenv("SSH_PASSWORD", "root")
SSH_PORT = int(os.getenv("SSH_PORT", "22"))
SSH_TIMEOUT = int(os.getenv("SSH_TIMEOUT", "10"))

REBOOT_SUPPRESS_WINDOW = int(os.getenv("REBOOT_SUPPRESS_WINDOW", "180"))
DRY_RUN = os.getenv("DRY_RUN", "false").lower() in ("1","true","yes")

# Logging rotation
LOGFILE = os.getenv("LOGFILE", "miner_watchman.log")
LOG_MAX_BYTES = int(os.getenv("LOG_MAX_BYTES", str(5 * 1024 * 1024)))
LOG_BACKUP_COUNT = int(os.getenv("LOG_BACKUP_COUNT", "7"))
# ==================================================

# ---------- Logging ----------
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
        print(f\"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}\")

def now(): return datetime.now().strftime(\"%Y-%m-%d %H:%M:%S\")\n
# NOTE: The full original logic (API parsing, restarts, Telegram polling) should be pasted below.
# For now this sanitized starter will implement basic status ping and Telegram notification helpers.
import time

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
        log(\"Telegram error (to chat): \" + str(e))
        return False

def send_telegram(text):
    return send_telegram_to(TELEGRAM_CHAT_ID, text)

def ping(host, timeout=2):
    try:
        if sys.platform.startswith(\"win\"):
            cmd = [\"ping\", \"-n\", \"1\", \"-w\", str(int(timeout*1000)), host]
        else:
            cmd = [\"ping\", \"-c\", \"1\", \"-W\", str(int(timeout)), host]
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return res.returncode == 0
    except Exception as e:
        log(\"Ping error: \" + str(e))
        return False

def quick_status_payload():
    ping_ok = ping(MINER_IP)
    if not ping_ok:
        return \"🔴 Miner OFFLINE (ping failed).\"
    return \"✅ Miner ONLINE (ping OK). For full status, paste the original detailed logic into this file.\"

def process_telegram_commands():
    if not TELEGRAM_TOKEN:
        return
    try:
        offset = 0
        url = f\"https://api.telegram.org/bot{TELEGRAM_TOKEN}/getUpdates\"
        r = requests.get(url, params={\"offset\": offset, \"timeout\": 0}, timeout=5)
        if r.status_code != 200:
            return
        data = r.json()
        if not data.get(\"ok\"): return
        updates = data.get(\"result\", [])
        for upd in updates:
            msg = upd.get(\"message\") or upd.get(\"edited_message\")
            if not msg: continue
            chat = msg.get(\"chat\", {})
            chat_id = chat.get(\"id\")
            text = (msg.get(\"text\") or \"\").strip()
            if not text: continue
            cmd = text.split()[0].lower()
            if cmd == \"/status\":
                payload = quick_status_payload()
                send_telegram_to(chat_id, payload)
            elif cmd == \"/help\":
                send_telegram_to(chat_id, \"/status - status\\n/help - this help\\n/restart - not implemented in sanitized version\")
            elif cmd == \"/restart\":
                send_telegram_to(chat_id, \"Restart command received, but not enabled in sanitized starter.\")
    except Exception as e:
        log(\"process_telegram_commands error: \" + str(e))

def main():
    log(f\"Starting sanitized miner_watchman for {MINER_IP}\")
    while True:
        try:
            process_telegram_commands()
            # simplified loop: ping and optionally send heartbeat
            if os.getenv('SEND_HEARTBEAT','false').lower() in ('1','true','yes'):
                if not ping(MINER_IP):
                    send_telegram(f\"⚠️ Miner {MINER_IP} is offline (ping failed).\" )
        except Exception:
            log(\"Exception in main cycle:\\n\" + traceback.format_exc())
        time.sleep(POLL_INTERVAL)

if __name__ == \"__main__\":
    main()
