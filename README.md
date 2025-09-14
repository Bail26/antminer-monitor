# B@IL — Antminer Monitor (CGIMiner)

> Remote monitor for CGIminer-based Antminers. Telegram commands + email alerts, with safe auto-restart logic.

![B@IL Logo Placeholder](assets/logo.png)

## Quick summary
Single-file Python monitor: **`miner.py`**.  
Runs on any machine on the *same LAN* as the miner (Raspberry Pi recommended). Polls CGIminer API, sends Telegram + optional Gmail alerts, and can attempt safe restarts via API / HTTP / SSH.

---

## Features
- Telegram commands: `/status`, `/restart`, `/help`
- Alerts: power cut/restore, API errors, zero-hash, fan/temp issues
- Auto-restart policy (API → HTTP → SSH) with suppression & limits
- Minimal dependencies. Runs 24/7 as a service (systemd recommended).

---

## Quick start (3 steps)
1. Install Python 3 (on Raspberry Pi: `sudo apt update && sudo apt install -y python3 python3-venv python3-pip`)
2. Add your credentials (Telegram token, chat id, SMTP app password) to a `.env` (see `.env.example`)
3. Run:
```bash
python3 miner.py
```

---

## Recommended files to add to this repo
- `miner.py` (already present)
- `.env.example` (copy/paste the example and fill values locally)
- `requirements.txt`
- `.gitignore`
- `systemd/antminer-monitor.service` (optional — for running on boot)
- `assets/` (logo + demo GIF)

---

## .env.example (DO NOT commit actual secrets)
```
# Network
MINER_IP=192.168.1.31
API_PORT=4028
POLL_INTERVAL=60

# Telegram
TELEGRAM_TOKEN=123456:ABC-DEF...
TELEGRAM_CHAT_ID=123456789

# Email (optional - use Gmail App Password)
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=youremail@gmail.com
SMTP_PASS=abcdefghijklmnop
EMAIL_TO=notifyto@example.com

# Auto restart
AUTO_RESTART_ENABLED=true
RESTART_MIN_INTERVAL=14400
RESTART_TIMEOUT=300

# Misc
DRY_RUN=false
LOGFILE=miner_watchman.log
```
---

## Dependencies
Create a venv and install:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

`requirements.txt` (add this file):
```
requests
paramiko
python-dotenv
```

`python-dotenv` is optional but recommended if you modify `miner.py` to load `.env` variables.

---

## How to get your Telegram bot token & chat id
1. Chat with `@BotFather` on Telegram → `/newbot` → follow prompts → you get `BOT_TOKEN`.
2. Start a chat with the bot (or add it to a group). Then run:
```bash
curl -s "https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates" | jq .
```
Look for `"chat": {"id": 123456789, ...}` — that number is `TELEGRAM_CHAT_ID`.

---

## How to create a Gmail app password (for SMTP)
1. Enable **2-Step Verification** for the Google account.
2. Go to Google Account → Security → App passwords → create one for Mail → copy the 16-char password.
3. Put it in `SMTP_PASS` and keep real account out of repo.

---

## Run as a systemd service (recommended for Raspberry Pi)
/etc/systemd/system/antminer-monitor.service:
```ini
[Unit]
Description=B@IL Antminer Monitor
After=network.target

[Service]
User=pi
WorkingDirectory=/home/pi/antminer-monitor
ExecStart=/home/pi/antminer-monitor/venv/bin/python /home/pi/antminer-monitor/miner.py
Restart=always
RestartSec=10
EnvironmentFile=/home/pi/antminer-monitor/.env

[Install]
WantedBy=multi-user.target
```

Commands:
```bash
sudo systemctl daemon-reload
sudo systemctl enable antminer-monitor.service
sudo systemctl start antminer-monitor.service
sudo journalctl -u antminer-monitor -f
```

---

## Security notes
- **Never** commit real tokens or passwords. Use `.env` and add it to `.gitignore`.
- Rotate tokens/passwords if leaked.
- Optionally use GitHub Secrets/CI for automation.

---

## Troubleshooting
- Check `miner_watchman.log` (or systemd journal) for errors.
- If Telegram messages don’t appear, check bot token and chat id.
- If email fails, verify SMTP credentials and app password.

---

## License
MIT — see `LICENSE` file.

---

Made with ❤️ by B@IL — turning hard things easy.