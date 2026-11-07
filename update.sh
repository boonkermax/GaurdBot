#!/usr/bin/env bash
# Pull the latest code from GitHub and restart the bot. The database (guardbot.db) and .env are untouched.
set -euo pipefail
cd "$(dirname "$0")"
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
git pull --ff-only
./venv/bin/pip install -q -r requirements.txt
./venv/bin/python -m py_compile guardbot.py   # refuse to restart on a syntax error
$SUDO systemctl restart guardbot
sleep 3
$SUDO systemctl --no-pager --lines=8 status guardbot || true
