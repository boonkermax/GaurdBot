# GuardBot

Telegram security bot: shield toggles, auto delete, premium clones, log channel, owner broadcast.

## First setup on the VPS (once)
```bash
sudo apt update && sudo apt install -y git python3-venv
sudo git clone https://github.com/YOU/guardbot.git /opt/guardbot   # private repo: use a deploy key or token URL
sudo chown -R $USER /opt/guardbot && cd /opt/guardbot
python3 -m venv venv && ./venv/bin/pip install -r requirements.txt
cp .env.example .env && nano .env            # fill BOT_TOKEN, DEV_IDS, ...
sudo cp guardbot.service /etc/systemd/system/ && sudo nano /etc/systemd/system/guardbot.service   # set User=
sudo systemctl daemon-reload && sudo systemctl enable --now guardbot
journalctl -u guardbot -f                    # live logs
```

## Shipping updates
1. Edit, commit, push to `main`.
2. Either run `./update.sh` on the VPS, or add the three repo secrets (`VPS_HOST`, `VPS_USER`, `VPS_SSH_KEY`)
   and the included GitHub Action deploys on every push.

`update.sh` checks the code compiles before restarting. `guardbot.db` (all settings, chats, premium, clones, pending
auto-deletes) lives on the VPS and is not in git. Back it up now and then: `cp guardbot.db guardbot.db.bak`.

## Notes
- Clone tokens are stored in `guardbot.db`: keep the file private. If a token leaks, revoke it in @BotFather.
- Every clone runs inside the same process (about 30-50 MB each); `MAX_CLONES` caps it for a 1 GB VPS.
- Grant premium from the bot: /start -> 👑 Owner Panel -> 💎 Grant Premium.
