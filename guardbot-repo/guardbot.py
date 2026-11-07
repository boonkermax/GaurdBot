"""
GuardBot – security panel, auto delete, premium clones  (python-telegram-bot v21)

Private chat
  /start  -> media + "Advanced Security Panel": 🔴/🟢 shield toggles, 🕒 Auto Delete, 🤖 Clone Bot
  /scan   -> connected chats and whether the bot has the rights it needs
  /stats  -> total connected chats/groups (owner sees full detailed stats)
  Owner-only button "👑 Owner Panel": full stats, broadcast, grant/revoke premium, clones
In groups/channels
  When added, the bot posts a configuration message (open settings here / in private chat).
  Settings opened there apply to that chat only; the private panel is the default for all of
  your chats.

Install:  pip install -r requirements.txt
Env:      see .env.example
Run:      python guardbot.py
"""
import asyncio
import html
import json
import logging
import os
import re
import sqlite3
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import httpx
from telegram import (
    Bot,
    BotCommand,
    ChatPermissions,
    InlineKeyboardButton as Btn,
    InlineKeyboardMarkup as Markup,
    MessageEntity,
    Update,
)
from telegram.constants import ChatMemberStatus as S, ChatType, ParseMode
from telegram.error import BadRequest, Forbidden, RetryAfter, TelegramError
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    ChatMemberHandler,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("guardbot")

TOKEN = os.environ["BOT_TOKEN"]
DEV_IDS = {int(x) for x in os.environ["DEV_IDS"].split(",") if x.strip()}
LOG_CHANNEL_ID = int(os.getenv("LOG_CHANNEL_ID") or 0)
SE_USER = os.getenv("SIGHTENGINE_USER")
SE_SECRET = os.getenv("SIGHTENGINE_SECRET")
DAILY_LIMIT = int(os.getenv("SCAN_DAILY_LIMIT", "450"))       # free plan: 500/day
MONTHLY_LIMIT = int(os.getenv("SCAN_MONTHLY_LIMIT", "1900"))  # free plan: 2000/month
NSFW_T = float(os.getenv("NSFW_THRESHOLD", "0.7"))
GORE_T = float(os.getenv("GORE_THRESHOLD", "0.7"))
TRIAL_DAYS = int(os.getenv("TRIAL_DAYS", "7"))
MAX_CLONES = int(os.getenv("MAX_CLONES", "10"))
PREMIUM_CONTACT = os.getenv("PREMIUM_CONTACT", "")
DB_PATH = os.getenv("DB_PATH", "guardbot.db")
API_URL = "https://api.sightengine.com/1.0/check.json"
API_MODELS = {"porn": "nudity-2.1", "violence": "gore-2.0"}

SHIELDS = [
    ("spam", "Anti-Spam"),
    ("copyright", "Copyright Shield"),
    ("porn", "Porn Block"),
    ("violence", "Violence Filter"),
    ("fake", "Fake Content"),
    ("competitor", "Competitor Attack"),
]
LABELS = dict(SHIELDS)
TIMES = [(30, "30s"), (60, "1m"), (300, "5m"), (600, "10m"), (1800, "30m"), (3600, "1h"), (10800, "3h"), (43200, "12h"), (86400, "24h")]
TIME_SECS = {s for s, _ in TIMES}

# Edit these lists to taste
COPYRIGHT_WORDS = (
    "webrip", "web-dl", "hdrip", "camrip", "hdcam", "dvdrip", "brrip", "bluray",
    "1080p", "720p", "480p", "x264", "x265", "hevc", "torrent", "full movie",
)
SCAM_WORDS = (
    "double your", "guaranteed profit", "send btc", "send usdt", "recovery expert",
    "dm me to earn", "verify your wallet", "claim your reward", "forex signal", "profit daily",
)
IMPERSONATE_RE = re.compile(r"\b(admin|support|official|moderator)\b", re.I)
INVITE_RE = re.compile(r"(t\.me/\+|t\.me/joinchat|telegram\.me/joinchat)", re.I)
TOKEN_RE = re.compile(r"^\d{6,12}:[A-Za-z0-9_-]{30,}$")

# ───────────────────────── database ─────────────────────────
db = sqlite3.connect(DB_PATH)
db.executescript(
    """
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY);
CREATE TABLE IF NOT EXISTS chats(id INTEGER PRIMARY KEY, title TEXT, kind TEXT, owner_id INTEGER);
CREATE TABLE IF NOT EXISTS flags(owner_id INTEGER PRIMARY KEY, data TEXT);
CREATE TABLE IF NOT EXISTS lists(id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER, kind TEXT, value TEXT);
CREATE TABLE IF NOT EXISTS counters(owner_id INTEGER, shield TEXT, n INTEGER DEFAULT 0, PRIMARY KEY(owner_id, shield));
CREATE TABLE IF NOT EXISTS settings(k TEXT PRIMARY KEY, v TEXT);
CREATE TABLE IF NOT EXISTS bchats(chat_id INTEGER, bot_key INTEGER, title TEXT, kind TEXT, owner_id INTEGER, flags TEXT, PRIMARY KEY(chat_id, bot_key));
CREATE TABLE IF NOT EXISTS premium(user_id INTEGER PRIMARY KEY, until INTEGER);
CREATE TABLE IF NOT EXISTS clones(owner_id INTEGER PRIMARY KEY, token TEXT, bot_id INTEGER, username TEXT, trial_end INTEGER, active INTEGER, created INTEGER);
CREATE TABLE IF NOT EXISTS pending_del(chat_id INTEGER, bot_key INTEGER, msg_id INTEGER, due INTEGER);
CREATE INDEX IF NOT EXISTS pd_due ON pending_del(due);
"""
)


def q(sql, args=()):
    cur = db.execute(sql, args)
    db.commit()
    return cur


def get_setting(k, default=""):
    r = q("SELECT v FROM settings WHERE k=?", (k,)).fetchone()
    return r[0] if r else default


def set_setting(k, v):
    q("INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))


# one-time migration of chats connected before clones existed (they belong to the main bot, key 0)
if not get_setting("migrated_v2"):
    q("INSERT OR IGNORE INTO bchats(chat_id,bot_key,title,kind,owner_id) SELECT id,0,title,kind,owner_id FROM chats")
    set_setting("migrated_v2", "1")

MAIN_ID = 0
BOTS = {}      # bot_key -> Bot   (0 = main bot, clones use their own bot id)
RUNNING = {}   # owner_id -> clone Application


def bkey(bot):
    return 0 if bot.id == MAIN_ID else bot.id


def esc(t):
    return html.escape(t or "")


def mention(u):
    return f'<a href="tg://user?id={u.id}">{esc(u.full_name)}</a>'


def fmt_secs(s):
    return f"{s}s" if s < 60 else f"{s // 60}m" if s < 3600 else f"{s // 3600}h"


def fmt_date(ts):
    return time.strftime("%d %b %Y", time.gmtime(ts)) + " UTC"


# ───────────────────────── settings storage ─────────────────────────
def owner_flags(uid):
    r = q("SELECT data FROM flags WHERE owner_id=?", (uid,)).fetchone()
    return json.loads(r[0]) if r else {}


def save_flags(uid, fl):
    q("INSERT INTO flags(owner_id,data) VALUES(?,?) ON CONFLICT(owner_id) DO UPDATE SET data=excluded.data", (uid, json.dumps(fl)))


def chat_row(chat_id, bk):
    """(owner_id, flags_json, kind, title) or None"""
    return q("SELECT owner_id,flags,kind,title FROM bchats WHERE chat_id=? AND bot_key=?", (chat_id, bk)).fetchone()


def chat_flags(chat_id, bk):
    row = chat_row(chat_id, bk)
    if not row:
        return {}
    return json.loads(row[1]) if row[1] else owner_flags(row[0])


def scope_flags(scope, bot, uid):
    return owner_flags(uid) if scope == "o" else chat_flags(int(scope[1:]), bkey(bot))


def scope_set(scope, bot, uid, updates):
    """scope 'o' = your default for all chats (also applied to chats with their own overrides);
    scope 'c<id>' = that chat only."""
    bk = bkey(bot)
    if scope == "o":
        fl = owner_flags(uid)
        fl.update(updates)
        save_flags(uid, fl)
        for cid, fj in q("SELECT chat_id,flags FROM bchats WHERE owner_id=? AND bot_key=? AND flags IS NOT NULL", (uid, bk)).fetchall():
            cf = json.loads(fj)
            cf.update(updates)
            q("UPDATE bchats SET flags=? WHERE chat_id=? AND bot_key=?", (json.dumps(cf), cid, bk))
        return fl
    cid = int(scope[1:])
    fl = chat_flags(cid, bk)
    fl.update(updates)
    q("UPDATE bchats SET flags=? WHERE chat_id=? AND bot_key=?", (json.dumps(fl), cid, bk))
    return fl


def bump(uid, shield):
    q("INSERT INTO counters(owner_id,shield,n) VALUES(?,?,1) ON CONFLICT(owner_id,shield) DO UPDATE SET n=n+1", (uid, shield))


def is_premium(uid):
    if uid in DEV_IDS:
        return True
    r = q("SELECT until FROM premium WHERE user_id=?", (uid,)).fetchone()
    return bool(r and r[0] > time.time())


# ───────────────────────── log channel ─────────────────────────
async def log_event(text):
    bot = BOTS.get(0)
    if not LOG_CHANNEL_ID or not bot:
        return
    try:
        await bot.send_message(LOG_CHANNEL_ID, text, parse_mode=ParseMode.HTML, disable_web_page_preview=True)
    except TelegramError as e:
        log.warning("log channel failed: %s", e)


# ───────────────────────── panel UI ─────────────────────────
def panel_view(scope, fl, uid):
    n = sum(1 for k, _ in SHIELDS if fl.get(k))
    if n:
        status = f"Your connected chats are protected against <b>{n}</b> type{'s' if n != 1 else ''} of threats."
    else:
        status = "Your connected chats are <b>not protected yet</b>."
    text = (
        "🛡 <b>ADVANCED SECURITY PANEL</b>\n\n"
        f"👥 <b>Active Shields: {n}</b> {'🟢' if n else '🔴'}\n\n"
        f"<i>{status}</i>\n\n"
        "📣 <b>Toggle Your Preferred Protections Below:</b>"
    )
    if scope != "o":
        text += "\n\n📍 <i>These settings apply to this chat only.</i>"
    rows, pair = [], []
    for key, label in SHIELDS:
        state = "🟢 ON" if fl.get(key) else "🔴 OFF"
        pair.append(Btn(f"{state} | {label}", callback_data=f"tg:{scope}:{key}"))
        if len(pair) == 2:
            rows.append(pair)
            pair = []
    ad = f"ON {fmt_secs(fl.get('autodel_secs', 600))}" if fl.get("autodel") else "OFF"
    row = [Btn(f"🕒 Auto Delete: {ad}", callback_data=f"ad:{scope}")]
    if scope == "o":
        row.append(Btn("🤖 Clone Bot", callback_data="cl"))
    rows.append(row)
    if scope == "o" and uid in DEV_IDS:
        rows.append([Btn("👑 Owner Panel", callback_data="ow")])
    rows.append([Btn("🔙 Back", callback_data="hm" if scope == "o" else f"cf:{scope[1:]}")])
    return text, Markup(rows)


def ad_view(scope, fl):
    on, secs = fl.get("autodel"), fl.get("autodel_secs", 600)
    text = (
        "🕒 <b>AUTO DELETE</b>\n\n"
        "Deletes messages from non-admins in groups after the time you pick.\n\n"
        f"Status: {'🟢 <b>ON</b> – every ' + fmt_secs(secs) if on else '🔴 <b>OFF</b>'}"
    )
    rows = [[Btn(f"{'🟢 ON' if on else '🔴 OFF'} | Auto Delete", callback_data=f"ao:{scope}")]]
    row = []
    for s, lab in TIMES:
        row.append(Btn(("✅ " if s == secs else "") + lab, callback_data=f"at:{scope}:{s}"))
        if len(row) == 3:
            rows.append(row)
            row = []
    rows.append([Btn("🔙 Back", callback_data=f"pn:{scope}")])
    return text, Markup(rows)


def home_view(bot_username):
    text = (
        "🛡 <b>Welcome to GuardBot</b>\n\n"
        "Add me as admin to your groups and channels, then switch on the shields you want.\n\n"
        "📡 /scan – check connected chats\n📊 /stats – statistics"
    )
    grp = f"https://t.me/{bot_username}?startgroup=true&admin=delete_messages+restrict_members+invite_users"
    chn = f"https://t.me/{bot_username}?startchannel=true&admin=post_messages+edit_messages+delete_messages"
    return text, Markup(
        [
            [Btn("🛡 Security Panel", callback_data="pn:o")],
            [Btn("➕ Add to Group", url=grp), Btn("➕ Add to Channel", url=chn)],
        ]
    )


def cf_view(bot_username, chat_id, kind):
    what = "channel" if kind == "channel" else "group"
    text = (
        "🛡 <b>GuardBot connected!</b>\n\n"
        f"⚙️ Choose the protections for this {what}.\n"
        "Open the settings here or in a private chat 👇\n\n"
        "<i>Only admins can change settings.</i>"
    )
    return text, Markup(
        [
            [Btn("⚙️ Open settings here", callback_data=f"pn:c{chat_id}")],
            [Btn("💬 Open in private chat", url=f"https://t.me/{bot_username}?start=settings")],
        ]
    )


def panel_media():
    v = get_setting("panel_media")
    return tuple(v.split(":", 1)) if ":" in v else None


async def send_panel(bot, uid):
    text, markup = panel_view("o", owner_flags(uid), uid)
    m = panel_media()
    kw = dict(chat_id=uid, parse_mode=ParseMode.HTML, reply_markup=markup)
    if m:
        kind, fid = m
        if kind == "video":
            return await bot.send_video(video=fid, caption=text, **kw)
        if kind == "animation":
            return await bot.send_animation(animation=fid, caption=text, **kw)
        return await bot.send_photo(photo=fid, caption=text, **kw)
    return await bot.send_message(text=text, **kw)


async def send_home(bot, uid):
    text, markup = home_view(bot.username)
    m = panel_media()
    kw = dict(chat_id=uid, parse_mode=ParseMode.HTML, reply_markup=markup)
    if m:
        kind, fid = m
        if kind == "video":
            return await bot.send_video(video=fid, caption=text, **kw)
        if kind == "animation":
            return await bot.send_animation(animation=fid, caption=text, **kw)
        return await bot.send_photo(photo=fid, caption=text, **kw)
    return await bot.send_message(text=text, **kw)


async def edit_msg(qy, text, markup):
    try:
        if qy.message.text is not None:
            await qy.edit_message_text(text, parse_mode=ParseMode.HTML, reply_markup=markup)
        else:
            await qy.edit_message_caption(caption=text, parse_mode=ParseMode.HTML, reply_markup=markup)
    except BadRequest as e:
        if "not modified" not in str(e).lower():
            raise


# ───────────────────────── premium + clone views ─────────────────────────
def clone_allowed(uid):
    if is_premium(uid):
        return True, ""
    if q("SELECT 1 FROM clones WHERE owner_id=?", (uid,)).fetchone():
        return False, "Your free trial has ended. Premium is required to run a clone."
    return True, ""


def clone_view(uid):
    row = q("SELECT username,trial_end,active,token FROM clones WHERE owner_id=?", (uid,)).fetchone()
    prem = is_premium(uid)
    until = (q("SELECT until FROM premium WHERE user_id=?", (uid,)).fetchone() or [0])[0]
    if uid in DEV_IDS:
        plan = "👑 Owner – unlimited"
    elif prem:
        plan = f"💎 Premium until {fmt_date(until)}"
    elif row:
        plan = "⏰ Free trial used"
    else:
        plan = f"🎁 Free {TRIAL_DAYS}-day trial available"
    lines = [
        "🤖 <b>CLONE BOT</b>\n",
        "Run your own copy of this bot with your own token – same panel, shields and auto delete.\n",
        f"Plan: {plan}",
    ]
    rows = []
    has = bool(row and row[3])
    if has and row[2]:
        end = "" if prem else f" · trial ends {fmt_date(row[1])}"
        lines.append(f"\n✅ <b>@{esc(row[0])}</b> is running{end}")
        rows.append([Btn("🗑 Remove Clone", callback_data="cl_rm")])
    elif has:
        lines.append(f"\n⏹ <b>@{esc(row[0])}</b> is stopped")
        if prem:
            rows.append([Btn("▶️ Restart Clone", callback_data="cl_go")])
        rows.append([Btn("🗑 Remove Clone", callback_data="cl_rm")])
    else:
        if clone_allowed(uid)[0]:
            rows.append([Btn("➕ Create Clone" if prem else f"🎁 Start {TRIAL_DAYS}-day Free Trial", callback_data="cl_new")])
        else:
            lines.append("\n🔒 Premium is required." + (f" Contact {esc(PREMIUM_CONTACT)}." if PREMIUM_CONTACT else ""))
    if not prem and has and not row[2]:
        lines.append("\n🔒 Get premium to restart it." + (f" Contact {esc(PREMIUM_CONTACT)}." if PREMIUM_CONTACT else ""))
    rows.append([Btn("🔙 Back", callback_data="pn:o")])
    return "\n".join(lines), Markup(rows)


def owner_view():
    text = "👑 <b>OWNER PANEL</b>\n\nFull control of the bot."
    return text, Markup(
        [
            [Btn("📊 Full Stats", callback_data="ow_stats"), Btn("📣 Broadcast", callback_data="ow_bc")],
            [Btn("💎 Grant Premium", callback_data="ow_gp"), Btn("🚫 Revoke Premium", callback_data="ow_rp")],
            [Btn("🤖 Clones", callback_data="ow_cl")],
            [Btn("🔙 Back", callback_data="pn:o")],
        ]
    )


BACK_OW = Markup([[Btn("🔙 Back", callback_data="ow")]])


def full_stats():
    def c(sql, args=()):
        return q(sql, args).fetchone()[0]

    day = time.strftime("%Y-%m-%d", time.gmtime())
    now = int(time.time())
    by = dict(q("SELECT shield,SUM(n) FROM counters GROUP BY shield").fetchall())
    lines = "\n".join(f"• {label}: <b>{by.get(k, 0)}</b>" for k, label in SHIELDS)
    users = c("SELECT COUNT(*) FROM users")
    chats = c("SELECT COUNT(*) FROM bchats")
    groups = c("SELECT COUNT(*) FROM bchats WHERE kind IN ('group','supergroup')")
    channels = c("SELECT COUNT(*) FROM bchats WHERE kind='channel'")
    prem = c("SELECT COUNT(*) FROM premium WHERE until>?", (now,))
    clones = c("SELECT COUNT(*) FROM clones WHERE token!=''")
    pending = c("SELECT COUNT(*) FROM pending_del")
    return (
        "📊 <b>Full statistics</b>\n\n"
        f"👤 Users: <b>{users}</b>\n"
        f"📡 Connected chats: <b>{chats}</b>\n"
        f"👥 Groups: <b>{groups}</b> · 📣 Channels: <b>{channels}</b>\n"
        f"💎 Premium users: <b>{prem}</b>\n"
        f"🤖 Clones: <b>{len(RUNNING)}</b> running / {clones} total\n"
        f"🕒 Pending auto-deletes: <b>{pending}</b>\n\n"
        f"<b>Threats removed</b>\n{lines}\n\n"
        f"🔍 Image scans: {get_setting('scan:' + day, '0')}/{DAILY_LIMIT} today · "
        f"{get_setting('scan:' + day[:7], '0')}/{MONTHLY_LIMIT} this month"
    )


def clones_text():
    rows = q("SELECT owner_id,username,active,trial_end FROM clones WHERE token!='' ORDER BY created DESC LIMIT 20").fetchall()
    if not rows:
        return "🤖 <b>Clones</b>\n\nNone yet."
    out = []
    for oid, un, act, te in rows:
        kind = "💎" if is_premium(oid) else "🎁"
        out.append(f"{'✅' if act else '⏹'} @{esc(un)} · owner <code>{oid}</code> · {kind}" + ("" if is_premium(oid) else f" ends {fmt_date(te)}"))
    return "🤖 <b>Clones</b>\n\n" + "\n".join(out)


# ───────────────────────── commands ─────────────────────────
async def start(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    ctx.user_data.pop("await", None)
    q("INSERT OR IGNORE INTO users(id) VALUES(?)", (update.effective_user.id,))
    if ctx.args and ctx.args[0] == "settings":  # deep link from group config message
        return await send_panel(ctx.bot, update.effective_user.id)
    await send_home(ctx.bot, update.effective_user.id)


async def cmd_scan(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid, bk = update.effective_user.id, bkey(ctx.bot)
    rows = q("SELECT chat_id,title,kind FROM bchats WHERE owner_id=? AND bot_key=?", (uid, bk)).fetchall()
    if not rows:
        _, markup = home_view(ctx.bot.username)
        return await update.message.reply_text("📡 No connected chats yet. Add me as admin to a group or channel first.", reply_markup=markup)
    lines = []
    for cid, title, kind in rows:
        try:
            cm = await ctx.bot.get_chat_member(cid, ctx.bot.id)
        except TelegramError:
            q("DELETE FROM bchats WHERE chat_id=? AND bot_key=?", (cid, bk))
            continue
        ok = cm.status == S.ADMINISTRATOR and getattr(cm, "can_delete_messages", False)
        fl = chat_flags(cid, bk)
        n = sum(1 for k, _ in SHIELDS if fl.get(k))
        lines.append(f"{'✅' if ok else '⚠️'} <b>{esc(title)}</b> ({kind}) – {'ready' if ok else 'needs Delete messages right'} · 🛡 {n}")
    await update.message.reply_text(
        "📡 <b>Connected chats</b>\n\n" + ("\n".join(lines) or "None left."), parse_mode=ParseMode.HTML
    )


async def cmd_stats(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    uid, bk = update.effective_user.id, bkey(ctx.bot)
    if uid in DEV_IDS:
        return await update.message.reply_text(full_stats(), parse_mode=ParseMode.HTML)
    g = q("SELECT COUNT(*) FROM bchats WHERE owner_id=? AND bot_key=? AND kind IN ('group','supergroup')", (uid, bk)).fetchone()[0]
    c = q("SELECT COUNT(*) FROM bchats WHERE owner_id=? AND bot_key=? AND kind='channel'", (uid, bk)).fetchone()[0]
    await update.message.reply_text(
        f"📊 <b>Statistics</b>\n\n📡 Connected chats: <b>{g + c}</b>\n👥 Groups: <b>{g}</b> · 📣 Channels: <b>{c}</b>",
        parse_mode=ParseMode.HTML,
    )


async def cmd_setmedia(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id not in DEV_IDS:
        return
    r = update.message.reply_to_message
    if r and r.photo:
        set_setting("panel_media", "photo:" + r.photo[-1].file_id)
    elif r and r.video:
        set_setting("panel_media", "video:" + r.video.file_id)
    elif r and r.animation:
        set_setting("panel_media", "animation:" + r.animation.file_id)
    else:
        return await update.message.reply_text("Reply to a photo, video or GIF with /setmedia")
    await update.message.reply_text("✅ Panel media updated. Send /start to see it.")


def norm(kind, v):
    v = v.strip().lower()
    if kind == "competitor":
        for p in ("https://", "http://", "t.me/", "telegram.me/", "@"):
            v = v.replace(p, "")
    return v


async def list_cmd(update, ctx, kind, title):
    uid = update.effective_user.id
    args = ctx.args
    sub = args[0].lower() if args else "list"
    if sub in ("add", "remove") and len(args) > 1:
        v = norm(kind, " ".join(args[1:]))
        if sub == "add":
            if len(v) < 4:
                return await update.message.reply_text("Too short (min 4 characters) – it would match too much.")
            if not q("SELECT 1 FROM lists WHERE owner_id=? AND kind=? AND value=?", (uid, kind, v)).fetchone():
                q("INSERT INTO lists(owner_id,kind,value) VALUES(?,?,?)", (uid, kind, v))
            return await update.message.reply_text(f"✅ Added: {v}")
        q("DELETE FROM lists WHERE owner_id=? AND kind=? AND value=?", (uid, kind, v))
        return await update.message.reply_text(f"🗑 Removed: {v}")
    vals = [r[0] for r in q("SELECT value FROM lists WHERE owner_id=? AND kind=?", (uid, kind)).fetchall()]
    await update.message.reply_text(
        f"<b>{title}</b>\n" + ("\n".join(f"• {esc(v)}" for v in vals) or "Empty")
        + f"\n\n/{'competitor' if kind == 'competitor' else 'keywords'} add &lt;text&gt; · remove &lt;text&gt;",
        parse_mode=ParseMode.HTML,
    )


async def cmd_competitor(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await list_cmd(update, ctx, "competitor", "Competitor list")


async def cmd_keywords(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    await list_cmd(update, ctx, "keyword", "Extra copyright keywords")


# ───────────────────────── button handler ─────────────────────────
async def buttons_cb(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    qy = update.callback_query
    uid, bk = qy.from_user.id, bkey(ctx.bot)
    data = qy.data or ""
    # older panel messages used these shorter callback names
    if data == "home":
        data = "hm"
    elif data == "panel":
        data = "pn:o"
    elif data.startswith("tg:") and data.count(":") == 1:
        data = "tg:o:" + data[3:]
    parts = data.split(":")
    act = parts[0]
    ctx.user_data.pop("await", None)
    note, alert, text, markup = None, False, None, None

    if act == "hm":
        text, markup = home_view(ctx.bot.username)

    elif act in ("tg", "pn", "ad", "ao", "at", "cf"):
        scope = ("c" + parts[1]) if act == "cf" else (parts[1] if len(parts) > 1 else "o")
        if scope != "o":
            try:
                cid = int(scope[1:])
            except ValueError:
                return await qy.answer()
            if not await is_admin(ctx.bot, cid, uid):
                return await qy.answer("Only admins can change settings.", show_alert=True)
            if not chat_row(cid, bk):
                return await qy.answer("This chat is no longer connected.", show_alert=True)
        fl = scope_flags(scope, ctx.bot, uid)
        if act == "tg":
            key = parts[2] if len(parts) > 2 else ""
            if key not in LABELS:
                return await qy.answer()
            fl = scope_set(scope, ctx.bot, uid, {key: not fl.get(key)})
            note = f"{LABELS[key]}: {'ON 🟢' if fl[key] else 'OFF 🔴'}"
            if fl[key] and key in API_MODELS and not SE_USER:
                note, alert = note + "\n⚠️ Image scanning isn't configured yet.", True
            text, markup = panel_view(scope, fl, uid)
        elif act == "pn":
            text, markup = panel_view(scope, fl, uid)
        elif act == "ad":
            text, markup = ad_view(scope, fl)
        elif act == "ao":
            fl = scope_set(scope, ctx.bot, uid, {"autodel": not fl.get("autodel")})
            note = f"Auto Delete: {'ON 🟢' if fl['autodel'] else 'OFF 🔴'}"
            text, markup = ad_view(scope, fl)
        elif act == "at":
            try:
                secs = int(parts[2])
            except (IndexError, ValueError):
                return await qy.answer()
            if secs not in TIME_SECS:
                return await qy.answer()
            fl = scope_set(scope, ctx.bot, uid, {"autodel": True, "autodel_secs": secs})
            note = f"Auto Delete: every {fmt_secs(secs)} 🟢"
            text, markup = ad_view(scope, fl)
        else:  # cf
            text, markup = cf_view(ctx.bot.username, int(scope[1:]), chat_row(int(scope[1:]), bk)[2])

    elif act == "cl":
        text, markup = clone_view(uid)

    elif act == "cl_new":
        ok, why = clone_allowed(uid)
        if not ok:
            note, alert = why, True
        else:
            ctx.user_data["await"] = "token"
            text = (
                "🤖 <b>Create your clone</b>\n\n"
                "1️⃣ Open @BotFather and send /newbot\n"
                "2️⃣ Copy the token and send it here\n\n"
                "<i>Your message with the token is deleted right away.</i>"
            )
            markup = Markup([[Btn("❌ Cancel", callback_data="cl")]])

    elif act == "cl_rm":
        await stop_clone(uid)
        q("UPDATE clones SET active=0, token='' WHERE owner_id=?", (uid,))
        note = "Clone removed."
        text, markup = clone_view(uid)

    elif act == "cl_go":
        if not is_premium(uid):
            note, alert = "Premium is required to restart your clone.", True
        elif await start_clone(uid):
            q("UPDATE clones SET active=1 WHERE owner_id=?", (uid,))
            note = "Clone restarted ✅"
            text, markup = clone_view(uid)
        else:
            note, alert = "Could not start the clone. Check the token.", True

    elif act.startswith("ow") or act == "bc_go":
        if uid not in DEV_IDS:
            return await qy.answer("Owner only.", show_alert=True)
        if act == "ow":
            text, markup = owner_view()
        elif act == "ow_stats":
            text, markup = full_stats(), BACK_OW
        elif act == "ow_cl":
            text, markup = clones_text(), BACK_OW
        elif act == "ow_bc":
            ctx.user_data["await"] = "broadcast"
            text = "📣 <b>Broadcast</b>\n\nSend (or forward) the message you want to broadcast. Text, photo, video – anything works."
            markup = Markup([[Btn("❌ Cancel", callback_data="ow")]])
        elif act == "ow_gp":
            ctx.user_data["await"] = "grant"
            text = "💎 <b>Grant Premium</b>\n\nSend: <code>user_id days</code>\nExample: <code>123456789 30</code>"
            markup = Markup([[Btn("❌ Cancel", callback_data="ow")]])
        elif act == "ow_rp":
            ctx.user_data["await"] = "revoke"
            text = "🚫 <b>Revoke Premium</b>\n\nSend the user ID."
            markup = Markup([[Btn("❌ Cancel", callback_data="ow")]])
        elif act == "bc_go":
            src = ctx.user_data.pop("bc", None)
            if not src or len(parts) < 2:
                note, alert = "Nothing to send.", True
            else:
                ctx.application.create_task(broadcast_worker(ctx.bot, uid, src, parts[1]))
                text, markup = "📣 Broadcast started. You'll get a report when it's done.", BACK_OW

    await qy.answer(note, show_alert=alert)
    if text:
        await edit_msg(qy, text, markup)


# ───────────────────────── private text input (clone token, premium, broadcast) ─────────────────────────
async def on_private(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    st = ctx.user_data.get("await")
    msg, uid = update.message, update.effective_user.id
    if not st or not msg:
        return
    ctx.user_data.pop("await", None)
    if st == "token":
        return await handle_token(ctx, msg, uid)
    if uid not in DEV_IDS:
        return
    if st == "broadcast":
        ctx.user_data["bc"] = (msg.chat_id, msg.message_id)
        return await msg.reply_text(
            "Where should it be posted?",
            reply_markup=Markup(
                [
                    [Btn("📡 Groups & Channels", callback_data="bc_go:c")],
                    [Btn("👤 Users", callback_data="bc_go:u"), Btn("📡+👤 Both", callback_data="bc_go:b")],
                    [Btn("❌ Cancel", callback_data="ow")],
                ]
            ),
        )
    args = (msg.text or "").split()
    if st == "grant":
        if len(args) != 2 or not args[0].isdigit() or not args[1].isdigit() or not 0 < int(args[1]) <= 3650:
            return await msg.reply_text("Format: user_id days (example: 123456789 30). Open Grant Premium to try again.")
        target, days = int(args[0]), int(args[1])
        cur = (q("SELECT until FROM premium WHERE user_id=?", (target,)).fetchone() or [0])[0]
        until = int(max(time.time(), cur) + days * 86400)
        q("INSERT INTO premium(user_id,until) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET until=excluded.until", (target, until))
        await msg.reply_text(f"✅ {target} is premium until {fmt_date(until)}.")
        await log_event(f"💎 Premium granted to <code>{target}</code> for {days} days.")
        try:
            await ctx.bot.send_message(target, f"💎 <b>Premium activated!</b>\nValid until {fmt_date(until)}.\nOpen /start → 🤖 Clone Bot.", parse_mode=ParseMode.HTML)
        except TelegramError:
            pass
    elif st == "revoke":
        if len(args) != 1 or not args[0].isdigit():
            return await msg.reply_text("Send just the user ID. Open Revoke Premium to try again.")
        q("UPDATE premium SET until=0 WHERE user_id=?", (int(args[0]),))
        await msg.reply_text("✅ Premium revoked. A running clone stops within a minute.")
        await log_event(f"🚫 Premium revoked for <code>{args[0]}</code>.")


# ───────────────────────── broadcast ─────────────────────────
async def broadcast_worker(bot, owner_dm, src, target):
    bk = bkey(bot)
    ids = []
    if target in ("c", "b"):
        ids += [("chat", r[0]) for r in q("SELECT chat_id FROM bchats WHERE bot_key=?", (bk,)).fetchall()]
    if target in ("u", "b"):
        ids += [("user", r[0]) for r in q("SELECT id FROM users").fetchall()]
    ok = fail = 0
    for kind, cid in ids:
        for _ in range(2):
            try:
                await bot.copy_message(cid, src[0], src[1])
                ok += 1
                break
            except RetryAfter as e:
                await asyncio.sleep(e.retry_after + 1)
            except Forbidden:
                if kind == "chat":
                    q("DELETE FROM bchats WHERE chat_id=? AND bot_key=?", (cid, bk))
                fail += 1
                break
            except TelegramError:
                fail += 1
                break
        await asyncio.sleep(0.05)
    try:
        await bot.send_message(owner_dm, f"📣 Broadcast done\n✅ Sent: {ok}\n❌ Failed: {fail}")
    except TelegramError:
        pass
    await log_event(f"📣 Broadcast finished: {ok} sent, {fail} failed.")


# ───────────────────────── clones ─────────────────────────
def register_handlers(app):
    P = filters.ChatType.PRIVATE
    for name, fn in (
        ("start", start),
        ("scan", cmd_scan),
        ("stats", cmd_stats),
        ("setmedia", cmd_setmedia),
        ("competitor", cmd_competitor),
        ("keywords", cmd_keywords),
    ):
        app.add_handler(CommandHandler(name, fn, filters=P))
    app.add_handler(CallbackQueryHandler(buttons_cb))
    app.add_handler(MessageHandler(P & ~filters.COMMAND, on_private))
    app.add_handler(ChatMemberHandler(on_my_member, ChatMemberHandler.MY_CHAT_MEMBER))
    app.add_handler(MessageHandler(filters.StatusUpdate.NEW_CHAT_MEMBERS, on_join))
    app.add_handler(
        MessageHandler(
            (filters.ChatType.GROUPS | filters.ChatType.CHANNEL) & ~filters.StatusUpdate.ALL & ~filters.COMMAND,
            on_message,
        ),
        group=1,
    )


COMMANDS = [BotCommand("start", "Start Bot"), BotCommand("scan", "Scan Channels"), BotCommand("stats", "Check Statistics")]


async def start_clone(owner_id):
    row = q("SELECT token FROM clones WHERE owner_id=?", (owner_id,)).fetchone()
    if not row or not row[0]:
        return False
    if owner_id in RUNNING:
        return True
    if len(RUNNING) >= MAX_CLONES:
        return False
    a = None
    try:
        a = Application.builder().token(row[0]).build()
        register_handlers(a)
        await a.initialize()
        await a.start()
        await a.updater.start_polling(allowed_updates=Update.ALL_TYPES)
        await a.bot.set_my_commands(COMMANDS)
        BOTS[a.bot.id] = a.bot
        RUNNING[owner_id] = a
        return True
    except Exception as e:
        log.error("clone start failed for %s: %s", owner_id, e)
        if a:
            try:
                await a.shutdown()
            except Exception:
                pass
        return False


async def stop_clone(owner_id):
    a = RUNNING.pop(owner_id, None)
    if not a:
        return
    BOTS.pop(a.bot.id, None)
    try:
        await a.updater.stop()
        await a.stop()
        await a.shutdown()
    except Exception as e:
        log.warning("clone stop issue: %s", e)


async def handle_token(ctx, msg, uid):
    token = (msg.text or "").strip()
    try:
        await msg.delete()  # never leave the token sitting in the chat
    except TelegramError:
        pass
    say = lambda t: ctx.bot.send_message(uid, t, parse_mode=ParseMode.HTML)
    if not TOKEN_RE.match(token):
        return await say("❌ That doesn't look like a bot token. Open 🤖 Clone Bot and try again.")
    ok, why = clone_allowed(uid)
    if not ok:
        return await say("🔒 " + why)
    if len(RUNNING) >= MAX_CLONES:
        return await say("⚠️ The clone limit has been reached. Please contact the owner.")
    try:
        async with Bot(token) as b:
            me = await b.get_me()
    except TelegramError:
        return await say("❌ Telegram rejected that token. Check it with @BotFather and try again.")
    if me.id == MAIN_ID or q("SELECT 1 FROM clones WHERE bot_id=? AND owner_id!=? AND token!=''", (me.id, uid)).fetchone():
        return await say("❌ That bot is already in use.")
    prev = q("SELECT trial_end FROM clones WHERE owner_id=?", (uid,)).fetchone()
    trial_end = prev[0] if prev else int(time.time()) + TRIAL_DAYS * 86400
    q(
        "INSERT INTO clones(owner_id,token,bot_id,username,trial_end,active,created) VALUES(?,?,?,?,?,1,?) "
        "ON CONFLICT(owner_id) DO UPDATE SET token=excluded.token,bot_id=excluded.bot_id,username=excluded.username,active=1",
        (uid, token, me.id, me.username, trial_end, int(time.time())),
    )
    if not await start_clone(uid):
        q("UPDATE clones SET active=0 WHERE owner_id=?", (uid,))
        return await say("⚠️ I couldn't start your clone. Please try again in a moment.")
    if is_premium(uid):
        plan = "💎 Premium clone – runs while your premium is active."
    else:
        plan = f"🎁 Free {TRIAL_DAYS}-day trial – ends {fmt_date(trial_end)}."
    await say(f"✅ <b>@{esc(me.username)}</b> is live!\n{plan}\n\nAdd it as admin to your groups and channels, then open it and send /start.")
    await log_event(f"🤖 Clone created: @{esc(me.username)} · owner <code>{uid}</code> · {'premium' if is_premium(uid) else 'trial'}")


async def clone_watch(ctx: ContextTypes.DEFAULT_TYPE):
    now = int(time.time())
    for owner_id, username, trial_end in q("SELECT owner_id,username,trial_end FROM clones WHERE active=1").fetchall():
        if is_premium(owner_id) or trial_end > now:
            continue
        await stop_clone(owner_id)
        q("UPDATE clones SET active=0 WHERE owner_id=?", (owner_id,))
        was_premium = bool(q("SELECT 1 FROM premium WHERE user_id=?", (owner_id,)).fetchone())
        why = "Your premium has ended." if was_premium else f"Your {TRIAL_DAYS}-day free trial has ended."
        try:
            await ctx.bot.send_message(
                owner_id,
                f"⏰ {why}\nYour clone bot <b>@{esc(username)}</b> will stop now.\n"
                "Get premium to keep it running." + (f" Contact {esc(PREMIUM_CONTACT)}." if PREMIUM_CONTACT else ""),
                parse_mode=ParseMode.HTML,
            )
        except TelegramError:
            pass
        await log_event(f"⏹ Clone stopped: @{esc(username)} · owner <code>{owner_id}</code>")


# ───────────────────────── connecting chats ─────────────────────────
async def chat_link(bot, chat):
    if chat.username:
        return f"https://t.me/{chat.username}"
    try:
        return (await bot.get_chat(chat.id)).invite_link or "no link available"
    except TelegramError:
        return "no link available"


async def on_my_member(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    c = update.my_chat_member
    chat, bk = c.chat, bkey(ctx.bot)
    if chat.type == ChatType.PRIVATE:
        return
    st = c.new_chat_member.status
    via = f" via @{esc(ctx.bot.username)}" if bk else ""
    if st not in (S.MEMBER, S.ADMINISTRATOR):
        if chat_row(chat.id, bk):
            q("DELETE FROM bchats WHERE chat_id=? AND bot_key=?", (chat.id, bk))
            await log_event(f"➖ <b>Removed</b>{via}\n📍 {esc(chat.title)} (<code>{chat.id}</code>)\n👤 by {mention(c.from_user)} (<code>{c.from_user.id}</code>)")
        return
    existing = chat_row(chat.id, bk)
    q("INSERT OR IGNORE INTO bchats(chat_id,bot_key,title,kind,owner_id) VALUES(?,?,?,?,?)", (chat.id, bk, chat.title, chat.type, c.from_user.id))
    q("UPDATE bchats SET title=? WHERE chat_id=? AND bot_key=?", (chat.title, chat.id, bk))
    owner = chat_row(chat.id, bk)[0]
    ready = st == S.ADMINISTRATOR and getattr(c.new_chat_member, "can_delete_messages", False)
    if not existing:
        link = await chat_link(ctx.bot, chat)
        await log_event(
            f"➕ <b>Added</b>{via}\n📍 {esc(chat.title)} ({chat.type})\n🆔 <code>{chat.id}</code>\n🔗 {esc(link)}\n"
            f"👤 by {mention(c.from_user)} (<code>{c.from_user.id}</code>)"
        )
        try:  # configuration message inside the chat
            text, markup = cf_view(ctx.bot.username, chat.id, chat.type)
            await ctx.bot.send_message(chat.id, text, parse_mode=ParseMode.HTML, reply_markup=markup)
        except TelegramError:
            pass
    if not existing or (c.old_chat_member.status != S.ADMINISTRATOR and st == S.ADMINISTRATOR):
        msg = "✅ Connected" if ready else "⚠️ Connected, but I need admin rights (Delete messages)"
        try:
            await ctx.bot.send_message(owner, f"{msg}: <b>{esc(chat.title)}</b>\nOpen /start to switch shields on.", parse_mode=ParseMode.HTML)
        except TelegramError:
            pass


joins = defaultdict(deque)
raid_alert = {}


async def on_join(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    chat, bk = update.message.chat, bkey(ctx.bot)
    row = chat_row(chat.id, bk)
    if not row or not chat_flags(chat.id, bk).get("competitor"):
        return
    now = time.time()
    dq = joins[(chat.id, bk)]
    dq.extend([now] * len(update.message.new_chat_members))
    while dq and now - dq[0] > 60:
        dq.popleft()
    if len(dq) >= 10 and now - raid_alert.get((chat.id, bk), 0) > 600:
        raid_alert[(chat.id, bk)] = now
        alert = (
            f"🚨 Possible join raid in <b>{esc(chat.title)}</b>: {len(dq)} joins in 60s.\n"
            "Consider turning on slow mode or restricting new members."
        )
        try:
            await ctx.bot.send_message(row[0], alert, parse_mode=ParseMode.HTML)
        except TelegramError:
            pass
        await log_event(alert)


# ───────────────────────── shield engine ─────────────────────────
flood = defaultdict(deque)
repeats = defaultdict(deque)
admin_cache = {}
scan_cache = {}


async def is_admin(bot, chat_id, uid):
    if uid in DEV_IDS:
        return True
    k = (chat_id, uid)
    c = admin_cache.get(k)
    if c and time.time() - c[0] < 300:
        return c[1]
    try:
        cm = await bot.get_chat_member(chat_id, uid)
        ok = cm.status in (S.ADMINISTRATOR, S.OWNER)
    except TelegramError:
        ok = False
    admin_cache[k] = (time.time(), ok)
    return ok


def haystack(msg):
    parts = [msg.text or "", msg.caption or ""]
    for m in (msg.document, msg.video, msg.audio):
        if m:
            parts.append(getattr(m, "file_name", "") or "")
    for ents in (msg.entities, msg.caption_entities):
        for e in ents or []:
            if e.url:
                parts.append(e.url)
    fo = msg.forward_origin
    if fo:
        for attr in ("chat", "sender_chat"):
            c = getattr(fo, attr, None)
            if c:
                parts += [c.title or "", c.username or ""]
        parts.append(getattr(fo, "sender_user_name", "") or "")
    return "\n".join(parts).lower()


def check_spam(msg, hay):
    u = msg.from_user
    if u:
        k, now = (msg.chat.id, u.id), time.time()
        dq = flood[k]
        dq.append(now)
        while dq and now - dq[0] > 10:
            dq.popleft()
        if len(dq) > 5:
            return "flooding", True
        t = (msg.text or msg.caption or "").strip().lower()
        if t:
            h = repeats[k]
            h.append((now, t))
            while h and now - h[0][0] > 60:
                h.popleft()
            if sum(1 for _, x in h if x == t) >= 3:
                return "repeated messages", True
    ents = (msg.entities or []) + (msg.caption_entities or [])
    if sum(1 for e in ents if e.type in (MessageEntity.MENTION, MessageEntity.TEXT_MENTION)) > 5:
        return "mass mentions", False
    if INVITE_RE.search(hay):
        return "invite-link promotion", False
    return None


def check_copyright(msg, hay, owner):
    words = [r[0] for r in q("SELECT value FROM lists WHERE owner_id=? AND kind='keyword'", (owner,)).fetchall()]
    if msg.document or msg.video or msg.audio or msg.photo or msg.animation:
        words += COPYRIGHT_WORDS
    return "copyrighted content" if any(w in hay for w in words) else None


def check_fake(msg, hay):
    if any(w in hay for w in SCAM_WORDS):
        return "scam content"
    u = msg.from_user
    if u and IMPERSONATE_RE.search(u.full_name or ""):
        return "impersonating staff"
    return None


def check_competitor(owner, hay):
    for (v,) in q("SELECT value FROM lists WHERE owner_id=? AND kind='competitor'", (owner,)).fetchall():
        if v in hay:
            return "competitor promotion"
    return None


def pick_image(msg):
    if msg.photo:
        big = [p for p in msg.photo if p.width >= 400]
        return big[0] if big else msg.photo[-1]
    st = msg.sticker
    if st and not st.is_animated and not st.is_video:
        return st
    thumb = None
    if msg.video:
        thumb = msg.video.thumbnail
    elif msg.animation:
        thumb = msg.animation.thumbnail
    elif msg.video_note:
        thumb = msg.video_note.thumbnail
    elif msg.document and (msg.document.mime_type or "").startswith("image/") and (msg.document.file_size or 0) < 5_000_000:
        return msg.document
    return thumb


def quota_ok(n):
    day = time.strftime("%Y-%m-%d", time.gmtime())
    return (
        int(get_setting("scan:" + day, "0")) + n <= DAILY_LIMIT
        and int(get_setting("scan:" + day[:7], "0")) + n <= MONTHLY_LIMIT
    )


def use_quota(n):
    day = time.strftime("%Y-%m-%d", time.gmtime())
    for k in ("scan:" + day, "scan:" + day[:7]):
        set_setting(k, str(int(get_setting(k, "0")) + n))


http = httpx.AsyncClient(timeout=20)


async def scores(bot, media, wanted):
    """Image scores from Sightengine. Cached per file; stops (fails open) when the free quota is used up."""
    entry = scan_cache.setdefault(media.file_unique_id, {})
    missing = [m for m in wanted if m not in entry]
    if not missing or not quota_ok(len(missing)):
        return entry
    f = await bot.get_file(media.file_id)
    data = bytes(await f.download_as_bytearray())
    r = await http.post(
        API_URL,
        data={"models": ",".join(API_MODELS[m] for m in missing), "api_user": SE_USER, "api_secret": SE_SECRET},
        files={"media": ("image", data)},
    )
    j = r.json()
    if j.get("status") != "success":
        log.warning("sightengine error: %s", j.get("error"))
        return entry
    use_quota(len(missing))
    if "porn" in missing:
        n = j.get("nudity") or {}
        entry["porn"] = max(n.get("sexual_activity", 0), n.get("sexual_display", 0), n.get("erotica", 0))
    if "violence" in missing:
        entry["violence"] = (j.get("gore") or {}).get("prob", 0)
    if len(scan_cache) > 5000:
        scan_cache.clear()
    return entry


async def delete_job(ctx: ContextTypes.DEFAULT_TYPE):
    try:
        await ctx.bot.delete_message(*ctx.job.data)
    except TelegramError:
        pass


async def sweep_job(ctx: ContextTypes.DEFAULT_TYPE):
    """Deletes messages whose auto-delete time is up (kept in the database, so restarts don't lose them)."""
    rows = q("SELECT rowid,chat_id,bot_key,msg_id FROM pending_del WHERE due<=? ORDER BY due LIMIT 100", (int(time.time()),)).fetchall()
    for rid, cid, bk, mid in rows:
        bot = BOTS.get(bk)
        if bot:
            try:
                await bot.delete_message(cid, mid)
            except RetryAfter as e:
                await asyncio.sleep(e.retry_after + 1)
                continue
            except TelegramError:
                pass
        q("DELETE FROM pending_del WHERE rowid=?", (rid,))
        await asyncio.sleep(0.05)


async def remove(ctx, msg, owner, shield, reason, mute=False):
    try:
        await msg.delete()
    except TelegramError:
        return  # no delete right, nothing happened
    bump(owner, shield)
    u = msg.from_user
    who = f"\n👤 {mention(u)} (<code>{u.id}</code>)" if u else ""
    via = f" via @{esc(ctx.bot.username)}" if bkey(ctx.bot) else ""
    await log_event(f"🚫 <b>{LABELS[shield]}</b>{via}: {reason}\n📍 {esc(msg.chat.title)} (<code>{msg.chat.id}</code>){who}")
    if msg.chat.type == ChatType.CHANNEL or not u:
        return
    try:
        if mute:
            await ctx.bot.restrict_chat_member(
                msg.chat.id, u.id, ChatPermissions.no_permissions(),
                until_date=datetime.now(timezone.utc) + timedelta(minutes=10),
            )
        note = await ctx.bot.send_message(
            msg.chat.id,
            f"🚫 Message from {mention(u)} removed: {reason}" + (" (muted 10 min)" if mute else ""),
            parse_mode=ParseMode.HTML,
        )
        ctx.job_queue.run_once(delete_job, 10, data=(msg.chat.id, note.message_id))
    except TelegramError:
        pass


async def on_message(update: Update, ctx: ContextTypes.DEFAULT_TYPE):
    msg = update.effective_message
    if not msg:
        return
    chat, bk = msg.chat, bkey(ctx.bot)
    row = chat_row(chat.id, bk)
    if not row:
        return
    owner = row[0]
    fl = json.loads(row[1]) if row[1] else owner_flags(owner)
    auto = bool(fl.get("autodel")) and chat.type != ChatType.CHANNEL and not (update.edited_message or update.edited_channel_post)
    if not auto and not any(fl.get(k) for k, _ in SHIELDS):
        return
    if chat.type != ChatType.CHANNEL:
        u = msg.from_user
        if msg.sender_chat or not u or u.is_bot or await is_admin(ctx.bot, chat.id, u.id):
            return
    hay = haystack(msg)

    checks = []
    if fl.get("spam"):
        checks.append(("spam", lambda: check_spam(msg, hay)))
    if fl.get("copyright"):
        checks.append(("copyright", lambda: (check_copyright(msg, hay, owner), False)))
    if fl.get("fake"):
        checks.append(("fake", lambda: (check_fake(msg, hay), False)))
    if fl.get("competitor"):
        checks.append(("competitor", lambda: (check_competitor(owner, hay), False)))
    for shield, fn in checks:
        res = fn()
        if res and res[0]:
            return await remove(ctx, msg, owner, shield, res[0], res[1])

    wanted = [m for m in API_MODELS if fl.get(m)]
    if wanted and SE_USER:
        media = pick_image(msg)
        if media:
            try:
                s = await scores(ctx.bot, media, wanted)
            except Exception as e:  # network/API problems must never break the bot
                log.warning("scan failed: %s", e)
                s = {}
            if fl.get("porn") and s.get("porn", 0) >= NSFW_T:
                return await remove(ctx, msg, owner, "porn", "adult content")
            if fl.get("violence") and s.get("violence", 0) >= GORE_T:
                return await remove(ctx, msg, owner, "violence", "violent content")

    if auto:
        secs = fl.get("autodel_secs", 600)
        q("INSERT INTO pending_del(chat_id,bot_key,msg_id,due) VALUES(?,?,?,?)", (chat.id, bk, msg.message_id, int(time.time()) + secs))


# ───────────────────────── main ─────────────────────────
async def post_init(app):
    global MAIN_ID
    MAIN_ID = app.bot.id
    BOTS[0] = app.bot
    await app.bot.set_my_commands(COMMANDS)
    app.job_queue.run_repeating(sweep_job, interval=5, first=10)
    app.job_queue.run_repeating(clone_watch, interval=60, first=30)
    if not SE_USER:
        log.warning("SIGHTENGINE_USER/SECRET not set: Porn Block and Violence Filter will not scan images.")
    now = int(time.time())
    for owner_id, trial_end in q("SELECT owner_id,trial_end FROM clones WHERE active=1 AND token!=''").fetchall():
        if is_premium(owner_id) or trial_end > now:
            await start_clone(owner_id)  # expired ones are stopped + notified by clone_watch


async def post_shutdown(app):
    for owner_id in list(RUNNING):
        await stop_clone(owner_id)


def main():
    app = Application.builder().token(TOKEN).post_init(post_init).post_shutdown(post_shutdown).build()
    register_handlers(app)
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
