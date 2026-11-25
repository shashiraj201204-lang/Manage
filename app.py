import os, json, time, uuid, sqlite3, secrets, asyncio, traceback
from functools import wraps
from flask import Flask, request, jsonify, session, send_file
from cryptography.fernet import Fernet, InvalidToken
from telethon import TelegramClient
from telethon.sessions import StringSession

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("DATA_DIR", os.path.join(APP_DIR, "data"))
SESSION_DIR = os.path.join(DATA_DIR, "sessions")
DB_PATH = os.path.join(DATA_DIR, "xirus.db")
os.makedirs(SESSION_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

app = Flask(__name__, static_folder=None)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 30,
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)

API_ID = os.environ.get("TG_API_ID", "32185221")
API_HASH = os.environ.get("TG_API_HASH", "da15b7e593c026a62ef52746e24fa76f")
WEB_PASSWORD = os.environ.get("WEB_PASSWORD", "shashi123")
CHAT_PASSWORD = os.environ.get("CHAT_PASSWORD", "shashi121")
FERNET_KEY = os.environ.get("FERNET_KEY", "")

if not app.secret_key or not WEB_PASSWORD or not CHAT_PASSWORD or not FERNET_KEY:
    print("CRITICAL ERROR: Missing environment variables. Set FLASK_SECRET_KEY, WEB_PASSWORD, CHAT_PASSWORD, FERNET_KEY")

cipher = Fernet(FERNET_KEY.encode())
pending = {}
live_logs = []

# Custom Logger to capture logs for the Web UI
def add_log(msg, level="INFO"):
    timestamp = time.strftime("%H:%M:%S", time.localtime())
    log_entry = {"time": timestamp, "level": level, "msg": msg}
    live_logs.append(log_entry)
    if len(live_logs) > 100: live_logs.pop(0)
    print(f"[{timestamp}] [{level}] {msg}")

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS accounts(
            id TEXT PRIMARY KEY, phone TEXT NOT NULL, label TEXT,
            session_enc BLOB NOT NULL, created_at INTEGER NOT NULL
        )""")
init_db()

def web_auth(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not session.get("web_ok"):
            return jsonify(error="Website login required"), 401
        return fn(*a, **kw)
    return wrapped

def chat_auth(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not session.get("chat_ok"):
            return jsonify(error="Unlock the Chat section first"), 403
        return fn(*a, **kw)
    return wrapped

def get_client(account_id):
    with db() as con:
        row = con.execute("SELECT session_enc FROM accounts WHERE id=?", (account_id,)).fetchone()
    if not row:
        return None
    try:
        string_session = cipher.decrypt(row["session_enc"]).decode()
    except Exception as e:
        add_log(f"Decryption failed for account {account_id}: {e}", "ERROR")
        return None
    
    # Telethon needs an event loop attached to the client
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    client = TelegramClient(StringSession(string_session), int(API_ID), API_HASH, loop=loop)
    
    loop.run_until_complete(client.connect())
    if not loop.run_until_complete(client.is_user_authorized()):
        loop.run_until_complete(client.disconnect())
        return None
    return client

# --- ROUTES ---

@app.get("/")
def home():
    return send_file(os.path.join(APP_DIR, "xirus.html"))

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/api/web-login")
def web_login():
    data = request.get_json(silent=True) or {}
    if not secrets.compare_digest(str(data.get("password", "")), WEB_PASSWORD):
        add_log(f"Failed web login attempt from {request.remote_addr}", "WARN")
        return jsonify(error="Incorrect password"), 401
    session.clear()
    session.permanent = True
    session["web_ok"] = True
    session["device_id"] = str(uuid.uuid4())
    add_log(f"Web login successful from {request.remote_addr}", "SUCCESS")
    return jsonify(ok=True, remember_days=30)

@app.post("/api/web-logout")
def web_logout():
    session.clear()
    add_log("Web logout successful", "INFO")
    return jsonify(ok=True)

@app.get("/api/me")
@web_auth
def me():
    return jsonify(ok=True, chat_unlocked=bool(session.get("chat_ok")), device_id=session.get("device_id"))

@app.post("/api/chat-unlock")
@web_auth
def chat_unlock():
    data = request.get_json(silent=True) or {}
    if not secrets.compare_digest(str(data.get("password", "")), CHAT_PASSWORD):
        add_log("Failed chat unlock attempt", "WARN")
        return jsonify(error="Incorrect chat password"), 401
    session["chat_ok"] = True
    add_log("Chat area unlocked", "SUCCESS")
    return jsonify(ok=True)

@app.post("/api/chat-lock")
@web_auth
def chat_lock():
    session.pop("chat_ok", None)
    return jsonify(ok=True)

@app.post("/api/telegram/start")
@web_auth
def telegram_start():
    data = request.get_json(silent=True) or {}
    phone = str(data.get("phone", "")).strip()
    if not phone:
        return jsonify(error="Phone number is required"), 400
    
    add_log(f"Initiating Telegram login for {phone}...", "INFO")
    
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        client = TelegramClient(StringSession(), int(API_ID), API_HASH, loop=loop)
        loop.run_until_complete(client.connect())
        
        sent = loop.run_until_complete(client.send_code_request(phone))
        
        login_id = secrets.token_urlsafe(24)
        pending[login_id] = {
            "client": client, "phone": phone, "phone_code_hash": sent.phone_code_hash,
            "owner": session.get("device_id"), "created": time.time(), "loop": loop
        }
        add_log(f"OTP sent successfully to {phone}", "SUCCESS")
        return jsonify(ok=True, login_id=login_id, message="Telegram login code sent")
    except Exception as e:
        error_msg = str(e)
        add_log(f"Telegram Send Code Error: {error_msg}", "ERROR")
        add_log(traceback.format_exc(), "DEBUG")
        return jsonify(error=error_msg), 400

@app.post("/api/telegram/verify")
@web_auth
def telegram_verify():
    data = request.get_json(silent=True) or {}
    login_id = str(data.get("login_id", ""))
    item = pending.get(login_id)
    
    if not item or item["owner"] != session.get("device_id"):
        add_log("Verify failed: Invalid or expired login session", "WARN")
        return jsonify(error="Login request expired. Start again."), 400
        
    if time.time() - item["created"] > 600:
        item["loop"].run_until_complete(item["client"].disconnect())
        pending.pop(login_id, None)
        add_log("Verify failed: OTP Timeout", "WARN")
        return jsonify(error="Code expired. Start again."), 400
        
    code = str(data.get("code", "")).strip()
    password = str(data.get("twofa", ""))
    loop = item["loop"]
    
    add_log(f"Verifying code for {item['phone']}...", "INFO")
    
    try:
        try:
            loop.run_until_complete(item["client"].sign_in(phone=item["phone"], code=code, phone_code_hash=item["phone_code_hash"]))
        except Exception as exc:
            if "password" in exc.__class__.__name__.lower() or "SessionPasswordNeeded" in str(type(exc)):
                if not password:
                    add_log("2FA required for this account", "WARN")
                    return jsonify(needs_2fa=True, error="Telegram two-step password required"), 202
                loop.run_until_complete(item["client"].sign_in(password=password))
            else:
                raise
                
        if not loop.run_until_complete(item["client"].is_user_authorized()):
            add_log("Verify failed: Authorization incomplete", "ERROR")
            return jsonify(error="Telegram authorization was not completed"), 400
            
        me_obj = loop.run_until_complete(item["client"].get_me())
        account_id = str(uuid.uuid4())
        raw = item["client"].session.save()
        encrypted = cipher.encrypt(raw.encode())
        label = (getattr(me_obj, "first_name", "") or "Telegram")[:80]
        
        with db() as con:
            con.execute("INSERT INTO accounts(id,phone,label,session_enc,created_at) VALUES(?,?,?,?,?)",
                        (account_id, item["phone"], label, encrypted, int(time.time())))
        
        loop.run_until_complete(item["client"].disconnect())
        pending.pop(login_id, None)
        add_log(f"Account {label} ({item['phone']}) successfully saved", "SUCCESS")
        return jsonify(ok=True, account_id=account_id, label=label, phone=item["phone"], message="Account securely saved")
        
    except Exception as e:
        error_msg = str(e)
        add_log(f"Verify Code Error: {error_msg}", "ERROR")
        return jsonify(error=error_msg), 400

@app.get("/api/accounts")
@web_auth
def accounts():
    with db() as con:
        rows = con.execute("SELECT id,phone,label,created_at FROM accounts ORDER BY created_at DESC").fetchall()
    return jsonify(accounts=[dict(r) for r in rows])

@app.post("/api/accounts/<account_id>/logout")
@web_auth
def logout_account(account_id):
    with db() as con:
        con.execute("DELETE FROM accounts WHERE id=?", (account_id,))
    add_log(f"Account {account_id} removed", "INFO")
    return jsonify(ok=True, message="This account was removed from this website")

@app.post("/api/accounts/logout-all")
@web_auth
def logout_all():
    with db() as con:
        con.execute("DELETE FROM accounts")
    session.pop("chat_ok", None)
    add_log("All saved accounts removed", "WARN")
    return jsonify(ok=True, message="All saved website account sessions removed")

@app.get("/api/chats/<account_id>")
@web_auth
@chat_auth
def chats(account_id):
    client = get_client(account_id)
    if not client:
        return jsonify(error="Account session unavailable; add the account again"), 404
    
    loop = asyncio.get_event_loop()
    try:
        dialogs = loop.run_until_complete(client.get_dialogs(limit=250))
        out = []
        for d in dialogs:
            ent = d.entity
            out.append({
                "id": str(d.id), "title": d.name or "Unknown",
                "type": "channel" if getattr(ent, "broadcast", False) else
                        ("group" if getattr(ent, "megagroup", False) or getattr(ent, "gigagroup", False) else
                         ("bot" if getattr(ent, "bot", False) else "private")),
                "unread": int(d.unread_count or 0),
                "date": d.date.isoformat() if d.date else None,
                "archived": bool(getattr(d, "folder_id", None) == 1)
            })
        return jsonify(chats=out)
    except Exception as e:
        add_log(f"Error loading chats: {e}", "ERROR")
        return jsonify(error=str(e)), 400
    finally:
        loop.run_until_complete(client.disconnect())

@app.get("/api/messages/<account_id>/<peer_id>")
@web_auth
@chat_auth
def messages(account_id, peer_id):
    client = get_client(account_id)
    if not client:
        return jsonify(error="Account session unavailable"), 404
        
    loop = asyncio.get_event_loop()
    try:
        entity = loop.run_until_complete(client.get_entity(int(peer_id)))
        msgs = loop.run_until_complete(client.get_messages(entity, limit=min(int(request.args.get("limit", 50)), 100)))
        out = []
        for m in reversed(msgs):
            if not m: continue
            out.append({
                "id": m.id, "text": m.message or "",
                "date": m.date.isoformat() if m.date else None,
                "out": bool(m.out), "media": bool(m.media)
            })
        return jsonify(messages=out)
    except Exception as e:
        add_log(f"Error loading messages: {e}", "ERROR")
        return jsonify(error=str(e)), 400
    finally:
        loop.run_until_complete(client.disconnect())

@app.get("/api/stats/<account_id>")
@web_auth
def stats(account_id):
    client = get_client(account_id)
    if not client:
        return jsonify(error="Account session unavailable"), 404
        
    loop = asyncio.get_event_loop()
    try:
        dialogs = loop.run_until_complete(client.get_dialogs(limit=500))
        return jsonify(total_chats=len(dialogs),
            groups=sum(1 for d in dialogs if getattr(d.entity, "megagroup", False)),
            channels=sum(1 for d in dialogs if getattr(d.entity, "broadcast", False)),
            unread=sum(int(d.unread_count or 0) for d in dialogs))
    except Exception as e:
        add_log(f"Error loading stats: {e}", "ERROR")
        return jsonify(error=str(e)), 400
    finally:
        loop.run_until_complete(client.disconnect())

@app.get("/api/logs")
@web_auth
def get_logs():
    return jsonify(logs=live_logs)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
