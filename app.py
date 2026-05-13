from flask import Flask, request, jsonify, redirect, session, render_template, url_for, make_response
import requests
import time
import datetime
import json
import os
import re
import jwt
import bcrypt
from functools import wraps

app = Flask(__name__, template_folder="templates")
app.secret_key = "shani_store_secret_2024"

JWT_SECRET = "shani_store_jwt_secret_2024"
USERS_FILE = "users_db.json"
SCREENSHOTS_DIR = "screenshots"

os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

session_req = requests.Session()

BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Content-Type": "application/json",
    "Origin": "https://ffemote.com",
    "Referer": "https://ffemote.com/"
}

blocked_uids = set()
logs = []

# ---------- USER DB ----------
def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, "r") as f:
        return json.load(f)

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)

# ---------- JWT ----------
def generate_token(email):
    payload = {
        "email": email,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=30)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return payload["email"]
    except:
        return None

# ---------- DECORATORS ----------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("auth_token")
        if not token:
            return redirect("/login")
        email = verify_token(token)
        if not email:
            resp = make_response(redirect("/login"))
            resp.set_cookie("auth_token", "", expires=0)
            return resp
        users = load_users()
        if email not in users:
            resp = make_response(redirect("/login"))
            resp.set_cookie("auth_token", "", expires=0)
            return resp
        return f(users[email], *args, **kwargs)
    return decorated

def api_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("auth_token")
        if not token:
            return jsonify({"error": "Unauthorized"}), 401
        email = verify_token(token)
        if not email:
            return jsonify({"error": "Unauthorized"}), 401
        users = load_users()
        if email not in users:
            return jsonify({"error": "Unauthorized"}), 401
        return f(users[email], *args, **kwargs)
    return decorated

# ---------- LOG ----------
def add_log(team, uid, response_text):
    current_time = time.time()
    timestamp = datetime.datetime.fromtimestamp(current_time).strftime('%H:%M:%S')
    log_entry = f"[{timestamp}] TEAM: {team} | UID: {uid} | {response_text}"
    logs.append((current_time, log_entry))
    if len(logs) > 200:
        logs.pop(0)

# ---------- PAGES ----------
@app.route("/")
def home():
    token = request.cookies.get("auth_token")
    user = None
    if token:
        email = verify_token(token)
        if email:
            users = load_users()
            user = users.get(email)
    return render_template("index.html", user=user)

@app.route("/login")
def login_page():
    token = request.cookies.get("auth_token")
    if token and verify_token(token):
        return redirect("/")
    return render_template("login.html")

@app.route("/unlock")
@login_required
def unlock_page(user):
    return render_template("unlock.html", user=user)

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if request.method == "POST":
        if request.form.get("password") == "pak112233":
            session["admin"] = True
            return redirect("/admin")
        else:
            return "Wrong Password"
    if not session.get("admin"):
        return '''
        <form method="POST" style="background:#0b1120;min-height:100vh;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:10px">
            <input name="password" type="password" placeholder="Admin Password" style="padding:10px;border-radius:8px;border:none;background:#1e293b;color:white;">
            <button style="padding:10px 20px;background:#2563eb;color:white;border:none;border-radius:8px;cursor:pointer">Login</button>
        </form>
        '''
    users = load_users()
    return render_template("admin.html", uids=list(blocked_uids), users=users)

@app.route("/logout")
def logout():
    session.pop("admin", None)
    resp = make_response(redirect("/"))
    resp.set_cookie("auth_token", "", expires=0)
    return resp

@app.route("/logs")
def view_logs():
    if not session.get("admin"):
        return redirect("/admin")
    return render_template("logs.html")

@app.route("/logs-data")
def logs_data():
    if not session.get("admin"):
        return "Unauthorized"
    output = [msg for t, msg in reversed(logs)]
    return "\n".join(output)

# ---------- AUTH API ----------
@app.route("/api/auth/register", methods=["POST"])
def api_register():
    data = request.get_json()
    username = data.get("username", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not username or not email or not password:
        return jsonify({"error": "All fields required"}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400
    if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
        return jsonify({"error": "Invalid email"}), 400

    users = load_users()
    if email in users:
        return jsonify({"error": "Email already registered"}), 400
    if any(u["username"] == username for u in users.values()):
        return jsonify({"error": "Username already taken"}), 400

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    users[email] = {
        "username": username,
        "email": email,
        "password_hash": pw_hash,
        "unlocked": False,
        "created_at": datetime.datetime.utcnow().isoformat()
    }
    save_users(users)
    return jsonify({"success": True, "message": "Registration successful"}), 200

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    users = load_users()
    user = users.get(email)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401
    if not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        return jsonify({"error": "Invalid credentials"}), 401

    token = generate_token(email)
    resp = make_response(jsonify({"success": True, "user": {"username": user["username"], "email": email, "unlocked": user.get("unlocked", False)}}))
    resp.set_cookie("auth_token", token, httponly=True, samesite="Lax", max_age=30*24*3600)
    return resp, 200

@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    resp = make_response(jsonify({"success": True}))
    resp.set_cookie("auth_token", "", expires=0)
    return resp, 200

@app.route("/api/auth/me", methods=["GET"])
@api_login_required
def api_me(user):
    return jsonify({"username": user["username"], "email": user["email"], "unlocked": user.get("unlocked", False)}), 200

# ---------- SCREENSHOT UPLOAD ----------
@app.route("/api/upload-screenshot", methods=["POST"])
@api_login_required
def upload_screenshot(user):
    if "screenshot" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files["screenshot"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    allowed = {"png", "jpg", "jpeg", "gif", "webp"}
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in allowed:
        return jsonify({"error": "Only image files allowed"}), 400

    timestamp = int(time.time())
    filename = f"{user['email'].replace('@','_')}_{timestamp}.{ext}"
    filepath = os.path.join(SCREENSHOTS_DIR, filename)
    file.save(filepath)

    # Mark user as pending review
    users = load_users()
    users[user["email"]]["pending_payment"] = True
    users[user["email"]]["screenshot"] = filename
    save_users(users)

    return jsonify({"success": True, "message": "Screenshot uploaded! Admin will verify and unlock your account."}), 200

# ---------- ADMIN: UNLOCK USER ----------
@app.route("/admin/unlock-user", methods=["POST"])
def admin_unlock_user():
    if not session.get("admin"):
        return redirect("/admin")
    email = request.form.get("email")
    users = load_users()
    if email in users:
        users[email]["unlocked"] = True
        users[email]["unlocked_at"] = datetime.datetime.utcnow().isoformat()
        users[email]["unlock_expires"] = (datetime.datetime.utcnow() + datetime.timedelta(days=30)).isoformat()
        save_users(users)
    return redirect("/admin")

# ---------- BLOCK / UNBLOCK ----------
@app.route("/block", methods=["POST"])
def block():
    if not session.get("admin"):
        return redirect("/admin")
    uid = request.form.get("uid")
    if uid:
        blocked_uids.add(uid)
        add_log("SYSTEM", uid, "BLOCKED")
    return redirect("/admin")

@app.route("/unblock", methods=["POST"])
def unblock():
    if not session.get("admin"):
        return redirect("/admin")
    uid = request.form.get("uid")
    if uid in blocked_uids:
        blocked_uids.remove(uid)
        add_log("SYSTEM", uid, "UNBLOCKED")
    return redirect("/admin")

# ---------- SEND ----------
@app.route("/send", methods=["POST"])
def send():
    token = request.cookies.get("auth_token")
    if not token or not verify_token(token):
        return jsonify({"status": "login_required"}), 401

    email = verify_token(token)
    users = load_users()
    user = users.get(email)
    if not user or not user.get("unlocked", False):
        return jsonify({"status": "unlock_required"}), 403

    uid = request.form.get("uid")
    team = request.form.get("team")
    emote = str(request.form.get("emote")).strip()
    no_bot = request.form.get("no_bot", "false").lower() == "true"

    if uid in blocked_uids:
        add_log(team, uid, "BLOCKED")
        return jsonify({"status": "blocked"})

    try:
        session_req.post(
            "https://ffemote.com/validate_passwords",
            json={"yt_password": "B25", "tg_password": "B25"},
            headers=BROWSER_HEADERS,
            timeout=10
        )
        r = session_req.post(
            "https://ffemote.com/send_emote",
            json={
                "server": "pakistan",
                "team_code": team,
                "emote_id": emote,
                "uids": [uid],
                "auto_leave": no_bot
            },
            headers=BROWSER_HEADERS,
            timeout=10
        )
        response_text = r.text.strip()
        if r.status_code == 200 and "success" in r.text.lower():
            add_log(team, uid, f"SUCCESS - {response_text}")
            return jsonify({"status": "success"})
        else:
            add_log(team, uid, f"FAIL - {response_text}")
            return jsonify({"status": "fail"})
    except Exception as e:
        add_log(team, uid, f"ERROR - {str(e)}")
        return jsonify({"status": "error"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)

# Serve uploaded screenshots (admin only)
from flask import send_from_directory
@app.route("/screenshots/<filename>")
def serve_screenshot(filename):
    if not session.get("admin"):
        return redirect("/admin")
    return send_from_directory(SCREENSHOTS_DIR, filename)
