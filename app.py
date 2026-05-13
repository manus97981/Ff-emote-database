from flask import Flask, request, jsonify, redirect, session, render_template, make_response, send_file, send_from_directory, Response
import requests, time, datetime, os, re, jwt, bcrypt, csv, io, base64
import pymysql
import pymysql.cursors
from functools import wraps

app = Flask(__name__, template_folder="templates")
app.secret_key = "shani_store_secret_2024"
JWT_SECRET = "shani_store_jwt_secret_2024"

# ---- MySQL Config (Railway Public Proxy) ----
MYSQL_HOST     = "yamabiko.proxy.rlwy.net"
MYSQL_PORT     = 52874
MYSQL_USER     = "root"
MYSQL_PASSWORD = "NbsYqIURPJKwcmisxGfaqDMdUzzGOfTj"
MYSQL_DB       = "railway"

session_req = requests.Session()
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36",
    "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9", "Content-Type": "application/json",
    "Origin": "https://ffemote.com", "Referer": "https://ffemote.com/"
}

blocked_uids = set()
logs = []

def get_db():
    return pymysql.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=MYSQL_DB,
        cursorclass=pymysql.cursors.DictCursor,
        charset="utf8mb4",
        autocommit=False
    )

def init_db():
    conn = get_db()
    with conn.cursor() as cur:
        # screenshot stored as MEDIUMBLOB (base64 string) so it survives redeploys
        cur.execute('''CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            unlocked TINYINT(1) DEFAULT 0,
            pending_payment TINYINT(1) DEFAULT 0,
            screenshot MEDIUMTEXT DEFAULT NULL,
            screenshot_mime VARCHAR(50) DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            unlocked_at DATETIME DEFAULT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')
        # Add new columns if upgrading from old schema
        try:
            cur.execute("ALTER TABLE users ADD COLUMN screenshot_mime VARCHAR(50) DEFAULT NULL")
        except:
            pass
        try:
            cur.execute("ALTER TABLE users MODIFY COLUMN screenshot MEDIUMTEXT DEFAULT NULL")
        except:
            pass
    conn.commit()
    conn.close()

init_db()

def generate_token(email):
    payload = {"email": email, "exp": datetime.datetime.utcnow() + datetime.timedelta(days=30)}
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")

def verify_token(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])["email"]
    except:
        return None

def get_user(email):
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT id,username,email,password_hash,unlocked,pending_payment,created_at,unlocked_at FROM users WHERE email=%s", (email,))
        u = cur.fetchone()
    conn.close()
    return u if u else None

def get_all_users():
    conn = get_db()
    with conn.cursor() as cur:
        # Don't fetch screenshot blob in list — fetch separately when needed
        cur.execute("SELECT id,username,email,unlocked,pending_payment,created_at,unlocked_at, CASE WHEN screenshot IS NOT NULL THEN 1 ELSE 0 END as has_screenshot, screenshot_mime FROM users ORDER BY created_at DESC")
        users = cur.fetchall()
    conn.close()
    return list(users)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("auth_token")
        if not token: return redirect("/login")
        email = verify_token(token)
        if not email:
            resp = make_response(redirect("/login")); resp.set_cookie("auth_token","",expires=0); return resp
        user = get_user(email)
        if not user:
            resp = make_response(redirect("/login")); resp.set_cookie("auth_token","",expires=0); return resp
        return f(user, *args, **kwargs)
    return decorated

def api_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("auth_token")
        if not token: return jsonify({"error":"Unauthorized"}), 401
        email = verify_token(token)
        if not email: return jsonify({"error":"Unauthorized"}), 401
        user = get_user(email)
        if not user: return jsonify({"error":"Unauthorized"}), 401
        return f(user, *args, **kwargs)
    return decorated

def add_log(team, uid, response_text):
    ts = datetime.datetime.now().strftime('%H:%M:%S')
    logs.append((time.time(), f"[{ts}] TEAM: {team} | UID: {uid} | {response_text}"))
    if len(logs) > 200: logs.pop(0)

# ---- PAGES ----
@app.route("/")
def home():
    token = request.cookies.get("auth_token")
    user = None
    if token:
        email = verify_token(token)
        if email: user = get_user(email)
    return render_template("index.html", user=user)

@app.route("/login")
def login_page():
    if request.cookies.get("auth_token") and verify_token(request.cookies.get("auth_token")):
        return redirect("/")
    return render_template("login.html")

@app.route("/unlock")
@login_required
def unlock_page(user):
    return render_template("unlock.html", user=user)

@app.route("/logout")
def logout():
    session.pop("admin", None)
    resp = make_response(redirect("/"))
    resp.set_cookie("auth_token","",expires=0)
    return resp

# ---- ADMIN ----
@app.route("/admin", methods=["GET","POST"])
def admin():
    if request.method == "POST":
        if request.form.get("password") == "pak112233":
            session["admin"] = True; return redirect("/admin")
        return "Wrong Password"
    if not session.get("admin"):
        return '''<form method="POST" style="background:#0b1120;min-height:100vh;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:12px">
            <h2 style="color:white;font-family:sans-serif">⚡ Admin Login</h2>
            <input name="password" type="password" placeholder="Password" style="padding:10px 14px;border-radius:8px;border:none;background:#1e293b;color:white;width:220px;font-size:15px">
            <button style="padding:10px 24px;background:#2563eb;color:white;border:none;border-radius:8px;cursor:pointer;font-size:15px">Login</button></form>'''
    users = get_all_users()
    return render_template("admin.html", uids=list(blocked_uids), users=users)

def is_ajax():
    return request.headers.get("X-Requested-With") == "XMLHttpRequest"

@app.route("/admin/approve/<int:user_id>", methods=["POST"])
def admin_approve(user_id):
    if not session.get("admin"): return (jsonify({"ok":False}), 403) if is_ajax() else redirect("/admin")
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("UPDATE users SET unlocked=1, pending_payment=0, screenshot=NULL, screenshot_mime=NULL, unlocked_at=%s WHERE id=%s",
                    (datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), user_id))
    conn.commit(); conn.close()
    return jsonify({"ok":True, "msg":"✅ Approved"}) if is_ajax() else redirect("/admin")

@app.route("/admin/unapprove/<int:user_id>", methods=["POST"])
def admin_unapprove(user_id):
    if not session.get("admin"): return (jsonify({"ok":False}), 403) if is_ajax() else redirect("/admin")
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("UPDATE users SET unlocked=0, unlocked_at=NULL WHERE id=%s", (user_id,))
    conn.commit(); conn.close()
    return jsonify({"ok":True, "msg":"🔒 Unapproved"}) if is_ajax() else redirect("/admin")

@app.route("/admin/reject/<int:user_id>", methods=["POST"])
def admin_reject(user_id):
    if not session.get("admin"): return (jsonify({"ok":False}), 403) if is_ajax() else redirect("/admin")
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("UPDATE users SET pending_payment=0, screenshot=NULL, screenshot_mime=NULL WHERE id=%s", (user_id,))
    conn.commit(); conn.close()
    return jsonify({"ok":True, "msg":"❌ Rejected"}) if is_ajax() else redirect("/admin")

@app.route("/admin/delete-user/<int:user_id>", methods=["POST"])
def admin_delete_user(user_id):
    if not session.get("admin"): return (jsonify({"ok":False}), 403) if is_ajax() else redirect("/admin")
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
    conn.commit(); conn.close()
    return jsonify({"ok":True, "msg":"🗑️ Deleted"}) if is_ajax() else redirect("/admin")

@app.route("/admin/edit-user/<int:user_id>", methods=["POST"])
def admin_edit_user(user_id):
    if not session.get("admin"): return (jsonify({"ok":False}), 403) if is_ajax() else redirect("/admin")
    username = request.form.get("username","").strip()
    unlocked = 1 if request.form.get("unlocked") == "1" else 0
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("UPDATE users SET username=%s, unlocked=%s WHERE id=%s", (username, unlocked, user_id))
    conn.commit(); conn.close()
    return jsonify({"ok":True}) if is_ajax() else redirect("/admin")

# Serve screenshot from DB (base64 decoded back to image)
@app.route("/screenshots/<int:user_id>")
def serve_screenshot(user_id):
    if not session.get("admin"): return redirect("/admin")
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT screenshot, screenshot_mime FROM users WHERE id=%s", (user_id,))
        row = cur.fetchone()
    conn.close()
    if not row or not row["screenshot"]:
        return "Not found", 404
    img_data = base64.b64decode(row["screenshot"])
    mime = row["screenshot_mime"] or "image/jpeg"
    return Response(img_data, mimetype=mime)

# Download full DB as CSV
@app.route("/admin/download-db")
def download_db():
    if not session.get("admin"): return redirect("/admin")
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("SELECT id, username, email, unlocked, pending_payment, created_at, unlocked_at FROM users ORDER BY created_at DESC")
        users = cur.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Username", "Email", "Unlocked", "Pending Payment", "Created At", "Unlocked At"])
    for u in users:
        writer.writerow([
            u["id"], u["username"], u["email"],
            "Yes" if u["unlocked"] else "No",
            "Yes" if u["pending_payment"] else "No",
            u["created_at"], u["unlocked_at"] or ""
        ])
    output.seek(0)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=shani_store_{timestamp}.csv"}
    )

@app.route("/logs")
def view_logs():
    if not session.get("admin"): return redirect("/admin")
    return render_template("logs.html")

@app.route("/logs-data")
def logs_data():
    if not session.get("admin"): return "Unauthorized"
    return "\n".join(msg for t, msg in reversed(logs))

@app.route("/block", methods=["POST"])
def block():
    if not session.get("admin"): return redirect("/admin")
    uid = request.form.get("uid")
    if uid: blocked_uids.add(uid); add_log("SYSTEM", uid, "BLOCKED")
    return redirect("/admin")

@app.route("/unblock", methods=["POST"])
def unblock():
    if not session.get("admin"): return redirect("/admin")
    uid = request.form.get("uid")
    if uid in blocked_uids: blocked_uids.remove(uid); add_log("SYSTEM", uid, "UNBLOCKED")
    return redirect("/admin")

# ---- AUTH API ----
@app.route("/api/auth/register", methods=["POST"])
def api_register():
    data = request.get_json()
    username = data.get("username","").strip()
    email = data.get("email","").strip().lower()
    password = data.get("password","")
    if not username or not email or not password:
        return jsonify({"error":"All fields required"}), 400
    if len(password) < 6:
        return jsonify({"error":"Password must be at least 6 characters"}), 400
    if not re.match(r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$', email):
        return jsonify({"error":"Invalid email"}), 400
    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        conn = get_db()
        with conn.cursor() as cur:
            cur.execute("INSERT INTO users (username, email, password_hash) VALUES (%s, %s, %s)",
                        (username, email, pw_hash))
        conn.commit(); conn.close()
        return jsonify({"success":True}), 200
    except pymysql.err.IntegrityError:
        return jsonify({"error":"Email already registered"}), 400

@app.route("/api/auth/login", methods=["POST"])
def api_login():
    data = request.get_json()
    email = data.get("email","").strip().lower()
    password = data.get("password","")
    user = get_user(email)
    if not user or not bcrypt.checkpw(password.encode(), user["password_hash"].encode()):
        return jsonify({"error":"Invalid credentials"}), 401
    token = generate_token(email)
    resp = make_response(jsonify({"success":True,"user":{"username":user["username"],"unlocked":bool(user["unlocked"])}}))
    resp.set_cookie("auth_token", token, httponly=True, samesite="Lax", max_age=30*24*3600)
    return resp, 200

@app.route("/api/auth/logout", methods=["POST"])
def api_logout():
    resp = make_response(jsonify({"success":True}))
    resp.set_cookie("auth_token","",expires=0)
    return resp, 200

@app.route("/api/auth/me")
@api_login_required
def api_me(user):
    return jsonify({"username":user["username"],"email":user["email"],"unlocked":bool(user["unlocked"])}), 200

@app.route("/api/upload-screenshot", methods=["POST"])
@api_login_required
def upload_screenshot(user):
    if "screenshot" not in request.files:
        return jsonify({"error":"No file uploaded"}), 400
    file = request.files["screenshot"]
    ext = file.filename.rsplit(".",1)[-1].lower() if "." in file.filename else ""
    mime_map = {"png":"image/png","jpg":"image/jpeg","jpeg":"image/jpeg","gif":"image/gif","webp":"image/webp"}
    if ext not in mime_map:
        return jsonify({"error":"Only image files allowed"}), 400
    # Store as base64 in DB — survives redeploys
    img_bytes = file.read()
    img_b64 = base64.b64encode(img_bytes).decode("utf-8")
    mime = mime_map[ext]
    conn = get_db()
    with conn.cursor() as cur:
        cur.execute("UPDATE users SET pending_payment=1, screenshot=%s, screenshot_mime=%s WHERE id=%s",
                    (img_b64, mime, user["id"]))
    conn.commit(); conn.close()
    return jsonify({"success":True,"message":"Screenshot upload ho gaya! Admin verify kar ke unlock karega."}), 200

@app.route("/send", methods=["POST"])
def send():
    token = request.cookies.get("auth_token")
    if not token or not verify_token(token):
        return jsonify({"status":"login_required"}), 401
    user = get_user(verify_token(token))
    if not user or not user["unlocked"]:
        return jsonify({"status":"unlock_required"}), 403
    uid = request.form.get("uid")
    team = request.form.get("team")
    emote = str(request.form.get("emote")).strip()
    no_bot = request.form.get("no_bot","false").lower() == "true"
    if uid in blocked_uids:
        add_log(team, uid, "BLOCKED"); return jsonify({"status":"blocked"})
    try:
        session_req.post("https://ffemote.com/validate_passwords",
                         json={"yt_password":"B25","tg_password":"B25"},
                         headers=BROWSER_HEADERS, timeout=10)
        r = session_req.post("https://ffemote.com/send_emote",
                             json={"server":"pakistan","team_code":team,"emote_id":emote,"uids":[uid],"auto_leave":no_bot},
                             headers=BROWSER_HEADERS, timeout=10)
        if r.status_code == 200 and "success" in r.text.lower():
            add_log(team, uid, f"SUCCESS - {r.text.strip()}"); return jsonify({"status":"success"})
        add_log(team, uid, f"FAIL - {r.text.strip()}"); return jsonify({"status":"fail"})
    except Exception as e:
        add_log(team, uid, f"ERROR - {str(e)}"); return jsonify({"status":"error"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
