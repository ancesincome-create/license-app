import sqlite3, hmac, hashlib, time, os, secrets
from functools import wraps
from flask import (Flask, request, jsonify, render_template,
                   redirect, url_for, session, g, flash)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", secrets.token_hex(32))
app.permanent_session_lifetime = 86400

DB = "keys.db"
LICENSE_SECRET = os.environ.get("LICENSE_SECRET", "GANTI_SECRET_PANJANG_INI")

DEFAULT_PRICES = {
    1: 1, 3: 2, 7: 4, 14: 7, 30: 12, 60: 20
}

def init_db():
    con = sqlite3.connect(DB)
    con.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'reseller',
        balance INTEGER DEFAULT 0,
        quota INTEGER DEFAULT 100,
        approved INTEGER DEFAULT 0,
        active INTEGER DEFAULT 1,
        created_at INTEGER,
        last_login INTEGER
    )""")
    con.execute("""CREATE TABLE IF NOT EXISTS licenses (
        key TEXT PRIMARY KEY,
        hwid TEXT,
        expiry INTEGER,
        created INTEGER,
        active INTEGER DEFAULT 1,
        note TEXT,
        created_by TEXT,
        duration_days INTEGER,
        price_paid INTEGER
    )""")
    con.execute("""CREATE TABLE IF NOT EXISTS activations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key TEXT,
        user_hwid TEXT,
        user_ip TEXT,
        activated_at INTEGER,
        reseller TEXT
    )""")
    con.execute("""CREATE TABLE IF NOT EXISTS prices (
        days INTEGER PRIMARY KEY,
        price INTEGER
    )""")
    con.execute("""CREATE TABLE IF NOT EXISTS topups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        amount INTEGER,
        note TEXT,
        created_at INTEGER,
        admin TEXT
    )""")
    for days, price in DEFAULT_PRICES.items():
        con.execute("INSERT OR IGNORE INTO prices (days, price) VALUES (?,?)", (days, price))
    con.commit()
    con.close()

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    d = g.pop("db", None)
    if d:
        d.close()
      
# ==================== UTILS ====================
def sign(payload):
    return hmac.new(LICENSE_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()

def gen_key(prefix="RED"):
    r = secrets.token_hex(8).upper()
    return prefix + "-" + r[:4] + "-" + r[4:8] + "-" + r[8:12]

def get_price(days):
    con = db()
    row = con.execute("SELECT price FROM prices WHERE days=?", (days,)).fetchone()
    return row[0] if row else 0

def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("username"):
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("username"):
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            return "Akses ditolak — hanya admin", 403
        return f(*a, **kw)
    return wrapper

# ==================== PUBLIC API ====================
@app.route("/api/activate", methods=["POST"])
def api_activate():
    data = request.json or {}
    key = (data.get("key") or "").strip()
    hwid = (data.get("hwid") or "").strip()
    if not key or not hwid:
        return jsonify(ok=False, msg="key/hwid kosong"), 400
    con = db()
    row = con.execute("SELECT hwid, expiry, active, created_by, duration_days FROM licenses WHERE key=?", (key,)).fetchone()
    if not row:
        return jsonify(ok=False, msg="key tidak ditemukan"), 404
    db_hwid, expiry, active, reseller, duration = row
    if not active:
        return jsonify(ok=False, msg="key dinonaktifkan"), 403
    if expiry < int(time.time()):
        return jsonify(ok=False, msg="key expired"), 403
    if db_hwid is None:
        con.execute("UPDATE licenses SET hwid=? WHERE key=?", (hwid, key))
        ip = request.remote_addr or "-"
        con.execute("INSERT INTO activations (key, user_hwid, user_ip, activated_at, reseller) VALUES (?,?,?,?,?)",
                    (key, hwid, ip, int(time.time()), reseller))
        con.commit()
    elif db_hwid != hwid:
        return jsonify(ok=False, msg="HWID tidak cocok"), 403
    token = sign(key + "|" + hwid + "|" + str(expiry))
    return jsonify(ok=True, token=token, expiry=expiry)

@app.route("/api/verify", methods=["POST"])
def api_verify():
    data = request.json or {}
    key, hwid, token = data.get("key"), data.get("hwid"), data.get("token")
    con = db()
    row = con.execute("SELECT hwid, expiry, active FROM licenses WHERE key=?", (key,)).fetchone()
    if not row:
        return jsonify(ok=False, msg="key hilang"), 404
    db_hwid, expiry, active = row
    expected = sign(key + "|" + hwid + "|" + str(expiry))
    if not hmac.compare_digest(expected, token or ""):
        return jsonify(ok=False, msg="token invalid"), 403
    if not active or expiry < int(time.time()):
        return jsonify(ok=False, msg="expired/nonaktif"), 403
    if db_hwid != hwid:
        return jsonify(ok=False, msg="HWID beda"), 403
    return jsonify(ok=True, expiry=expiry)

@app.route("/activate")
def page_activate():
    return render_template("activate.html")
  
# ==================== LANDING & AUTH ====================
@app.route("/")
def index():
    return render_template("landing.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        con = db()
        row = con.execute("SELECT username, password_hash, role, approved, active FROM users WHERE username=?", (username,)).fetchone()
        if not row or not check_password_hash(row[1], password):
            return render_template("login.html", error="Username atau password salah")
        if not row[4]:
            return render_template("login.html", error="Akun dinonaktifkan")
        if not row[3]:
            return render_template("login.html", error="Akun belum di-approve admin")
        session.permanent = True
        session["username"] = row[0]
        session["role"] = row[2]
        con.execute("UPDATE users SET last_login=? WHERE username=?", (int(time.time()), row[0]))
        con.commit()
        if row[2] == "admin":
            return redirect(url_for("admin_panel"))
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            return render_template("register.html", error="Username dan password wajib diisi")
        if len(password) < 6:
            return render_template("register.html", error="Password minimal 6 karakter")
        con = db()
        try:
            con.execute("INSERT INTO users (username, password_hash, role, balance, quota, approved, active, created_at) VALUES (?,?,?,?,?,?,?,?)",
                        (username, generate_password_hash(password), "reseller", 0, 100, 0, 1, int(time.time())))
            con.commit()
            return render_template("register.html", success="Pendaftaran berhasil. Tunggu approve admin sebelum bisa login.")
        except sqlite3.IntegrityError:
            return render_template("register.html", error="Username sudah dipakai")
    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

# ==================== ADMIN PANEL ====================
@app.route("/admin")
@admin_required
def admin_panel():
    con = db()
    rows = con.execute("SELECT key, hwid, expiry, active, note, created, created_by, duration_days FROM licenses ORDER BY created DESC LIMIT 100").fetchall()
    now = int(time.time())
    licenses = []
    for key, hwid, expiry, active, note, created, created_by, duration in rows:
        status = "AKTIF" if (active and expiry > now) else "EXPIRED/OFF"
        sisa = max(0, (expiry - now) // 86400)
        licenses.append({
            "key": key, "hwid": hwid or "-", "status": status,
            "sisa": sisa, "note": note or "",
            "created_by": created_by or "admin",
            "duration": duration or 0,
            "expiry_date": time.strftime("%Y-%m-%d", time.localtime(expiry))
        })
    stats = {
        "total_users": con.execute("SELECT COUNT(*) FROM users WHERE role='reseller'").fetchone()[0],
        "pending": con.execute("SELECT COUNT(*) FROM users WHERE approved=0").fetchone()[0],
        "total_keys": con.execute("SELECT COUNT(*) FROM licenses").fetchone()[0],
        "total_activations": con.execute("SELECT COUNT(*) FROM activations").fetchone()[0],
    }
    return render_template("admin_panel.html", licenses=licenses, username=session.get("username"), stats=stats)

@app.route("/admin/create", methods=["POST"])
@admin_required
def admin_create():
    username = session.get("username")
    days = int(request.form.get("days", 1))
    note = request.form.get("note", "")
    key = gen_key()
    expiry = int(time.time()) + days * 86400
    con = db()
    con.execute("INSERT INTO licenses (key, expiry, created, note, created_by, duration_days, price_paid) VALUES (?,?,?,?,?,?,?)",
                (key, expiry, int(time.time()), note, username, days, 0))
    con.commit()
    return redirect(url_for("admin_panel"))

@app.route("/admin/revoke/<key>", methods=["POST"])
@admin_required
def admin_revoke(key):
    con = db()
    con.execute("UPDATE licenses SET active=0 WHERE key=?", (key,))
    con.commit()
    return redirect(url_for("admin_panel"))

@app.route("/admin/delete/<key>", methods=["POST"])
@admin_required
def admin_delete(key):
    con = db()
    con.execute("DELETE FROM licenses WHERE key=?", (key,))
    con.commit()
    return redirect(url_for("admin_panel"))
  
# ==================== ADMIN: USERS ====================
@app.route("/admin/users")
@admin_required
def admin_users():
    con = db()
    rows = con.execute("SELECT id, username, role, balance, quota, approved, active, created_at, last_login FROM users ORDER BY created_at DESC").fetchall()
    users = []
    for id_, un, role, bal, quota, appr, act, cat, ll in rows:
        used = con.execute("SELECT COUNT(*) FROM licenses WHERE created_by=?", (un,)).fetchone()[0]
        users.append({
            "id": id_, "username": un, "role": role, "balance": bal,
            "quota": quota, "approved": appr, "active": act,
            "used": used,
            "created": time.strftime("%Y-%m-%d", time.localtime(cat or 0)),
            "last_login": time.strftime("%Y-%m-%d %H:%M", time.localtime(ll)) if ll else "-"
        })
    return render_template("admin_users.html", users=users, username=session.get("username"))

@app.route("/admin/users/approve/<int:user_id>", methods=["POST"])
@admin_required
def admin_users_approve(user_id):
    con = db()
    con.execute("UPDATE users SET approved=1 WHERE id=?", (user_id,))
    con.commit()
    return redirect(url_for("admin_users"))

@app.route("/admin/users/toggle/<int:user_id>", methods=["POST"])
@admin_required
def admin_users_toggle(user_id):
    con = db()
    row = con.execute("SELECT active FROM users WHERE id=?", (user_id,)).fetchone()
    if row:
        con.execute("UPDATE users SET active=? WHERE id=?", (0 if row[0] else 1, user_id))
        con.commit()
    return redirect(url_for("admin_users"))

@app.route("/admin/users/delete/<int:user_id>", methods=["POST"])
@admin_required
def admin_users_delete(user_id):
    con = db()
    row = con.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    if row and row[0] == session.get("username"):
        flash("Tidak bisa hapus akun sendiri", "error")
        return redirect(url_for("admin_users"))
    con.execute("DELETE FROM users WHERE id=?", (user_id,))
    con.commit()
    return redirect(url_for("admin_users"))

@app.route("/admin/users/quota/<int:user_id>", methods=["POST"])
@admin_required
def admin_users_quota(user_id):
    quota = int(request.form.get("quota", 100))
    con = db()
    con.execute("UPDATE users SET quota=? WHERE id=?", (quota, user_id))
    con.commit()
    return redirect(url_for("admin_users"))

@app.route("/admin/users/topup/<int:user_id>", methods=["POST"])
@admin_required
def admin_users_topup(user_id):
    amount = int(request.form.get("amount") or 0)
    con = db()
    row = con.execute("SELECT username FROM users WHERE id=?", (user_id,)).fetchone()
    if row:
        con.execute("UPDATE users SET balance = balance + ? WHERE id=?", (amount, user_id))
        con.execute("INSERT INTO topups (username, amount, note, created_at, admin) VALUES (?,?,?,?,?)",
                    (row[0], amount, note, int(time.time()), session.get("username")))
        con.commit()
    return redirect(url_for("admin_users"))

# ==================== ADMIN: PRICES ====================
@app.route("/admin/prices", methods=["GET", "POST"])
@admin_required
def admin_prices():
    con = db()
    if request.method == "POST":
        for days in [1, 3, 7, 14, 30, 60]:
            p = request.form.get("price_" + str(days))
            if p is not None:
                con.execute("INSERT OR REPLACE INTO prices (days, price) VALUES (?,?)", (days, int(p)))
        con.commit()
        flash("Harga berhasil diupdate", "ok")
    rows = con.execute("SELECT days, price FROM prices ORDER BY days").fetchall()
    prices = [{"days": d, "price": p} for d, p in rows]
    return render_template("admin_prices.html", prices=prices, username=session.get("username"))

# ==================== ADMIN: HISTORY ====================
@app.route("/admin/history")
@admin_required
def admin_history():
    con = db()
    rows = con.execute("""SELECT a.id, a.key, a.user_hwid, a.user_ip, a.activated_at, a.reseller, l.duration_days
                          FROM activations a LEFT JOIN licenses l ON a.key = l.key
                          ORDER BY a.activated_at DESC LIMIT 200""").fetchall()
    activations = []
    for id_, key, hwid, ip, at, reseller, dur in rows:
        activations.append({
            "id": id_, "key": key, "hwid": hwid or "-",
            "ip": ip or "-", "reseller": reseller or "-",
            "duration": dur or 0,
            "when": time.strftime("%Y-%m-%d %H:%M", time.localtime(at or 0))
        })
    return render_template("admin_history.html", activations=activations, username=session.get("username"))
  
# ==================== RESELLER DASHBOARD ====================
@app.route("/dashboard")
@login_required
def dashboard():
    if session.get("role") == "admin":
        return redirect(url_for("admin_panel"))
    username = session.get("username")
    con = db()
    user = con.execute("SELECT balance, quota FROM users WHERE username=?", (username,)).fetchone()
    balance = user[0] if user else 0
    quota = user[1] if user else 0
    used = con.execute("SELECT COUNT(*) FROM licenses WHERE created_by=?", (username,)).fetchone()[0]
    rows = con.execute("""SELECT a.id, a.key, a.user_hwid, a.activated_at, l.duration_days
                          FROM activations a LEFT JOIN licenses l ON a.key = l.key
                          WHERE a.reseller = ?
                          ORDER BY a.activated_at DESC LIMIT 50""", (username,)).fetchall()
    activations = []
    for id_, key, hwid, at, dur in rows:
        activations.append({
            "id": id_, "key": key, "hwid": hwid or "-",
            "duration": dur or 0,
            "when": time.strftime("%Y-%m-%d %H:%M", time.localtime(at or 0))
        })
    key_rows = con.execute("SELECT key, hwid, expiry, active, note, duration_days, created FROM licenses WHERE created_by=? ORDER BY created DESC LIMIT 50", (username,)).fetchall()
    now = int(time.time())
    keys = []
    for key, hwid, expiry, active, note, dur, created in key_rows:
        status = "AKTIF" if (active and expiry > now) else "EXPIRED/OFF"
        sisa = max(0, (expiry - now) // 86400)
        keys.append({
            "key": key, "hwid": hwid or "-", "status": status,
            "sisa": sisa, "note": note or "", "duration": dur or 0,
            "expiry_date": time.strftime("%Y-%m-%d", time.localtime(expiry))
        })
    prices = con.execute("SELECT days, price FROM prices ORDER BY days").fetchall()
    prices = [{"days": d, "price": p} for d, p in prices]
    return render_template("dashboard.html", username=username, balance=balance,
                           quota=quota, used=used, activations=activations,
                           keys=keys, prices=prices)

@app.route("/dashboard/create", methods=["POST"])
@login_required
def dashboard_create():
    if session.get("role") == "admin":
        return redirect(url_for("admin_panel"))
    username = session.get("username")
    con = db()
    days = int(request.form.get("days", 1))
    note = request.form.get("note", "")
    price = get_price(days)
    user = con.execute("SELECT balance, quota FROM users WHERE username=?", (username,)).fetchone()
    if not user:
        return redirect(url_for("dashboard"))
    balance, quota = user
    used = con.execute("SELECT COUNT(*) FROM licenses WHERE created_by=?", (username,)).fetchone()[0]
    if balance < price:
        flash("Balance tidak cukup. Hubungi admin untuk top-up.", "error")
        return redirect(url_for("dashboard"))
    if used >= quota:
        flash("Quota habis. Hubungi admin.", "error")
        return redirect(url_for("dashboard"))
    key = gen_key()
    expiry = int(time.time()) + days * 86400
    con.execute("INSERT INTO licenses (key, expiry, created, note, created_by, duration_days, price_paid) VALUES (?,?,?,?,?,?,?)",
                (key, expiry, int(time.time()), note, username, days, price))
    con.execute("UPDATE users SET balance = balance - ? WHERE username=?", (price, username))
    con.commit()
    flash("Key berhasil dibuat: " + key, "ok")
    return redirect(url_for("dashboard"))

@app.route("/dashboard/revoke/<key>", methods=["POST"])
@login_required
def dashboard_revoke(key):
    username = session.get("username")
    con = db()
    owner = con.execute("SELECT created_by FROM licenses WHERE key=?", (key,)).fetchone()
    if not owner or owner[0] != username:
        return "Akses ditolak", 403
    con.execute("UPDATE licenses SET active=0 WHERE key=?", (key,))
    con.commit()
    return redirect(url_for("dashboard"))

@app.route("/profile")
@login_required
def profile():
    username = session.get("username")
    con = db()
    user = con.execute("SELECT role, balance, quota, created_at, last_login FROM users WHERE username=?", (username,)).fetchone()
    if not user:
        return redirect(url_for("logout"))
    used = con.execute("SELECT COUNT(*) FROM licenses WHERE created_by=?", (username,)).fetchone()[0]
    topups = con.execute("SELECT amount, note, created_at, admin FROM topups WHERE username=? ORDER BY created_at DESC LIMIT 20", (username,)).fetchall()
    topups = [{"amount": a, "note": n or "", "when": time.strftime("%Y-%m-%d %H:%M", time.localtime(t or 0)), "admin": ad or "-"} for a, n, t, ad in topups]
    info = {
        "username": username, "role": user[0], "balance": user[1],
        "quota": user[2], "used": used,
        "created": time.strftime("%Y-%m-%d", time.localtime(user[3] or 0)),
        "last_login": time.strftime("%Y-%m-%d %H:%M", time.localtime(user[4] or 0)) if user[4] else "-"
    }
    return render_template("profile.html", info=info, topups=topups)

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
