import sqlite3, hmac, hashlib, time, os, secrets
from functools import wraps
from flask import (Flask, request, jsonify, render_template,
                   redirect, url_for, session, g)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", secrets.token_hex(32))

DB = "keys.db"
LICENSE_SECRET = os.environ.get("LICENSE_SECRET", "GANTI_SECRET_PANJANG_INI")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

def init_db():
    con = sqlite3.connect(DB)
    con.execute("CREATE TABLE IF NOT EXISTS licenses (key TEXT PRIMARY KEY, hwid TEXT, expiry INTEGER, created INTEGER, active INTEGER DEFAULT 1, note TEXT)")
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

def sign(payload):
    return hmac.new(LICENSE_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()

def gen_key(prefix="VIP"):
    r = secrets.token_hex(8).upper()
    return prefix + "-" + r[:4] + "-" + r[4:8] + "-" + r[8:12]

@app.route("/api/activate", methods=["POST"])
def api_activate():
    data = request.json or {}
    key  = (data.get("key") or "").strip()
    hwid = (data.get("hwid") or "").strip()
    if not key or not hwid:
        return jsonify(ok=False, msg="key/hwid kosong"), 400
    con = db()
    row = con.execute("SELECT hwid, expiry, active FROM licenses WHERE key=?", (key,)).fetchone()
    if not row:
        return jsonify(ok=False, msg="key tidak ditemukan"), 404
    db_hwid, expiry, active = row
    if not active:
        return jsonify(ok=False, msg="key dinonaktifkan"), 403
    if expiry < int(time.time()):
        return jsonify(ok=False, msg="key expired"), 403
    if db_hwid is None:
        con.execute("UPDATE licenses SET hwid=? WHERE key=?", (hwid, key))
        con.commit()
    elif db_hwid != hwid:
        return jsonify(ok=False, msg="HWID tidak cocok"), 403
    token = sign(key + "|" + hwid + "|" + str(expiry))
    return jsonify(ok=True, token=token, expiry=expiry)

@app.route("/api/verify", methods=["POST"])
def api_verify():
    data = request.json or {}
    key   = data.get("key")
    hwid  = data.get("hwid")
    token = data.get("token")
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

def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not session.get("admin"):
            return redirect(url_for("admin_login"))
        return f(*a, **kw)
    return wrapper

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PASSWORD:
            session["admin"] = True
            return redirect(url_for("admin_panel"))
        return render_template("admin_login.html", error="Password salah")
    return render_template("admin_login.html")

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin", None)
    return redirect(url_for("admin_login"))

@app.route("/admin")
@admin_required
def admin_panel():
    con = db()
    rows = con.execute("SELECT key, hwid, expiry, active, note, created FROM licenses ORDER BY created DESC").fetchall()
    now = int(time.time())
    licenses = []
    for key, hwid, expiry, active, note, created in rows:
        status = "AKTIF" if (active and expiry > now) else "EXPIRED/OFF"
        sisa = max(0, (expiry - now) // 86400)
        licenses.append({
            "key": key,
            "hwid": hwid or "-",
            "status": status,
            "sisa": sisa,
            "note": note or "",
            "expiry_date": time.strftime("%Y-%m-%d", time.localtime(expiry))
        })
    return render_template("admin_panel.html", licenses=licenses)

@app.route("/admin/create", methods=["POST"])
@admin_required
def admin_create():
    days = int(request.form.get("days", 30))
    note = request.form.get("note", "")
    key = gen_key()
    expiry = int(time.time()) + days * 86400
    con = db()
    con.execute("INSERT INTO licenses (key, expiry, created, note) VALUES (?,?,?,?)", (key, expiry, int(time.time()), note))
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

@app.route("/")
def index():
    return redirect(url_for("page_activate"))

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
