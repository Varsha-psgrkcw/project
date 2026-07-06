from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os, jwt, bcrypt
from datetime import datetime, timedelta
from functools import wraps

# ─── Use PostgreSQL on Render, SQLite locally ─────────────────
DATABASE_URL = os.environ.get("DATABASE_URL")

if DATABASE_URL:
    import psycopg2
    import psycopg2.extras
    def get_db():
        conn = psycopg2.connect(DATABASE_URL)
        conn.autocommit = False
        return conn
    def fetchall(cursor): return cursor.fetchall()
    def fetchone(cursor): return cursor.fetchone()
    PLACEHOLDER = "%s"
else:
    import sqlite3
    DB_PATH = os.path.join(os.path.dirname(__file__), "../database/neataura.db")
    def get_db():
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn
    PLACEHOLDER = "?"

app = Flask(__name__, static_folder="../frontend/static")
CORS(app, resources={r"/api/*": {"origins": "*"}})

SECRET_KEY = os.environ.get("SECRET_KEY", "neataura-secret-key-change-in-production")

# ─── Auto-initialize database on startup ─────────────────────────
def init_database():
    sql_path = os.path.join(os.path.dirname(__file__), "../database/schema.sql")
    if not os.path.exists(sql_path):
        return
    with open(sql_path, "r", encoding="utf-8") as f:
        sql = f.read()
    if DATABASE_URL:
        try:
            import psycopg2
            conn = psycopg2.connect(DATABASE_URL)
            conn.autocommit = True
            cur = conn.cursor()
            statements = [s.strip() for s in sql.split(";") if s.strip()]
            for stmt in statements:
                try:
                    cur.execute(stmt)
                except Exception:
                    pass
            conn.close()
            print("✅ PostgreSQL database ready")
        except Exception as e:
            print(f"[DB Init] PostgreSQL error: {e}")
    else:
        try:
            import sqlite3
            db_path = os.path.join(os.path.dirname(__file__), "../database/neataura.db")
            sql_lite = sql.replace("SERIAL PRIMARY KEY", "INTEGER PRIMARY KEY AUTOINCREMENT")
            sql_lite = sql_lite.replace("ON CONFLICT DO NOTHING", "OR IGNORE")
            conn = sqlite3.connect(db_path)
            conn.executescript(sql_lite)
            conn.commit()
            conn.close()
            print(f"✅ SQLite database ready at {db_path}")
        except Exception as e:
            print(f"[DB Init] SQLite error: {e}")

init_database()

# ─── DB query helper ──────────────────────────────────────────
def db_query(sql, params=(), one=False, write=False):
    sql = sql.replace("?", PLACEHOLDER)
    conn = get_db()
    try:
        if DATABASE_URL:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        else:
            cur = conn.cursor()
        cur.execute(sql, params)
        if write:
            conn.commit()
            return cur.lastrowid if not DATABASE_URL else cur.fetchone()
        result = cur.fetchone() if one else cur.fetchall()
        return result
    finally:
        conn.close()

# ─── JWT auth decorator ──────────────────────────────────────
def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return jsonify({"error": "Missing token"}), 401
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user_id = payload["user_id"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(*args, **kwargs)
    return wrapper

# ─── Auth routes ─────────────────────────────────────────────
@app.post("/api/register")
def register():
    data     = request.json
    username = data.get("username", "").strip()
    email    = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not username or not email or not password:
        return jsonify({"error": "All fields are required"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    try:
        db_query(
            "INSERT INTO users (username, email, password_hash) VALUES (?,?,?)",
            (username, email, pw_hash), write=True
        )
    except Exception as e:
        if "unique" in str(e).lower() or "duplicate" in str(e).lower():
            return jsonify({"error": "Email already registered"}), 409
        return jsonify({"error": str(e)}), 500

    return jsonify({"message": "Account created successfully"}), 201

@app.post("/api/login")
def login():
    data  = request.json
    email = data.get("email", "").strip().lower()
    pw    = data.get("password", "")

    user = db_query("SELECT * FROM users WHERE email=?", (email,), one=True)
    if not user:
        return jsonify({"error": "Invalid credentials"}), 401

    stored_hash = user["password_hash"] if isinstance(user, dict) else user[3]
    if not bcrypt.checkpw(pw.encode(), stored_hash.encode()):
        return jsonify({"error": "Invalid credentials"}), 401

    user_id   = user["id"] if isinstance(user, dict) else user[0]
    user_name = user["username"] if isinstance(user, dict) else user[1]

    token = jwt.encode(
        {"user_id": user_id, "exp": datetime.utcnow() + timedelta(days=7)},
        SECRET_KEY, algorithm="HS256"
    )
    return jsonify({"token": token, "username": user_name})

# ─── Services ────────────────────────────────────────────────
@app.get("/api/services")
def get_services():
    rows = db_query("SELECT * FROM services ORDER BY category, name")
    return jsonify([dict(r) for r in rows])

@app.get("/api/services/<int:service_id>")
def get_service(service_id):
    row = db_query("SELECT * FROM services WHERE id=?", (service_id,), one=True)
    if not row:
        return jsonify({"error": "Service not found"}), 404
    return jsonify(dict(row))

# ─── Workers ─────────────────────────────────────────────────
@app.get("/api/workers")
def get_workers():
    service_id  = request.args.get("service_id")
    city        = request.args.get("city")
    gender_pref = request.args.get("gender")   # Male | Female | Any

    query  = "SELECT * FROM workers WHERE available=1"
    params = []

    if service_id:
        query += " AND id IN (SELECT worker_id FROM worker_services WHERE service_id=?)"
        params.append(service_id)
    if city:
        query += " AND city LIKE ?"
        params.append(f"%{city}%")
    if gender_pref and gender_pref != "Any":
        query += " AND gender=?"
        params.append(gender_pref)

    rows = db_query(query, params)
    return jsonify([dict(r) for r in rows])

# ─── Bookings ────────────────────────────────────────────────
@app.post("/api/bookings")
@require_auth
def create_booking():
    data = request.json
    if DATABASE_URL:
        conn = get_db()
        cur  = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(
            """INSERT INTO bookings
               (user_id, service_id, worker_id, city, booking_date, booking_time,
                num_workers, num_days, total_amount, status)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
            (request.user_id, data["service_id"], data.get("worker_id"),
             data["city"], data["date"], data["time"],
             data.get("num_workers", 1), data.get("num_days", 1),
             data["total_amount"], "pending")
        )
        booking_id = cur.fetchone()["id"]
        conn.commit()
        conn.close()
    else:
        import sqlite3
        conn = get_db()
        cur  = conn.execute(
            """INSERT INTO bookings
               (user_id, service_id, worker_id, city, booking_date, booking_time,
                num_workers, num_days, total_amount, status)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (request.user_id, data["service_id"], data.get("worker_id"),
             data["city"], data["date"], data["time"],
             data.get("num_workers", 1), data.get("num_days", 1),
             data["total_amount"], "pending")
        )
        booking_id = cur.lastrowid
        conn.commit()
        conn.close()

    return jsonify({"booking_id": booking_id, "message": "Booking confirmed!"}), 201

@app.get("/api/bookings")
@require_auth
def get_bookings():
    rows = db_query(
        """SELECT b.*, s.name as service_name, w.name as worker_name
           FROM bookings b
           LEFT JOIN services s ON b.service_id = s.id
           LEFT JOIN workers  w ON b.worker_id  = w.id
           WHERE b.user_id=?
           ORDER BY b.created_at DESC""",
        (request.user_id,)
    )
    return jsonify([dict(r) for r in rows])

@app.put("/api/bookings/<int:booking_id>/cancel")
@require_auth
def cancel_booking(booking_id):
    row = db_query(
        "SELECT * FROM bookings WHERE id=? AND user_id=?",
        (booking_id, request.user_id), one=True
    )
    if not row:
        return jsonify({"error": "Booking not found"}), 404
    db_query("UPDATE bookings SET status='cancelled' WHERE id=?", (booking_id,), write=True)
    return jsonify({"message": "Booking cancelled"})

# ─── Profile ─────────────────────────────────────────────────
@app.get("/api/profile")
@require_auth
def get_profile():
    user = db_query(
        "SELECT id, username, email, city, phone, created_at FROM users WHERE id=?",
        (request.user_id,), one=True
    )
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify(dict(user))

@app.put("/api/profile")
@require_auth
def update_profile():
    data = request.json
    db_query(
        "UPDATE users SET city=?, phone=?, username=? WHERE id=?",
        (data.get("city"), data.get("phone"), data.get("username"), request.user_id),
        write=True
    )
    return jsonify({"message": "Profile updated"})

# ─── SendGrid Email Notifications ────────────────────────────────
import urllib.request, json as _json, threading

def send_email(subject, html_body):
    def _send():
        api_key  = os.environ.get("SENDGRID_KEY")
        sender   = os.environ.get("GMAIL_USER")
        receiver = os.environ.get("NOTIFY_EMAIL", sender)
        if not api_key or not sender:
            print("[Email] SENDGRID_KEY or GMAIL_USER not set — skipping")
            return
        try:
            payload = _json.dumps({
                "personalizations": [{"to": [{"email": receiver}]}],
                "from": {"email": sender, "name": "NeatAura"},
                "subject": subject,
                "content": [{"type": "text/html", "value": html_body}]
            }).encode()
            req = urllib.request.Request(
                "https://api.sendgrid.com/v3/mail/send",
                data=payload,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                method="POST"
            )
            res = urllib.request.urlopen(req, timeout=10)
            print(f"[Email] Sent to {receiver} — status {res.status}")
        except Exception as e:
            print(f"[Email] Error: {e}")
    threading.Thread(target=_send, daemon=True).start()

@app.get("/api/test-email")
def test_email():
    sender   = os.environ.get("GMAIL_USER")
    receiver = os.environ.get("NOTIFY_EMAIL", sender)
    if not sender:
        return jsonify({"error": "GMAIL_USER not set"})
    send_email("🔔 NeatAura Test Email", "<h2>✅ NeatAura Email Working!</h2><p>Booking and SOS alerts will be sent here.</p>")
    return jsonify({"success": True, "sent_to": receiver})

@app.post("/api/notify/booking")
@require_auth
def notify_booking():
    d    = request.json or {}
    user = db_query("SELECT username, email, phone FROM users WHERE id=?", (request.user_id,), one=True)
    uname  = user["username"] if user else "Unknown"
    uemail = user["email"]    if user else "—"
    uphone = user["phone"]    if user else "—"
    send_email(
        f"🔔 New Booking #{d.get('booking_id','?')} — NeatAura",
        f"""<div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;border:1px solid #e5e7eb;border-radius:12px;overflow:hidden;">
        <div style="background:#6C3CE1;padding:20px 24px;"><h2 style="color:#fff;margin:0;">🔔 New Booking — NeatAura</h2></div>
        <div style="padding:24px;">
        <table style="width:100%;border-collapse:collapse;">
        <tr><td style="padding:8px 0;color:#6b7280;width:40%;">Booking ID</td><td style="font-weight:600;">#{d.get('booking_id','—')}</td></tr>
        <tr style="background:#f9fafb;"><td style="padding:8px 6px;color:#6b7280;">Service</td><td style="padding:8px 6px;font-weight:600;">{d.get('service','—')}</td></tr>
        <tr><td style="padding:8px 0;color:#6b7280;">Worker</td><td style="font-weight:600;">{d.get('worker','—')}</td></tr>
        <tr style="background:#f9fafb;"><td style="padding:8px 6px;color:#6b7280;">Date & Time</td><td style="padding:8px 6px;font-weight:600;">{d.get('date','—')} at {d.get('time','—')}</td></tr>
        <tr><td style="padding:8px 0;color:#6b7280;">City</td><td style="font-weight:600;">{d.get('city','—')}</td></tr>
        <tr style="background:#f9fafb;"><td style="padding:8px 6px;color:#6b7280;">Payment</td><td style="padding:8px 6px;font-weight:600;">{d.get('payment','—')}</td></tr>
        <tr style="background:#ecfdf5;"><td style="padding:10px 6px;color:#065f46;font-weight:700;">Total</td><td style="padding:10px 6px;color:#065f46;font-weight:700;font-size:18px;">₹{d.get('total','0')}</td></tr>
        </table>
        <div style="margin-top:16px;padding:14px;background:#f3f0ff;border-radius:8px;">
        <p style="margin:0;font-weight:600;">👤 Customer: {uname}</p>
        <p style="margin:4px 0;">Email: {uemail}</p>
        <p style="margin:2px 0;">Phone: {uphone}</p>
        </div></div></div>"""
    )
    return jsonify({"ok": True})

@app.post("/api/notify/sos")
@require_auth
def notify_sos():
    d    = request.json or {}
    user = db_query("SELECT username, phone FROM users WHERE id=?", (request.user_id,), one=True)
    uname  = user["username"] if user else "Unknown"
    uphone = user["phone"]    if user else "—"
    send_email(
        f"🆘 SOS EMERGENCY from {uname} — NeatAura",
        f"""<div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto;border:2px solid #ef4444;border-radius:12px;overflow:hidden;">
        <div style="background:#ef4444;padding:20px 24px;"><h2 style="color:#fff;margin:0;">🆘 SOS EMERGENCY — NeatAura</h2></div>
        <div style="padding:24px;">
        <div style="background:#fef2f2;border-radius:8px;padding:14px;margin-bottom:14px;">
        <p style="margin:0;color:#991b1b;font-weight:700;font-size:16px;">⚠️ Reason: {d.get('reason','—')}</p></div>
        <table style="width:100%;border-collapse:collapse;">
        <tr><td style="padding:8px 0;color:#6b7280;width:40%;">Booking</td><td style="font-weight:600;">#{d.get('booking_id','—')}</td></tr>
        <tr><td style="padding:8px 0;color:#6b7280;">Customer</td><td style="font-weight:600;">{uname}</td></tr>
        <tr><td style="padding:8px 0;color:#6b7280;">Phone</td><td style="font-weight:700;color:#dc2626;font-size:16px;">{uphone}</td></tr>
        <tr><td style="padding:8px 0;color:#6b7280;">Address</td><td style="font-weight:600;">{d.get('address','—')}</td></tr>
        </table>
        <div style="margin-top:14px;padding:12px;background:#fef2f2;border-radius:8px;text-align:center;">
        <p style="margin:0;color:#991b1b;font-weight:700;">🚨 Please call the customer immediately!</p></div>
        </div></div>"""
    )
    return jsonify({"ok": True})

# ─── Serve frontend ──────────────────────────────────────────
@app.get("/")
def serve_frontend():
    return send_from_directory("../frontend/templates", "index.html")

@app.get("/static/js/<path:filename>")
def serve_js(filename):
    return send_from_directory("../frontend/static/js", filename)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)