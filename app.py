from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sock import Sock
import sqlite3, hashlib, random, string, smtplib, os, json, time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime, timedelta
from math import radians, sin, cos, sqrt, atan2   # FIX 1: moved import to top level
import threading

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app, resources={r"/*": {"origins": "*"}})

# ─── CONFIG ───────────────────────────────────────────────────────────────────
# FIX 2: read secrets from environment variables (required for production deploy)
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'smartattend-super-secret-jwt-key-2024')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)

EMAIL_SENDER   = os.environ.get('EMAIL_SENDER', 'smart.codemark.attendance@gmail.com')
EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', 'bfsq fiaj felf pcwy')

# FIX 3: use /tmp for the DB so it works on read-only file systems (Render free tier)
DB_PATH = os.environ.get('DB_PATH', '/tmp/smartattend.db')

jwt     = JWTManager(app)
sock    = Sock(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# WebSocket clients
ws_clients = set()

# ─── DATABASE ─────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            name     TEXT NOT NULL,
            email    TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            type     TEXT NOT NULL CHECK(type IN ('student','teacher','admin')),
            verified INTEGER DEFAULT 0,
            joined   TEXT DEFAULT (date('now')),
            face_data TEXT DEFAULT NULL,
            theme    TEXT DEFAULT 'dark'
        );
        CREATE TABLE IF NOT EXISTS otps (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            email   TEXT NOT NULL,
            otp     TEXT NOT NULL,
            expires TEXT NOT NULL,
            attempts INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS subjects (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT NOT NULL,
            teacher_id INTEGER NOT NULL,
            FOREIGN KEY(teacher_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS attendance_codes (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            code       TEXT NOT NULL UNIQUE,
            subject_id INTEGER NOT NULL,
            teacher_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            lat        REAL DEFAULT NULL,
            lng        REAL DEFAULT NULL,
            radius     INTEGER DEFAULT NULL,
            FOREIGN KEY(subject_id) REFERENCES subjects(id)
        );
        CREATE TABLE IF NOT EXISTS attendance (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            subject_id INTEGER NOT NULL,
            date       TEXT NOT NULL,
            ip_address TEXT DEFAULT NULL,
            lat        REAL DEFAULT NULL,
            lng        REAL DEFAULT NULL,
            UNIQUE(student_id, subject_id, date),
            FOREIGN KEY(student_id) REFERENCES users(id),
            FOREIGN KEY(subject_id) REFERENCES subjects(id)
        );
        CREATE TABLE IF NOT EXISTS activity_logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER,
            user_name  TEXT,
            action     TEXT NOT NULL,
            details    TEXT,
            ip_address TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS suspicious_flags (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER,
            subject_id INTEGER,
            reason     TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );
    """)
    conn.commit()
    conn.close()

# ─── HELPERS ──────────────────────────────────────────────────────────────────
def hash_pass(p):
    return hashlib.sha256(p.encode()).hexdigest()

def send_email(to, subject, body, attachment=None, attachment_name=None):
    try:
        msg = MIMEMultipart()
        msg['From']    = EMAIL_SENDER
        msg['To']      = to
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))
        if attachment and attachment_name:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment)
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename={attachment_name}')
            msg.attach(part)
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
            s.login(EMAIL_SENDER, EMAIL_PASSWORD)
            s.sendmail(EMAIL_SENDER, to, msg.as_string())
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def store_otp(email, otp):
    conn    = get_db()
    expires = (datetime.now() + timedelta(minutes=10)).isoformat()
    conn.execute("DELETE FROM otps WHERE email=?", (email,))
    conn.execute("INSERT INTO otps(email,otp,expires,attempts) VALUES(?,?,?,0)", (email, otp, expires))
    conn.commit()
    conn.close()

def verify_otp_db(email, otp):
    conn = get_db()
    row  = conn.execute(
        "SELECT * FROM otps WHERE email=? AND expires>?",
        (email, datetime.now().isoformat())
    ).fetchone()
    if not row:
        conn.close()
        return False, "OTP expired or not found"
    attempts = row['attempts'] + 1
    if attempts > 5:
        conn.execute("DELETE FROM otps WHERE email=?", (email,))
        conn.commit()
        conn.close()
        return False, "Too many attempts. Request a new OTP."
    if row['otp'] != otp:
        conn.execute("UPDATE otps SET attempts=? WHERE email=?", (attempts, email))
        conn.commit()
        conn.close()
        return False, f"Wrong OTP. {5-attempts} attempts left."
    conn.execute("DELETE FROM otps WHERE email=?", (email,))
    conn.commit()
    conn.close()
    return True, "OK"

def get_user_by_email(email):
    conn = get_db()
    u    = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    return dict(u) if u else None

def get_user_by_id(uid):
    conn = get_db()
    u    = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    return dict(u) if u else None

def log_activity(user_id, user_name, action, details=None, ip=None):
    conn = get_db()
    conn.execute(
        "INSERT INTO activity_logs(user_id,user_name,action,details,ip_address) VALUES(?,?,?,?,?)",
        (user_id, user_name, action, details, ip)
    )
    conn.commit()
    conn.close()

def broadcast_ws(data):
    dead = set()
    for ws in ws_clients:
        try:
            ws.send(json.dumps(data))
        except:
            dead.add(ws)
    ws_clients.difference_update(dead)

def otp_email_body(otp, name):
    return f"""
    <div style="font-family:Arial;max-width:500px;margin:auto;background:#0a0a0f;color:#f0f0f5;padding:36px;border-radius:16px;border:1px solid #2a2a3a">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
        <div style="width:8px;height:8px;border-radius:50%;background:#e04c2f"></div>
        <h2 style="color:#e04c2f;margin:0;font-size:20px">SmartAttend</h2>
      </div>
      <p style="color:#888899;margin-bottom:28px;font-size:13px">Secure Authentication</p>
      <p style="margin-bottom:6px">Hi <strong>{name}</strong>,</p>
      <p style="color:#888899;margin-bottom:24px">Your one-time password for SmartAttend:</p>
      <div style="text-align:center;background:#16161f;border:1px solid #2a2a3a;border-radius:12px;padding:28px;margin:20px 0">
        <div style="font-size:44px;font-weight:700;letter-spacing:14px;color:#e04c2f;font-family:monospace">{otp}</div>
        <div style="color:#888899;font-size:12px;margin-top:10px">Valid for 10 minutes &middot; Do not share</div>
      </div>
      <p style="color:#888899;font-size:12px;margin-top:20px">If you didn't request this, you can safely ignore this email.</p>
      <hr style="border:none;border-top:1px solid #2a2a3a;margin:20px 0">
      <p style="color:#555;font-size:11px">SmartAttend &middot; Secure Attendance System</p>
    </div>
    """

def low_attendance_email(student_name, student_email, subject_name, percentage):
    body = f"""
    <div style="font-family:Arial;max-width:500px;margin:auto;background:#0a0a0f;color:#f0f0f5;padding:36px;border-radius:16px;border:1px solid #e74c3c">
      <h2 style="color:#e74c3c">&#9888;&#65039; Low Attendance Alert</h2>
      <p>Hi <strong>{student_name}</strong>,</p>
      <p>Your attendance in <strong>{subject_name}</strong> has dropped to:</p>
      <div style="text-align:center;background:#16161f;border:2px solid #e74c3c;border-radius:12px;padding:24px;margin:20px 0">
        <div style="font-size:52px;font-weight:700;color:#e74c3c;font-family:monospace">{percentage}%</div>
        <div style="color:#888899;font-size:13px;margin-top:6px">Minimum required: 75%</div>
      </div>
      <p style="color:#f1c40f">Please attend upcoming classes to improve your attendance.</p>
      <hr style="border:none;border-top:1px solid #2a2a3a;margin:20px 0">
      <p style="color:#555;font-size:11px">SmartAttend &middot; Automated Alert</p>
    </div>
    """
    send_email(student_email, f"Low Attendance Alert - {subject_name}", body)

# ─── SERVE STATIC ─────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

# ─── WEBSOCKET ────────────────────────────────────────────────────────────────
@sock.route('/ws')
def websocket(ws):
    ws_clients.add(ws)
    try:
        while True:
            data = ws.receive()
            if data is None:
                break
    except:
        pass
    finally:
        ws_clients.discard(ws)

# ─── AUTH ROUTES ──────────────────────────────────────────────────────────────
@app.route('/register', methods=['POST'])
@limiter.limit("10 per hour")
def register():
    data  = request.json
    name  = data.get('name','').strip()
    email = data.get('email','').strip().lower()
    pwd   = data.get('password','')
    utype = data.get('type','student')
    if not all([name, email, pwd]):
        return jsonify({'message':'All fields are required'}), 400
    if utype not in ('student','teacher','admin'):
        return jsonify({'message':'Invalid account type'}), 400
    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
    if existing:
        conn.close()
        return jsonify({'message':'Email already registered'}), 409
    conn.execute("INSERT INTO users(name,email,password,type,verified) VALUES(?,?,?,?,0)",
                 (name, email, hash_pass(pwd), utype))
    conn.commit()
    conn.close()
    otp = generate_otp()
    store_otp(email, otp)
    send_email(email, "SmartAttend — Verify Your Email", otp_email_body(otp, name))
    log_activity(None, name, 'REGISTER', f'New {utype} registered', request.remote_addr)
    return jsonify({'message':'OTP sent to your email'}), 200

@app.route('/login', methods=['POST'])
@limiter.limit("20 per hour")
def login():
    data  = request.json
    email = data.get('email','').strip().lower()
    pwd   = data.get('password','')
    user  = get_user_by_email(email)
    if not user or user['password'] != hash_pass(pwd):
        return jsonify({'message':'Invalid email or password'}), 401
    otp = generate_otp()
    store_otp(email, otp)
    send_email(email, "SmartAttend — Login OTP", otp_email_body(otp, user['name']))
    log_activity(user['id'], user['name'], 'LOGIN_ATTEMPT', None, request.remote_addr)
    return jsonify({'message':'OTP sent to your email'}), 200

@app.route('/verify', methods=['POST'])
@limiter.limit("30 per hour")
def verify():
    data  = request.json
    email = data.get('email','').strip().lower()
    otp   = data.get('otp','').strip()
    ok, msg = verify_otp_db(email, otp)
    if not ok:
        return jsonify({'message': msg}), 401
    conn = get_db()
    conn.execute("UPDATE users SET verified=1 WHERE email=?", (email,))
    conn.commit()
    conn.close()
    user  = get_user_by_email(email)
    token = create_access_token(identity=str(user['id']))
    log_activity(user['id'], user['name'], 'LOGIN_SUCCESS', None, request.remote_addr)
    return jsonify({'message':'Verified', 'token': token, 'user': {
        'id': user['id'], 'name': user['name'],
        'email': user['email'], 'type': user['type'],
        'theme': user['theme'] or 'dark',
        'has_face': bool(user['face_data'])
    }}), 200

@app.route('/resend-otp', methods=['POST'])
@limiter.limit("5 per hour")
def resend_otp():
    data  = request.json
    email = data.get('email','').strip().lower()
    user  = get_user_by_email(email)
    if not user:
        return jsonify({'message':'Email not found'}), 404
    otp = generate_otp()
    store_otp(email, otp)
    send_email(email, "SmartAttend — New OTP", otp_email_body(otp, user['name']))
    return jsonify({'message':'OTP resent'}), 200

# ─── FACE RECOGNITION ────────────────────────────────────────────────────────
@app.route('/face/register', methods=['POST'])
@jwt_required()
def face_register():
    uid       = int(get_jwt_identity())
    face_data = request.json.get('face_data')
    if not face_data:
        return jsonify({'message':'No face data provided'}), 400
    conn = get_db()
    conn.execute("UPDATE users SET face_data=? WHERE id=?", (face_data, uid))
    conn.commit()
    conn.close()
    user = get_user_by_id(uid)
    log_activity(uid, user['name'], 'FACE_REGISTERED', None, request.remote_addr)
    return jsonify({'message':'Face registered successfully'}), 200

@app.route('/face/login', methods=['POST'])
@limiter.limit("10 per hour")
def face_login():
    data      = request.json
    email     = data.get('email','').strip().lower()
    face_data = data.get('face_data')
    user      = get_user_by_email(email)
    if not user or not user['face_data']:
        return jsonify({'message':'Face login not set up for this account'}), 400
    if face_data and user['face_data']:
        token = create_access_token(identity=str(user['id']))
        log_activity(user['id'], user['name'], 'FACE_LOGIN', None, request.remote_addr)
        return jsonify({'message':'Face verified', 'token': token, 'user': {
            'id': user['id'], 'name': user['name'],
            'email': user['email'], 'type': user['type'],
            'theme': user['theme'] or 'dark',
            'has_face': True
        }}), 200
    return jsonify({'message':'Face not recognized'}), 401

# ─── THEME ────────────────────────────────────────────────────────────────────
@app.route('/user/theme', methods=['POST'])
@jwt_required()
def update_theme():
    uid   = int(get_jwt_identity())
    theme = request.json.get('theme','dark')
    conn  = get_db()
    conn.execute("UPDATE users SET theme=? WHERE id=?", (theme, uid))
    conn.commit()
    conn.close()
    return jsonify({'message':'Theme updated'}), 200

# ─── STUDENT ROUTES ───────────────────────────────────────────────────────────
@app.route('/student/dashboard', methods=['GET'])
@jwt_required()
def student_dashboard():
    uid  = int(get_jwt_identity())
    user = get_user_by_id(uid)
    if not user or user['type'] != 'student':
        return jsonify({'message':'Unauthorized'}), 403
    conn = get_db()
    rows = conn.execute("""
        SELECT s.id, s.name, u.name as teacher,
               COALESCE(SUM(CASE WHEN a.student_id=? THEN 1 ELSE 0 END),0) as present,
               COUNT(DISTINCT ac.id) as total
        FROM subjects s
        LEFT JOIN users u ON u.id=s.teacher_id
        LEFT JOIN attendance_codes ac ON ac.subject_id=s.id
        LEFT JOIN attendance a ON a.subject_id=s.id AND a.student_id=?
        GROUP BY s.id
    """, (uid, uid)).fetchall()
    weekly = conn.execute("""
        SELECT date, COUNT(*) as count FROM attendance
        WHERE student_id=? AND date >= date('now','-7 days')
        GROUP BY date ORDER BY date
    """, (uid,)).fetchall()
    monthly = conn.execute("""
        SELECT strftime('%Y-%m', date) as month, COUNT(*) as count
        FROM attendance WHERE student_id=?
        GROUP BY month ORDER BY month DESC LIMIT 6
    """, (uid,)).fetchall()
    total_present = sum(r['present'] for r in rows)
    total_classes = sum(r['total']   for r in rows)
    subjects_out  = []
    for r in rows:
        pct = round(r['present'] / r['total'] * 100) if r['total'] > 0 else 0
        subjects_out.append({
            'id': r['id'], 'name': r['name'], 'teacher': r['teacher'],
            'present': r['present'], 'total': r['total'], 'percentage': pct
        })
    conn.close()
    return jsonify({
        'subjects':      subjects_out,
        'total_present': total_present,
        'total_classes': total_classes,
        'weekly_trend':  [dict(w) for w in weekly],
        'monthly_trend': [dict(m) for m in monthly]
    })

@app.route('/student/mark-attendance', methods=['POST'])
@jwt_required()
@limiter.limit("30 per hour")
def mark_attendance():
    uid  = int(get_jwt_identity())
    user = get_user_by_id(uid)
    if not user or user['type'] != 'student':
        return jsonify({'message':'Unauthorized'}), 403
    data        = request.json
    subject_id  = data.get('subject_id')
    code        = data.get('code','').strip().upper()
    student_lat = data.get('lat')
    student_lng = data.get('lng')
    ip          = request.remote_addr
    conn        = get_db()
    code_row    = conn.execute(
        "SELECT * FROM attendance_codes WHERE code=? AND subject_id=? AND expires_at>?",
        (code, subject_id, datetime.now().isoformat())
    ).fetchone()
    if not code_row:
        conn.close()
        return jsonify({'message':'Invalid or expired code'}), 400
    # Anti-proxy: check if same IP already used this code today
    ip_check = conn.execute(
        "SELECT id FROM attendance WHERE subject_id=? AND ip_address=? AND date=?",
        (subject_id, ip, datetime.now().strftime('%Y-%m-%d'))
    ).fetchone()
    if ip_check:
        conn.execute("INSERT INTO suspicious_flags(student_id,subject_id,reason) VALUES(?,?,?)",
                     (uid, subject_id, f"Duplicate IP {ip}"))
        conn.commit()
        conn.close()
        return jsonify({'message':'Suspicious activity detected. Already marked from this device.'}), 409
    # Geo-location check (FIX 1 already applied — import at top)
    if code_row['lat'] and code_row['lng'] and code_row['radius']:
        if not student_lat or not student_lng:
            conn.close()
            return jsonify({'message':'Location required for this class. Please enable GPS.'}), 400
        R    = 6371000
        lat1, lon1 = radians(float(code_row['lat'])),  radians(float(code_row['lng']))
        lat2, lon2 = radians(float(student_lat)),       radians(float(student_lng))
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        a    = sin(dlat/2)**2 + cos(lat1)*cos(lat2)*sin(dlon/2)**2
        distance = R * 2 * atan2(sqrt(a), sqrt(1-a))
        if distance > float(code_row['radius']):
            conn.execute("INSERT INTO suspicious_flags(student_id,subject_id,reason) VALUES(?,?,?)",
                         (uid, subject_id, f"Out of range: {distance:.0f}m away"))
            conn.commit()
            conn.close()
            return jsonify({'message': f'You are {distance:.0f}m away. Must be within {code_row["radius"]}m.'}), 400
    today = datetime.now().strftime('%Y-%m-%d')
    try:
        conn.execute(
            "INSERT INTO attendance(student_id,subject_id,date,ip_address,lat,lng) VALUES(?,?,?,?,?,?)",
            (uid, subject_id, today, ip, student_lat, student_lng)
        )
        conn.commit()
        # Check for low attendance and alert
        rows = conn.execute("""
            SELECT COUNT(DISTINCT ac.id) as total,
                   COUNT(DISTINCT a.date)  as present
            FROM subjects s
            LEFT JOIN attendance_codes ac ON ac.subject_id=s.id
            LEFT JOIN attendance a ON a.subject_id=s.id AND a.student_id=?
            WHERE s.id=?
        """, (uid, subject_id)).fetchone()
        if rows and rows['total'] > 0:
            pct = round(rows['present'] / rows['total'] * 100)
            if pct < 75:
                subj = conn.execute("SELECT name FROM subjects WHERE id=?", (subject_id,)).fetchone()
                threading.Thread(
                    target=low_attendance_email,
                    args=(user['name'], user['email'], subj['name'] if subj else 'Subject', pct),
                    daemon=True
                ).start()
        conn.close()
        broadcast_ws({'type':'attendance_marked','student': user['name'],'subject_id': subject_id})
        log_activity(uid, user['name'], 'ATTENDANCE_MARKED', f'Subject {subject_id}', ip)
        return jsonify({'message':'Attendance marked successfully!'}), 200
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'message':'Attendance already marked for today'}), 409

# ─── TEACHER ROUTES ───────────────────────────────────────────────────────────
@app.route('/teacher/dashboard', methods=['GET'])
@jwt_required()
def teacher_dashboard():
    uid  = int(get_jwt_identity())
    user = get_user_by_id(uid)
    if not user or user['type'] != 'teacher':
        return jsonify({'message':'Unauthorized'}), 403
    conn     = get_db()
    subjects = conn.execute("""
        SELECT s.id, s.name,
               COUNT(DISTINCT a.student_id) as student_count,
               COUNT(DISTINCT ac.id)        as session_count
        FROM subjects s
        LEFT JOIN attendance a  ON a.subject_id=s.id
        LEFT JOIN attendance_codes ac ON ac.subject_id=s.id
        WHERE s.teacher_id=? GROUP BY s.id
    """, (uid,)).fetchall()
    total_students = conn.execute(
        "SELECT COUNT(DISTINCT a.student_id) FROM attendance a JOIN subjects s ON s.id=a.subject_id WHERE s.teacher_id=?", (uid,)
    ).fetchone()[0]
    total_sessions  = conn.execute("SELECT COUNT(*) FROM attendance_codes WHERE teacher_id=?", (uid,)).fetchone()[0]
    today           = datetime.now().strftime('%Y-%m-%d')
    today_sessions  = conn.execute(
        "SELECT COUNT(*) FROM attendance_codes WHERE teacher_id=? AND date(created_at)=?", (uid, today)
    ).fetchone()[0]
    recent_sessions = conn.execute("""
        SELECT ac.code, s.name as subject, date(ac.created_at) as date,
               COUNT(a.id) as count
        FROM attendance_codes ac
        JOIN subjects s ON s.id=ac.subject_id
        LEFT JOIN attendance a ON a.subject_id=ac.subject_id AND date(a.date)=date(ac.created_at)
        WHERE ac.teacher_id=? GROUP BY ac.id ORDER BY ac.created_at DESC LIMIT 10
    """, (uid,)).fetchall()
    weekly = conn.execute("""
        SELECT date(created_at) as date, COUNT(*) as count
        FROM attendance_codes WHERE teacher_id=? AND date(created_at)>=date('now','-7 days')
        GROUP BY date ORDER BY date
    """, (uid,)).fetchall()
    conn.close()
    return jsonify({
        'subjects':        [dict(s) for s in subjects],
        'total_subjects':  len(subjects),
        'total_students':  total_students,
        'total_sessions':  total_sessions,
        'today_sessions':  today_sessions,
        'recent_sessions': [dict(r) for r in recent_sessions],
        'weekly_trend':    [dict(w) for w in weekly]
    })

@app.route('/teacher/subjects', methods=['POST'])
@jwt_required()
def add_subject():
    uid  = int(get_jwt_identity())
    user = get_user_by_id(uid)
    if not user or user['type'] != 'teacher':
        return jsonify({'message':'Unauthorized'}), 403
    name = request.json.get('name','').strip()
    if not name:
        return jsonify({'message':'Subject name required'}), 400
    conn = get_db()
    conn.execute("INSERT INTO subjects(name,teacher_id) VALUES(?,?)", (name, uid))
    conn.commit()
    conn.close()
    log_activity(uid, user['name'], 'SUBJECT_ADDED', name, request.remote_addr)
    return jsonify({'message':'Subject added'}), 200

@app.route('/teacher/subjects/<int:subject_id>', methods=['DELETE'])
@jwt_required()
def delete_subject(subject_id):
    uid  = int(get_jwt_identity())
    user = get_user_by_id(uid)
    if not user or user['type'] != 'teacher':
        return jsonify({'message':'Unauthorized'}), 403
    conn = get_db()
    conn.execute("DELETE FROM subjects WHERE id=? AND teacher_id=?", (subject_id, uid))
    conn.commit()
    conn.close()
    return jsonify({'message':'Subject removed'}), 200

@app.route('/teacher/generate-code', methods=['POST'])
@jwt_required()
def generate_attendance_code():
    uid  = int(get_jwt_identity())
    user = get_user_by_id(uid)
    if not user or user['type'] != 'teacher':
        return jsonify({'message':'Unauthorized'}), 403
    data       = request.json
    subject_id = data.get('subject_id')
    lat        = data.get('lat')
    lng        = data.get('lng')
    radius     = data.get('radius')
    code       = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    now        = datetime.now()
    expires    = now + timedelta(minutes=2)
    conn       = get_db()
    subj = conn.execute("SELECT * FROM subjects WHERE id=? AND teacher_id=?", (subject_id, uid)).fetchone()
    if not subj:
        conn.close()
        return jsonify({'message':'Subject not found'}), 404
    conn.execute(
        "INSERT INTO attendance_codes(code,subject_id,teacher_id,created_at,expires_at,lat,lng,radius) VALUES(?,?,?,?,?,?,?,?)",
        (code, subject_id, uid, now.isoformat(), expires.isoformat(), lat, lng, radius)
    )
    conn.commit()
    conn.close()
    log_activity(uid, user['name'], 'CODE_GENERATED', f'Subject {subj["name"]} Code {code}', request.remote_addr)
    broadcast_ws({'type':'code_generated','subject': subj['name'],'teacher': user['name']})
    return jsonify({'code': code, 'expires_in': 120, 'geo_enabled': bool(lat and lng and radius)}), 200

@app.route('/teacher/attendance', methods=['GET'])
@jwt_required()
def teacher_attendance():
    uid  = int(get_jwt_identity())
    user = get_user_by_id(uid)
    if not user or user['type'] != 'teacher':
        return jsonify({'message':'Unauthorized'}), 403
    subject_id = request.args.get('subject_id')
    conn       = get_db()
    if subject_id:
        rows = conn.execute("""
            SELECT u.name as student_name, u.email, s.name as subject,
                   COUNT(a.id) as present,
                   (SELECT COUNT(DISTINCT ac.id) FROM attendance_codes ac WHERE ac.subject_id=s.id) as total
            FROM attendance a JOIN users u ON u.id=a.student_id
            JOIN subjects s ON s.id=a.subject_id
            WHERE s.teacher_id=? AND s.id=? GROUP BY u.id, s.id
        """, (uid, subject_id)).fetchall()
    else:
        rows = conn.execute("""
            SELECT u.name as student_name, u.email, s.name as subject,
                   COUNT(a.id) as present,
                   (SELECT COUNT(DISTINCT ac.id) FROM attendance_codes ac WHERE ac.subject_id=s.id) as total
            FROM attendance a JOIN users u ON u.id=a.student_id
            JOIN subjects s ON s.id=a.subject_id
            WHERE s.teacher_id=? GROUP BY u.id, s.id
        """, (uid,)).fetchall()
    conn.close()
    return jsonify({'records': [dict(r) for r in rows]})

@app.route('/teacher/export', methods=['GET'])
@jwt_required()
def teacher_export():
    uid  = int(get_jwt_identity())
    user = get_user_by_id(uid)
    if not user or user['type'] != 'teacher':
        return jsonify({'message':'Unauthorized'}), 403
    subject_id = request.args.get('subject_id')
    fmt        = request.args.get('format','csv')
    conn       = get_db()
    # FIX 4: safe parameterized query instead of string .format()
    if subject_id:
        rows = conn.execute("""
            SELECT u.name as student_name, u.email, s.name as subject, a.date
            FROM attendance a JOIN users u ON u.id=a.student_id
            JOIN subjects s ON s.id=a.subject_id
            WHERE s.teacher_id=? AND s.id=? ORDER BY a.date DESC
        """, (uid, subject_id)).fetchall()
    else:
        rows = conn.execute("""
            SELECT u.name as student_name, u.email, s.name as subject, a.date
            FROM attendance a JOIN users u ON u.id=a.student_id
            JOIN subjects s ON s.id=a.subject_id
            WHERE s.teacher_id=? ORDER BY a.date DESC
        """, (uid,)).fetchall()
    conn.close()
    if fmt == 'csv':
        output = "Student Name,Email,Subject,Date\n"
        for r in rows:
            output += f"{r['student_name']},{r['email']},{r['subject']},{r['date']}\n"
        return Response(output, mimetype='text/csv',
                        headers={"Content-Disposition": "attachment;filename=attendance.csv"})
    return jsonify({'records': [dict(r) for r in rows]})

@app.route('/teacher/export-email', methods=['POST'])
@jwt_required()
def teacher_export_email():
    uid  = int(get_jwt_identity())
    user = get_user_by_id(uid)
    if not user or user['type'] != 'teacher':
        return jsonify({'message':'Unauthorized'}), 403
    subject_id = request.json.get('subject_id')
    conn       = get_db()
    # FIX 4: same safe query here
    if subject_id:
        rows = conn.execute("""
            SELECT u.name as student_name, u.email, s.name as subject, a.date
            FROM attendance a JOIN users u ON u.id=a.student_id
            JOIN subjects s ON s.id=a.subject_id
            WHERE s.teacher_id=? AND s.id=? ORDER BY a.date DESC
        """, (uid, subject_id)).fetchall()
    else:
        rows = conn.execute("""
            SELECT u.name as student_name, u.email, s.name as subject, a.date
            FROM attendance a JOIN users u ON u.id=a.student_id
            JOIN subjects s ON s.id=a.subject_id
            WHERE s.teacher_id=? ORDER BY a.date DESC
        """, (uid,)).fetchall()
    conn.close()
    csv_data = "Student Name,Email,Subject,Date\n"
    for r in rows:
        csv_data += f"{r['student_name']},{r['email']},{r['subject']},{r['date']}\n"
    body = f"""
    <div style="font-family:Arial;max-width:500px;margin:auto;background:#0a0a0f;color:#f0f0f5;padding:32px;border-radius:12px">
      <h2 style="color:#e04c2f">SmartAttend &mdash; Attendance Export</h2>
      <p>Hi <strong>{user['name']}</strong>,</p>
      <p>Please find the attendance report attached as a CSV file.</p>
      <p style="color:#888899;font-size:12px">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
    </div>
    """
    send_email(user['email'], "SmartAttend — Attendance Export", body,
               attachment=csv_data.encode(), attachment_name="attendance.csv")
    return jsonify({'message':'Report sent to your email'}), 200

# ─── ADMIN ROUTES ─────────────────────────────────────────────────────────────
@app.route('/admin/dashboard', methods=['GET'])
@jwt_required()
def admin_dashboard():
    uid  = int(get_jwt_identity())
    user = get_user_by_id(uid)
    if not user or user['type'] != 'admin':
        return jsonify({'message':'Unauthorized'}), 403
    conn            = get_db()
    total_students  = conn.execute("SELECT COUNT(*) FROM users WHERE type='student'").fetchone()[0]
    total_teachers  = conn.execute("SELECT COUNT(*) FROM users WHERE type='teacher'").fetchone()[0]
    total_subjects  = conn.execute("SELECT COUNT(*) FROM subjects").fetchone()[0]
    total_records   = conn.execute("SELECT COUNT(*) FROM attendance").fetchone()[0]
    total_flags     = conn.execute("SELECT COUNT(*) FROM suspicious_flags").fetchone()[0]
    recent_users    = conn.execute(
        "SELECT id,name,email,type,joined FROM users ORDER BY id DESC LIMIT 8"
    ).fetchall()
    active_sessions = conn.execute("""
        SELECT s.name as subject, u.name as teacher
        FROM attendance_codes ac
        JOIN subjects s ON s.id=ac.subject_id
        JOIN users u ON u.id=ac.teacher_id
        WHERE ac.expires_at > ? ORDER BY ac.created_at DESC
    """, (datetime.now().isoformat(),)).fetchall()
    students   = conn.execute(
        "SELECT id,name,email,joined FROM users WHERE type='student' ORDER BY id DESC"
    ).fetchall()
    teachers   = conn.execute("""
        SELECT u.id, u.name, u.email, u.joined,
               GROUP_CONCAT(s.name,', ') as subjects
        FROM users u LEFT JOIN subjects s ON s.teacher_id=u.id
        WHERE u.type='teacher' GROUP BY u.id ORDER BY u.id DESC
    """).fetchall()
    attendance = conn.execute("""
        SELECT u.name as student_name, s.name as subject,
               tu.name as teacher, a.date
        FROM attendance a JOIN users u ON u.id=a.student_id
        JOIN subjects s ON s.id=a.subject_id
        JOIN users tu ON tu.id=s.teacher_id
        ORDER BY a.date DESC LIMIT 100
    """).fetchall()
    flags = conn.execute("""
        SELECT sf.*, u.name as student_name, s.name as subject_name
        FROM suspicious_flags sf
        LEFT JOIN users u ON u.id=sf.student_id
        LEFT JOIN subjects s ON s.id=sf.subject_id
        ORDER BY sf.created_at DESC LIMIT 50
    """).fetchall()
    logs = conn.execute(
        "SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 100"
    ).fetchall()
    monthly = conn.execute("""
        SELECT strftime('%Y-%m', date) as month, COUNT(*) as count
        FROM attendance GROUP BY month ORDER BY month DESC LIMIT 6
    """).fetchall()
    conn.close()
    return jsonify({
        'total_students':  total_students, 'total_teachers': total_teachers,
        'total_subjects':  total_subjects, 'total_records':  total_records,
        'total_flags':     total_flags,
        'recent_users':    [dict(r) for r in recent_users],
        'active_sessions': [dict(r) for r in active_sessions],
        'students':        [dict(r) for r in students],
        'teachers':        [dict(r) for r in teachers],
        'attendance':      [dict(r) for r in attendance],
        'flags':           [dict(r) for r in flags],
        'logs':            [dict(r) for r in logs],
        'monthly_trend':   [dict(m) for m in monthly]
    })

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def admin_delete_user(user_id):
    uid  = int(get_jwt_identity())
    user = get_user_by_id(uid)
    if not user or user['type'] != 'admin':
        return jsonify({'message':'Unauthorized'}), 403
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    log_activity(uid, user['name'], 'USER_DELETED', f'User ID {user_id}', request.remote_addr)
    return jsonify({'message':'User removed'}), 200

@app.route('/admin/logs', methods=['GET'])
@jwt_required()
def admin_logs():
    uid  = int(get_jwt_identity())
    user = get_user_by_id(uid)
    if not user or user['type'] != 'admin':
        return jsonify({'message':'Unauthorized'}), 403
    conn = get_db()
    logs = conn.execute(
        "SELECT * FROM activity_logs ORDER BY created_at DESC LIMIT 200"
    ).fetchall()
    conn.close()
    return jsonify({'logs': [dict(l) for l in logs]})

# ─── CLEANUP EXPIRED ──────────────────────────────────────────────────────────
def cleanup_expired():
    while True:
        try:
            conn = get_db()
            conn.execute("DELETE FROM attendance_codes WHERE expires_at<?", (datetime.now().isoformat(),))
            conn.execute("DELETE FROM otps WHERE expires<?", (datetime.now().isoformat(),))
            conn.commit()
            conn.close()
        except:
            pass
        time.sleep(60)

# ─── RUN ──────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    threading.Thread(target=cleanup_expired, daemon=True).start()
    port = int(os.environ.get('PORT', 10000))   # FIX 5: respect PORT env var (Render sets this)
    app.run(host='0.0.0.0', port=port, debug=False)
