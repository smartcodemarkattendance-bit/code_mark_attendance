from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3, hashlib, random, string, os
from datetime import datetime, timedelta
import threading, time

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

DB_PATH = "smartattend.db"

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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            type TEXT NOT NULL CHECK(type IN ('student','teacher','admin')),
            verified INTEGER DEFAULT 0,
            joined TEXT DEFAULT (date('now'))
        );
        CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            otp TEXT NOT NULL,
            expires TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            teacher_id INTEGER NOT NULL,
            FOREIGN KEY(teacher_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS attendance_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            subject_id INTEGER NOT NULL,
            teacher_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(subject_id) REFERENCES subjects(id)
        );
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            subject_id INTEGER NOT NULL,
            date TEXT NOT NULL,
            UNIQUE(student_id, subject_id, date),
            FOREIGN KEY(student_id) REFERENCES users(id),
            FOREIGN KEY(subject_id) REFERENCES subjects(id)
        );
    """)
    conn.commit()
    conn.close()

# ─── HELPERS ──────────────────────────────────────────────────────────────────

def hash_pass(p):
    return hashlib.sha256(p.encode()).hexdigest()

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def store_otp(email, otp):
    conn = get_db()
    expires = (datetime.now() + timedelta(minutes=10)).isoformat()
    conn.execute("DELETE FROM otps WHERE email=?", (email,))
    conn.execute("INSERT INTO otps(email,otp,expires) VALUES(?,?,?)", (email, otp, expires))
    conn.commit()
    conn.close()

def verify_otp_db(email, otp):
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM otps WHERE email=? AND otp=? AND expires>?",
        (email, otp, datetime.now().isoformat())
    ).fetchone()
    if row:
        conn.execute("DELETE FROM otps WHERE email=?", (email,))
        conn.commit()
    conn.close()
    return row is not None

def get_user_by_email(email):
    conn = get_db()
    u = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    conn.close()
    return dict(u) if u else None

def current_user_from_request():
    email = request.headers.get('X-User-Email')
    if not email:
        return None
    return get_user_by_email(email)

# ─── SERVE INDEX ──────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return app.send_static_file('index.html')

# ─── AUTH ROUTES ──────────────────────────────────────────────────────────────

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    name = data.get('name','').strip()
    email = data.get('email','').strip().lower()
    pwd = data.get('password','')
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
    conn.execute(
        "INSERT INTO users(name,email,password,type,verified) VALUES(?,?,?,?,0)",
        (name, email, hash_pass(pwd), utype)
    )
    conn.commit()
    conn.close()

    otp = generate_otp()
    store_otp(email, otp)
    # Return OTP to frontend — EmailJS sends the email
    return jsonify({'message':'OTP ready', 'otp': otp, 'name': name}), 200


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email','').strip().lower()
    pwd = data.get('password','')
    user = get_user_by_email(email)
    if not user or user['password'] != hash_pass(pwd):
        return jsonify({'message':'Invalid email or password'}), 401

    otp = generate_otp()
    store_otp(email, otp)
    # Return OTP to frontend — EmailJS sends the email
    return jsonify({'message':'OTP ready', 'otp': otp, 'name': user['name']}), 200


@app.route('/verify', methods=['POST'])
def verify():
    data = request.json
    email = data.get('email','').strip().lower()
    otp = data.get('otp','').strip()
    if not verify_otp_db(email, otp):
        return jsonify({'message':'Invalid or expired OTP'}), 401
    conn = get_db()
    conn.execute("UPDATE users SET verified=1 WHERE email=?", (email,))
    conn.commit()
    conn.close()
    user = get_user_by_email(email)
    return jsonify({'message':'Verified', 'user': {
        'id': user['id'], 'name': user['name'],
        'email': user['email'], 'type': user['type']
    }}), 200


@app.route('/resend-otp', methods=['POST'])
def resend_otp():
    data = request.json
    email = data.get('email','').strip().lower()
    user = get_user_by_email(email)
    if not user:
        return jsonify({'message':'Email not found'}), 404
    otp = generate_otp()
    store_otp(email, otp)
    # Return OTP to frontend — EmailJS sends the email
    return jsonify({'message':'OTP ready', 'otp': otp, 'name': user['name']}), 200

# ─── STUDENT ROUTES ───────────────────────────────────────────────────────────

@app.route('/student/dashboard', methods=['GET'])
def student_dashboard():
    user = current_user_from_request()
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
    """, (user['id'], user['id'])).fetchall()

    total_present = sum(r['present'] for r in rows)
    total_classes = sum(r['total'] for r in rows)
    subjects_out = []
    for r in rows:
        pct = round(r['present'] / r['total'] * 100) if r['total'] > 0 else 0
        subjects_out.append({
            'id': r['id'], 'name': r['name'], 'teacher': r['teacher'],
            'present': r['present'], 'total': r['total'], 'percentage': pct
        })
    conn.close()
    return jsonify({
        'subjects': subjects_out,
        'total_present': total_present,
        'total_classes': total_classes
    })


@app.route('/student/mark-attendance', methods=['POST'])
def mark_attendance():
    user = current_user_from_request()
    if not user or user['type'] != 'student':
        return jsonify({'message':'Unauthorized'}), 403
    data = request.json
    subject_id = data.get('subject_id')
    code = data.get('code','').strip().upper()
    conn = get_db()
    code_row = conn.execute(
        "SELECT * FROM attendance_codes WHERE code=? AND subject_id=? AND expires_at>?",
        (code, subject_id, datetime.now().isoformat())
    ).fetchone()
    if not code_row:
        conn.close()
        return jsonify({'message':'Invalid or expired code'}), 400
    today = datetime.now().strftime('%Y-%m-%d')
    try:
        conn.execute(
            "INSERT INTO attendance(student_id,subject_id,date) VALUES(?,?,?)",
            (user['id'], subject_id, today)
        )
        conn.commit()
        conn.close()
        return jsonify({'message':'Attendance marked!'}), 200
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'message':'Attendance already marked for today'}), 409

# ─── TEACHER ROUTES ───────────────────────────────────────────────────────────

@app.route('/teacher/dashboard', methods=['GET'])
def teacher_dashboard():
    user = current_user_from_request()
    if not user or user['type'] != 'teacher':
        return jsonify({'message':'Unauthorized'}), 403
    conn = get_db()
    subjects = conn.execute(
        "SELECT s.id, s.name, COUNT(DISTINCT a.student_id) as student_count, COUNT(DISTINCT ac.id) as session_count FROM subjects s LEFT JOIN attendance a ON a.subject_id=s.id LEFT JOIN attendance_codes ac ON ac.subject_id=s.id WHERE s.teacher_id=? GROUP BY s.id",
        (user['id'],)
    ).fetchall()
    total_students = conn.execute(
        "SELECT COUNT(DISTINCT a.student_id) FROM attendance a JOIN subjects s ON s.id=a.subject_id WHERE s.teacher_id=?",
        (user['id'],)
    ).fetchone()[0]
    total_sessions = conn.execute(
        "SELECT COUNT(*) FROM attendance_codes WHERE teacher_id=?", (user['id'],)
    ).fetchone()[0]
    today = datetime.now().strftime('%Y-%m-%d')
    today_sessions = conn.execute(
        "SELECT COUNT(*) FROM attendance_codes WHERE teacher_id=? AND date(created_at)=?",
        (user['id'], today)
    ).fetchone()[0]
    recent_sessions = conn.execute("""
        SELECT ac.code, s.name as subject, date(ac.created_at) as date,
            COUNT(a.id) as count
        FROM attendance_codes ac
        JOIN subjects s ON s.id=ac.subject_id
        LEFT JOIN attendance a ON a.subject_id=ac.subject_id AND date(a.date)=date(ac.created_at)
        WHERE ac.teacher_id=?
        GROUP BY ac.id ORDER BY ac.created_at DESC LIMIT 10
    """, (user['id'],)).fetchall()
    conn.close()
    return jsonify({
        'subjects': [dict(s) for s in subjects],
        'total_subjects': len(subjects),
        'total_students': total_students,
        'total_sessions': total_sessions,
        'today_sessions': today_sessions,
        'recent_sessions': [dict(r) for r in recent_sessions]
    })


@app.route('/teacher/subjects', methods=['POST'])
def add_subject():
    user = current_user_from_request()
    if not user or user['type'] != 'teacher':
        return jsonify({'message':'Unauthorized'}), 403
    name = request.json.get('name','').strip()
    if not name:
        return jsonify({'message':'Subject name required'}), 400
    conn = get_db()
    conn.execute("INSERT INTO subjects(name,teacher_id) VALUES(?,?)", (name, user['id']))
    conn.commit()
    conn.close()
    return jsonify({'message':'Subject added'}), 200


@app.route('/teacher/subjects/<int:subject_id>', methods=['DELETE'])
def delete_subject(subject_id):
    user = current_user_from_request()
    if not user or user['type'] != 'teacher':
        return jsonify({'message':'Unauthorized'}), 403
    conn = get_db()
    conn.execute("DELETE FROM subjects WHERE id=? AND teacher_id=?", (subject_id, user['id']))
    conn.commit()
    conn.close()
    return jsonify({'message':'Subject removed'}), 200


@app.route('/teacher/generate-code', methods=['POST'])
def generate_attendance_code():
    user = current_user_from_request()
    if not user or user['type'] != 'teacher':
        return jsonify({'message':'Unauthorized'}), 403
    subject_id = request.json.get('subject_id')
    code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    now = datetime.now()
    expires = now + timedelta(minutes=2)
    conn = get_db()
    subj = conn.execute("SELECT * FROM subjects WHERE id=? AND teacher_id=?", (subject_id, user['id'])).fetchone()
    if not subj:
        conn.close()
        return jsonify({'message':'Subject not found'}), 404
    conn.execute(
        "INSERT INTO attendance_codes(code,subject_id,teacher_id,created_at,expires_at) VALUES(?,?,?,?,?)",
        (code, subject_id, user['id'], now.isoformat(), expires.isoformat())
    )
    conn.commit()
    conn.close()
    return jsonify({'code': code, 'expires_in': 120}), 200


@app.route('/teacher/attendance', methods=['GET'])
def teacher_attendance():
    user = current_user_from_request()
    if not user or user['type'] != 'teacher':
        return jsonify({'message':'Unauthorized'}), 403
    subject_id = request.args.get('subject_id')
    conn = get_db()
    if subject_id:
        rows = conn.execute("""
            SELECT u.name as student_name, s.name as subject,
                COUNT(a.id) as present,
                (SELECT COUNT(DISTINCT ac.id) FROM attendance_codes ac WHERE ac.subject_id=s.id) as total
            FROM attendance a
            JOIN users u ON u.id=a.student_id
            JOIN subjects s ON s.id=a.subject_id
            WHERE s.teacher_id=? AND s.id=?
            GROUP BY u.id, s.id
        """, (user['id'], subject_id)).fetchall()
    else:
        rows = conn.execute("""
            SELECT u.name as student_name, s.name as subject,
                COUNT(a.id) as present,
                (SELECT COUNT(DISTINCT ac.id) FROM attendance_codes ac WHERE ac.subject_id=s.id) as total
            FROM attendance a
            JOIN users u ON u.id=a.student_id
            JOIN subjects s ON s.id=a.subject_id
            WHERE s.teacher_id=?
            GROUP BY u.id, s.id
        """, (user['id'],)).fetchall()
    conn.close()
    return jsonify({'records': [dict(r) for r in rows]})

# ─── ADMIN ROUTES ─────────────────────────────────────────────────────────────

@app.route('/admin/dashboard', methods=['GET'])
def admin_dashboard():
    user = current_user_from_request()
    if not user or user['type'] != 'admin':
        return jsonify({'message':'Unauthorized'}), 403
    conn = get_db()
    total_students = conn.execute("SELECT COUNT(*) FROM users WHERE type='student'").fetchone()[0]
    total_teachers = conn.execute("SELECT COUNT(*) FROM users WHERE type='teacher'").fetchone()[0]
    total_subjects = conn.execute("SELECT COUNT(*) FROM subjects").fetchone()[0]
    total_records = conn.execute("SELECT COUNT(*) FROM attendance").fetchone()[0]
    recent_users = conn.execute(
        "SELECT id,name,email,type,joined FROM users ORDER BY id DESC LIMIT 5"
    ).fetchall()
    active_sessions = conn.execute("""
        SELECT s.name as subject, u.name as teacher
        FROM attendance_codes ac
        JOIN subjects s ON s.id=ac.subject_id
        JOIN users u ON u.id=ac.teacher_id
        WHERE ac.expires_at > ? ORDER BY ac.created_at DESC
    """, (datetime.now().isoformat(),)).fetchall()
    students = conn.execute(
        "SELECT id,name,email,joined FROM users WHERE type='student' ORDER BY id DESC"
    ).fetchall()
    teachers = conn.execute("""
        SELECT u.id, u.name, u.email, u.joined,
            GROUP_CONCAT(s.name,', ') as subjects
        FROM users u
        LEFT JOIN subjects s ON s.teacher_id=u.id
        WHERE u.type='teacher'
        GROUP BY u.id ORDER BY u.id DESC
    """).fetchall()
    attendance = conn.execute("""
        SELECT u.name as student_name, s.name as subject,
            tu.name as teacher, a.date
        FROM attendance a
        JOIN users u ON u.id=a.student_id
        JOIN subjects s ON s.id=a.subject_id
        JOIN users tu ON tu.id=s.teacher_id
        ORDER BY a.date DESC LIMIT 50
    """).fetchall()
    conn.close()
    return jsonify({
        'total_students': total_students,
        'total_teachers': total_teachers,
        'total_subjects': total_subjects,
        'total_records': total_records,
        'recent_users': [dict(r) for r in recent_users],
        'active_sessions': [dict(r) for r in active_sessions],
        'students': [dict(r) for r in students],
        'teachers': [dict(r) for r in teachers],
        'attendance': [dict(r) for r in attendance]
    })


@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    user = current_user_from_request()
    if not user or user['type'] != 'admin':
        return jsonify({'message':'Unauthorized'}), 403
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return jsonify({'message':'User removed'}), 200

# ─── CLEANUP EXPIRED CODES ────────────────────────────────────────────────────

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

# ─── STARTUP (works with gunicorn AND python app.py) ─────────────────────────
init_db()
threading.Thread(target=cleanup_expired, daemon=True).start()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000)
