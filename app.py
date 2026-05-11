from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import smtplib
import random
from email.mime.text import MIMEText

app = Flask(__name__)
CORS(app)

# EMAIL CONFIG
EMAIL_SENDER = "smart.codemark.attendance@gmail.com"
EMAIL_PASSWORD = "bfsq fiaj felf pcwy"

# DATABASE
def get_db():
    conn = sqlite3.connect("smartattend.db")
    conn.row_factory = sqlite3.Row
    return conn

# CREATE TABLE
conn = get_db()

conn.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT,
    password TEXT
)
""")

conn.commit()
conn.close()

# HOME ROUTE
@app.route("/")
def home():
    return "SmartAttend Backend Running"

# REGISTER ROUTE
@app.route("/register", methods=["POST"])
def register():

    data = request.get_json()

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    otp = str(random.randint(100000, 999999))

    conn = get_db()

    conn.execute(
        "INSERT INTO users (name,email,password) VALUES (?,?,?)",
        (name, email, password)
    )

    conn.commit()
    conn.close()

    try:
        msg = MIMEText(f"Your SmartAttend OTP is: {otp}")

        msg["Subject"] = "SmartAttend OTP"
        msg["From"] = EMAIL_SENDER
        msg["To"] = email

        server = smtplib.SMTP_SSL("smtp.gmail.com", 465)

        server.login(EMAIL_SENDER, EMAIL_PASSWORD)

        server.sendmail(
            EMAIL_SENDER,
            email,
            msg.as_string()
        )

        server.quit()

    except Exception as e:
        return jsonify({
            "message": str(e)
        }), 500

    return jsonify({
        "message": "OTP sent successfully",
        "otp": otp
    })

# RUN
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
