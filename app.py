from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3, hashlib, random, string, smtplib, os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import threading, time

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

# DATABASE SETUP
def get_db():
    conn = sqlite3.connect("smartattend.db")
    conn.row_factory = sqlite3.Row
    return conn

with app.app_context():
    conn = get_db()

    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            type TEXT NOT NULL,
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
            teacher_id INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS attendance_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            subject_id INTEGER NOT NULL,
            teacher_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            subject_id INTEGER NOT NULL,
            date TEXT NOT NULL
        );
    """)

    conn.commit()
    conn.close()

# CONFIG
EMAIL_SENDER = "smart.codemark.attendance@gmail.com"
EMAIL_PASSWORD = "bfsq fiaj felf pcwy"
DB_PATH = "smartattend.db"
