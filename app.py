from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3, hashlib, random, string, smtplib, os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import threading, time

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)

# ─── CONFIG ───────────────────────────────────────────────────────────────────
EMAIL_SENDER   = "smart.codemark.attendance@gmail.com"
EMAIL_PASSWORD = "bfsq fiaj felf pcwy"
