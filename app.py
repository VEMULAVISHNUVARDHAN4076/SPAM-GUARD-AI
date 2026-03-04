from flask import Flask, render_template, request, redirect, url_for, session, flash
from functools import wraps
import pickle
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re
import requests
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = 'super_secret_key_987654321_change_me_in_real_app'

DB_PATH = 'users.db'

model = pickle.load(open("model.pkl", "rb"))
vectorizer = pickle.load(open("vectorizer.pkl", "rb"))

def init_db():
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        hashed_pw = generate_password_hash("spam123")
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("admin", hashed_pw))
            conn.commit()
        except sqlite3.IntegrityError:
            pass
        conn.close()
init_db()

@app.before_request
def enforce_trial_limit():
    if request.endpoint in ['predict_message', 'predict_url'] and 'user' not in session:
        now = datetime.now()
        if 'trial_reset_time' not in session:
            session['trial_reset_time'] = now.isoformat()
            session['trial_uses'] = 0

        reset_time = datetime.fromisoformat(session['trial_reset_time'])
        if now - reset_time >= timedelta(hours=24):
            session['trial_uses'] = 0
            session['trial_reset_time'] = now.isoformat()

        if session['trial_uses'] >= 3:
            flash("Trial limit reached (3 checks). Please login to continue or wait 24 hours for reset.", "warning")
            return redirect(url_for('login'))

def extract_urls(text):
    pattern = r'(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:\'".,<>?«»“”‘’]))'
    return re.findall(pattern, text)

def check_google_safe_browsing(url, api_key):
    endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "spamguard-ai", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    params = {"key": api_key}
    try:
        response = requests.post(endpoint, params=params, json=payload, timeout=6)
        response.raise_for_status()
        data = response.json()
        if "matches" in data and data["matches"]:
            threats = [m["threatType"] for m in data["matches"]]
            return "MALICIOUS", f"Flagged by Google: {', '.join(threats)}"
        return "SAFE", "No threats found"
    except Exception as e:
        return "ERROR", f"Check failed: {str(e)}"

def check_urlhaus(url):
    try:
        resp = requests.get("https://urlhaus-api.abuse.ch/v1/url/", params={"url": url}, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("query_status") == "malicious":
                return True, "Listed in URLhaus as malware distribution"
        return False, ""
    except:
        return False, ""

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if not username or not password:
            flash("Username and password are required.", "danger")
            return render_template("register.html")
        if len(password) < 6:
            flash("Password must be at least 6 characters.", "danger")
            return render_template("register.html")
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE username = ?", (username,))
        if c.fetchone():
            flash("Username already taken.", "danger")
            conn.close()
            return render_template("register.html")
        hashed_pw = generate_password_hash(password)
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
            conn.commit()
            flash("Registration successful! Please login.", "success")
            conn.close()
            return redirect(url_for("login"))
        except Exception as e:
            flash("Error creating account.", "danger")
            conn.close()
            return render_template("register.html")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        conn.close()
        if result and check_password_hash(result[0], password):
            session["user"] = username
            flash(f"Welcome back, {username}!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid username or password.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))

@app.route("/", methods=["GET"])
def home():
    is_logged_in = "user" in session
    username = session.get("user", "Guest")
   
    trial_remaining = None
    if not is_logged_in:
        now = datetime.now()
        if 'trial_reset_time' in session:
            reset_time = datetime.fromisoformat(session['trial_reset_time'])
            if now - reset_time >= timedelta(hours=24):
                session['trial_uses'] = 0
                session['trial_reset_time'] = now.isoformat()
        uses = session.get('trial_uses', 0)
        trial_remaining = max(3 - uses, 0)
   
    return render_template("index.html",
                         username=username,
                         is_logged_in=is_logged_in,
                         trial_remaining=trial_remaining)

@app.route("/predict", methods=["GET"])
def predict_get():
    return redirect(url_for('home'))
    
@app.route("/predict_message", methods=["POST"])
def predict_message():
    message = request.form.get("message", "").strip()
    if not message:
        flash("Please enter a message to check.", "warning")
        return redirect(url_for("home"))

    if 'user' not in session:
        session['trial_uses'] = session.get('trial_uses', 0) + 1

    urls = extract_urls(message)
    url_results = []

    SAFE_BROWSING_API_KEY = os.environ.get("AIzaSyA8N2UdJy_EwevmCRyAh6fHP1DoWLmP1ak")

    if urls and SAFE_BROWSING_API_KEY:
        for url in urls:
            status, reason = check_google_safe_browsing(url, SAFE_BROWSING_API_KEY)
            if status == "SAFE":
                is_malware, haus_reason = check_urlhaus(url)
                if is_malware:
                    status = "MALICIOUS"
                    reason = haus_reason
            url_results.append({"url": url.strip(), "status": status, "reason": reason})

    lower_msg = message.lower()
    suspicious_keywords = [
        'parcel', 'package', 'delivery', 'customs', 'clearance', 'fee', 'pay now',
        'held at', 'urgent payment', 'bit.ly', 'tinyurl', '₹', 'custom duty',
        'dhl', 'fedex', 'india post', 'clear custom'
    ]
    has_suspicious = any(word in lower_msg for word in suspicious_keywords)
    has_pay_mention = 'pay' in lower_msg or 'payment' in lower_msg or '₹' in lower_msg
    has_link = any(x in lower_msg for x in ['http', 'www.', 'bit.ly', 'tinyurl'])
    
    if has_suspicious and has_pay_mention and (has_link or 'urgent' in lower_msg or 'held' in lower_msg):
        result = "LIKELY SPAM (possible delivery/customs scam)"
        spam_prob = 92.0
        is_spam = True
    else:
        message_vector = vectorizer.transform([message])
        prediction = model.predict(message_vector)[0]
        probs = model.predict_proba(message_vector)[0]
        spam_prob = probs[1] * 100
        result = "SPAM" if prediction == 1 else "NOT SPAM"
        is_spam = (prediction == 1)

    return render_template("index.html",
                         result=result,
                         prob=round(spam_prob, 2),
                         is_spam=is_spam,
                         username=session.get("user", "Guest"),
                         is_logged_in="user" in session,
                         url_results=url_results,
                         trial_remaining = max(3 - session.get('trial_uses', 0), 0) if 'user' not in session else None)

@app.route("/predict_url", methods=["POST"])
def predict_url():
    url = request.form.get("url", "").strip()

    if not url:
        flash("Please enter a URL to check.", "warning")
        return redirect(url_for("home"))

    if 'user' not in session:
        session['trial_uses'] = session.get('trial_uses', 0) + 1

    SAFE_BROWSING_API_KEY = os.environ.get("AIzaSyA8N2UdJy_EwevmCRyAh6fHP1DoWLmP1ak")

    status = "UNKNOWN"
    reason = "Could not check URL"

    if SAFE_BROWSING_API_KEY:
        status, reason = check_google_safe_browsing(url, SAFE_BROWSING_API_KEY)
        if status == "SAFE":
            is_malware, haus_reason = check_urlhaus(url)
            if is_malware:
                status = "MALICIOUS"
                reason = haus_reason

    return render_template("index.html",
                       url_result=True,   # ✅ ADD THIS LINE
                       checked_url=url,
                       url_status=status,
                       url_reason=reason,
                       username=session.get("user", "Guest"),
                       is_logged_in="user" in session,
                       trial_remaining=max(3 - session.get('trial_uses', 0), 0)
                       if 'user' not in session else None)

if __name__ == "__main__":
    app.run(debug=True)
