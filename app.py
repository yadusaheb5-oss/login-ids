from flask import Flask, render_template, request, redirect
import sqlite3
from datetime import datetime

app = Flask(__name__)

# Create database
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS logins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            ip_address TEXT,
            timestamp TEXT,
            status TEXT,
            alert TEXT
        )
    ''')

    conn.commit()
    conn.close()

init_db()

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    ip_address = request.form.get('ip', request.remote_addr)

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    alert_type = "none"

    # ⚡ Model 4: Spike Detection
    one_minute_ago = datetime.now().timestamp() - 60

    cursor.execute("SELECT timestamp FROM logins")
    recent_attempts = cursor.fetchall()

    count = 0
    for row in recent_attempts:
        try:
            log_time = datetime.fromisoformat(row[0]).timestamp()
            if log_time >= one_minute_ago:
                count += 1
        except:
            pass

    if count >= 5:
        alert_type = "spike"
        conn.close()
        return render_template("alert.html", message="⚡ ALERT: Too many login attempts in short time (Spike Detected)")

    # 🔴 Model 1: Brute Force Detection
    cursor.execute("SELECT timestamp FROM logins WHERE username=? AND status='failed'", (username,))
    rows = cursor.fetchall()

    failed_attempts = 0
    for row in rows:
        try:
            log_time = datetime.fromisoformat(row[0]).timestamp()
            if log_time >= one_minute_ago:
                failed_attempts += 1
        except:
            pass

    if failed_attempts >= 5:
        alert_type = "brute"
        conn.close()
        return render_template("alert.html", message="🚨 ALERT: Too many failed attempts (Brute Force Detected)")

    # 🔍 Get previous IPs
    cursor.execute("SELECT ip_address FROM logins WHERE username=?", (username,))
    known_ips = list(set([row[0] for row in cursor.fetchall()]))

    print("Current IP:", ip_address)
    print("Known IPs:", known_ips)

    alert_message = None

    # 🌍 Model 2: IP Detection
    if len(known_ips) > 0 and ip_address not in known_ips:
        alert_message = "🌍 ALERT: Login from new IP address detected"
        alert_type = "ip"

    # ⏰ Model 3: Time Detection
    current_hour = datetime.now().hour
    if current_hour < 9 or current_hour > 22:
        if alert_message:
            alert_message += " + ⏰ Unusual login time"
        else:
            alert_message = "⏰ ALERT: Login at unusual time detected"
        alert_type = "time"

    # ✅ Normal login
    if username == "admin" and password == "1234":
        status = "success"
    else:
        status = "failed"

    # 💾 Store login
    cursor.execute(
        "INSERT INTO logins (username, password, ip_address, timestamp, status, alert) VALUES (?, ?, ?, ?, ?, ?)",
        (username, password, ip_address, datetime.now(), status, alert_type)
    )

    conn.commit()
    conn.close()

    # 🚨 Show alerts if any
    if alert_message:
        return render_template("alert.html", message=alert_message)

    # ✅ Redirect on success
    if status == "success":
        return redirect("/dashboard")
    else:
        return "Login failed"


@app.route('/dashboard')
def dashboard():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM logins")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logins WHERE status='success'")
    success = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logins WHERE status='failed'")
    failed = cursor.fetchone()[0]

    cursor.execute("SELECT username, ip_address, timestamp, status FROM logins ORDER BY id DESC LIMIT 10")
    logs = cursor.fetchall()

    conn.close()

    return render_template("dashboard.html", total=total, success=success, failed=failed, logs=logs)


if __name__ == '__main__':
    app.run(debug=True)