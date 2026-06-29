from flask import Flask, render_template, request, redirect
import sqlite3
from datetime import datetime
from zoneinfo import ZoneInfo

app = Flask(__name__)

# -------------------- Create Database --------------------
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            device TEXT,
            timestamp TEXT,
            status TEXT,
            alert TEXT
        )
    """)

    conn.commit()
    conn.close()


init_db()


# -------------------- Detect Browser --------------------
def get_browser(user_agent):
    user_agent = user_agent.lower()

    if "edg" in user_agent:
        return "Microsoft Edge"
    elif "chrome" in user_agent and "edg" not in user_agent:
        return "Google Chrome"
    elif "firefox" in user_agent:
        return "Mozilla Firefox"
    elif "safari" in user_agent and "chrome" not in user_agent:
        return "Safari"
    elif "opr" in user_agent or "opera" in user_agent:
        return "Opera"
    else:
        return "Unknown Browser"


# -------------------- Home --------------------
@app.route("/")
def home():
    return render_template("login.html")


# -------------------- Login --------------------
@app.route("/login", methods=["POST"])
def login():

    username = request.form["username"]
    password = request.form["password"]

    browser = get_browser(request.headers.get("User-Agent", ""))

    current_time = datetime.now(ZoneInfo("Asia/Kolkata"))
    current_timestamp = current_time.isoformat()
    one_minute_ago = current_time.timestamp() - 60

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    alert_type = "none"
    alert_message = None

    # ---------------- Normal Login ----------------
    if username == "admin" and password == "1234":
        status = "success"
    else:
        status = "failed"

    # =====================================================
    # Model 2 : New Browser Detection
    # =====================================================
    cursor.execute(
        "SELECT device FROM logins WHERE username=?",
        (username,)
    )

    known_browsers = [row[0] for row in cursor.fetchall()]

    if known_browsers and browser not in known_browsers:
        alert_message = "🌐 ALERT: Login from a new browser detected."
        alert_type = "browser"

    # =====================================================
    # Model 3 : Time Detection
    # =====================================================
    if current_time.hour >= 0:

        if alert_message:
            alert_message += " + ⏰ Unusual login time detected."
        else:
            alert_message = "⏰ ALERT: Login at unusual time detected."

        alert_type = "time"

    # =====================================================
    # Store Current Login
    # =====================================================
    cursor.execute("""
        INSERT INTO logins
        (username,password,device,timestamp,status,alert)
        VALUES (?,?,?,?,?,?)
    """, (
        username,
        password,
        browser,
        current_timestamp,
        status,
        alert_type
    ))

    conn.commit()

    # =====================================================
    # Model 4 : Spike Detection
    # =====================================================
    cursor.execute("SELECT timestamp FROM logins")
    rows = cursor.fetchall()

    spike_count = 0

    for row in rows:
        try:
            log_time = datetime.fromisoformat(row[0]).timestamp()

            if log_time >= one_minute_ago:
                spike_count += 1

        except Exception:
            pass

    if spike_count >= 5:
        conn.close()
        return render_template(
            "alert.html",
            message="⚡ ALERT: Too many login attempts in a short time (Spike Detected)"
        )

    # =====================================================
    # Model 1 : Brute Force Detection
    # =====================================================
    cursor.execute("""
        SELECT timestamp
        FROM logins
        WHERE username=? AND status='failed'
    """, (username,))

    rows = cursor.fetchall()

    failed_attempts = 0

    for row in rows:
        try:
            log_time = datetime.fromisoformat(row[0]).timestamp()

            if log_time >= one_minute_ago:
                failed_attempts += 1

        except Exception:
            pass

    if failed_attempts >= 5:
        conn.close()
        return render_template(
            "alert.html",
            message="🚨 ALERT: Too many failed login attempts (Brute Force Detected)"
        )

    conn.close()

    # =====================================================
    # Show Browser / Time Alert
    # =====================================================
    if alert_message:
        return render_template("alert.html", message=alert_message)

    # =====================================================
    # Redirect
    # =====================================================
    if status == "success":
        return redirect("/dashboard")
    else:
        return "Login Failed"


# -------------------- Dashboard --------------------
@app.route("/dashboard")
def dashboard():

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM logins")
    total = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logins WHERE status='success'")
    success = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM logins WHERE status='failed'")
    failed = cursor.fetchone()[0]

    cursor.execute("""
        SELECT username, device, timestamp, status
        FROM logins
        ORDER BY id DESC
        LIMIT 10
    """)

    logs = cursor.fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        total=total,
        success=success,
        failed=failed,
        logs=logs
    )


# -------------------- Run --------------------
if __name__ == "__main__":
    app.run(debug=True)
