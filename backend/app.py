from flask import Flask, jsonify, request, session, render_template, redirect
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from database import create_tables, connect_db
from scanner import scan_cloud_config

import os
import json

# ---------------- BASE DIR ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------- APP SETUP ----------------
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"))
CORS(app, supports_credentials=True)

app.secret_key = "armoredsec_secret_key"

# 🔥 IMPORTANT: CREATE TABLES FOR RENDER
create_tables()


# ---------------- RISK SCORE FUNCTION ----------------
def calculate_risk(alerts):

    risk_points = 0

    for alert in alerts:
        severity = alert[3]

        if severity == "Critical":
            risk_points += 30
        elif severity == "High":
            risk_points += 20
        elif severity == "Medium":
            risk_points += 10
        elif severity == "Low":
            risk_points += 5

    score = max(0, 100 - risk_points)

    return score


# ---------------- HOME ROUTE ----------------
@app.route("/")
def home():
    return redirect("/loginpage")


# ---------------- LOGIN PAGE ----------------
@app.route("/loginpage")
def login_page():
    return render_template("login.html")


# ---------------- DASHBOARD PAGE ----------------
@app.route("/dashboard")
def dashboard_page():

    if "user" not in session:
        return redirect("/loginpage")

    return render_template("dashboard.html")


# ---------------- SIGNUP API ----------------
@app.route("/signup", methods=["POST"])
def signup():

    data = request.json
    username = data["username"]
    password = data["password"]

    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    existing_user = cursor.fetchone()

    if existing_user:
        conn.close()
        return jsonify({"message": "Username already exists"})

    hashed_password = generate_password_hash(password)

    cursor.execute(
        "INSERT INTO users(username,password) VALUES (?,?)",
        (username, hashed_password)
    )

    conn.commit()
    conn.close()

    return jsonify({"message": "User Registered Successfully"})


# ---------------- LOGIN API ----------------
@app.route("/login", methods=["POST"])
def login():

    data = request.json
    username = data["username"]
    password = data["password"]

    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username=?",
        (username,)
    )

    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user[2], password):
        session["user"] = username
        return jsonify({"message": "Login Successful"})
    else:
        return jsonify({"message": "Invalid Credentials"})


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():

    session.pop("user", None)
    return jsonify({"message": "Logged Out Successfully"})


# ---------------- SECURITY SCAN ----------------
@app.route("/scan")
def run_scan():

    if "user" not in session:
        return jsonify({"message": "Unauthorized Access"}), 401

    username = session["user"]

    alerts = scan_cloud_config()

    conn = connect_db()
    cursor = conn.cursor()

    for issue, severity, solution in alerts:

        cursor.execute(
            "SELECT * FROM alerts WHERE username=? AND issue=?",
            (username, issue)
        )

        existing = cursor.fetchone()

        if not existing:
            cursor.execute(
                "INSERT INTO alerts(username,issue,severity,solution,timestamp) VALUES (?,?,?,?,?)",
                (
                    username,
                    issue,
                    severity,
                    solution,
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                )
            )

    conn.commit()
    conn.close()

    return jsonify({"message": "Scan Completed"})


# ---------------- ALERTS API ----------------
@app.route("/alerts")
def get_alerts():

    if "user" not in session:
        return jsonify({"message": "Unauthorized Access"}), 401

    username = session["user"]

    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM alerts WHERE username=?",
        (username,)
    )

    alerts = cursor.fetchall()

    high = sum(1 for a in alerts if a[3] == "High")
    medium = sum(1 for a in alerts if a[3] == "Medium")

    if high > 0:
        risk = "HIGH"
    elif medium > 0:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    risk_score = calculate_risk(alerts)

    conn.close()

    return jsonify({
        "alerts": alerts,
        "total": len(alerts),
        "high": high,
        "medium": medium,
        "risk": risk,
        "risk_score": risk_score
    })


# ---------------- FIX PUBLIC S3 BUCKET ----------------
@app.route("/fix_s3", methods=["POST"])
def fix_s3():

    if "user" not in session:
        return jsonify({"message": "Unauthorized"}), 401

    config_path = os.path.join(BASE_DIR, "config.json")

    if not os.path.exists(config_path):
        return jsonify({"message": "Cloud not connected"}), 400

    with open(config_path) as f:
        config = json.load(f)

    import boto3

    s3 = boto3.client(
        "s3",
        aws_access_key_id=config["aws_access_key"],
        aws_secret_access_key=config["aws_secret_key"],
        region_name=config["region"]
    )

    bucket_name = request.json["bucket"]

    try:
        s3.delete_bucket_policy(Bucket=bucket_name)

        return jsonify({
            "message": f"Public access removed from {bucket_name}"
        })

    except Exception as e:
        return jsonify({
            "message": "Fix failed",
            "error": str(e)
        })


# ---------------- CONNECT CLOUD PAGE ----------------
@app.route("/connectcloud")
def connect_cloud():

    if "user" not in session:
        return redirect("/loginpage")

    return render_template("connect_cloud.html")


# ---------------- SAVE CLOUD CONFIG ----------------
@app.route("/save_cloud", methods=["POST"])
def save_cloud():

    data = request.json

    config_path = os.path.join(BASE_DIR, "config.json")

    with open(config_path, "w") as f:
        json.dump(data, f)

    return jsonify({"message": "Cloud Connected Successfully"})


# ---------------- START APP ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)