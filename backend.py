from flask import Flask, jsonify, request
from flask_cors import CORS
import time

app = Flask(__name__)
CORS(app)

# -----------------------------
# STORAGE
# -----------------------------

alerts = []
rtt_data = []
rss_data = []

MAX_ITEMS = 20

# -----------------------------
# ADD ALERT
# -----------------------------

def add_alert_internal(alert_type, message):

    alert = {
        "type": alert_type,
        "message": message,
        "time": time.strftime("%H:%M:%S")
    }

    alerts.append(alert)

    if len(alerts) > MAX_ITEMS:
        alerts.pop(0)

    print("[!] BACKEND RECEIVED ALERT:", alert)

# -----------------------------
# GET ALERTS
# -----------------------------

@app.route("/alerts")
def get_alerts():
    return jsonify(alerts)

# -----------------------------
# CLEAR DATA
# -----------------------------

@app.route("/clear", methods=["POST"])
def clear_data():
    global alerts, rtt_data, rss_data
    alerts = []
    rtt_data = []
    rss_data = []
    print("[*] BACKEND DATA CLEARED")
    return jsonify({"status": "ok"})

# -----------------------------
# ADD ALERT (API)
# -----------------------------

@app.route("/alert", methods=["POST"])
def add_alert():

    data = request.json or {}

    alert_type = data.get("type", "info")
    message = data.get("message", "unknown alert")

    add_alert_internal(alert_type, message)

    return jsonify({"status": "ok"})

# -----------------------------
# GET METRICS
# -----------------------------

@app.route("/metrics")
def get_metrics():

    return jsonify({
        "rtt": rtt_data,
        "rss": rss_data
    })

# -----------------------------
# ADD METRICS
# -----------------------------

@app.route("/metrics", methods=["POST"])
def add_metrics():

    data = request.json or {}

    if "rtt" in data:
        rtt_data.append(data["rtt"])
        if len(rtt_data) > MAX_ITEMS:
            rtt_data.pop(0)

    if "rss" in data:
        rss_data.append(data["rss"])
        if len(rss_data) > MAX_ITEMS:
            rss_data.pop(0)

    return jsonify({"status": "ok"})

# -----------------------------
# START SERVER
# -----------------------------

if __name__ == "__main__":

    print("[*] Backend server running on port 5000")

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )